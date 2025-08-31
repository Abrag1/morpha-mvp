require('dotenv').config();
const express = require('express');
const multer = require('multer');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const OpenAI = require('openai');
const pdfParse = require('pdf-parse');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const xss = require('xss');

const app = express();
const PORT = process.env.PORT || 3000;
app.set('trust proxy', 1);

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
            scriptSrcAttr: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "https://api.openai.com"]
        }
    }
}));

// Initialize OpenAI
if (!process.env.OPENAI_API_KEY) {
    console.error('❌ OPENAI_API_KEY is not set in environment variables');
    process.exit(1);
}

const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY
});

// Rate limiting configurations
const uploadLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 uploads per windowMs
    message: {
        error: 'Too many document uploads. Please try again in 15 minutes.',
        retryAfter: 15 * 60
    },
    standardHeaders: true,
    legacyHeaders: false
});

const chatLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 10, // limit each IP to 10 chat requests per minute
    message: {
        error: 'Too many chat requests. Please slow down.',
        retryAfter: 60
    },
    standardHeaders: true,
    legacyHeaders: false
});

const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: {
        error: 'Too many requests. Please try again later.',
        retryAfter: 15 * 60
    }
});

// Apply rate limiting
app.use(generalLimiter);

// Middleware
app.use(cors({
    origin: process.env.NODE_ENV === 'production' 
        ? ['https://getmorpha.com', 'https://www.getmorpha.com'] 
        : ['http://localhost:3000'],
    credentials: true
}));
app.use(express.json({ limit: '1mb' }));
app.use(express.static('public'));

// Input sanitization function
function sanitizeInput(input) {
    if (typeof input !== 'string') return input;
    // Remove XSS attempts and sanitize
    return xss(input, {
        whiteList: {}, // No HTML tags allowed
        stripIgnoreTag: true,
        stripIgnoreTagBody: ['script']
    }).trim();
}

// Usage tracking
let usageStats = {
    totalUploads: 0,
    totalChats: 0,
    totalTokensUsed: 0,
    estimatedCost: 0,
    dailyStats: {}
};

function trackUsage(type, tokens = 0) {
    const today = new Date().toISOString().split('T')[0];
    
    if (!usageStats.dailyStats[today]) {
        usageStats.dailyStats[today] = {
            uploads: 0,
            chats: 0,
            tokens: 0,
            cost: 0
        };
    }
    
    if (type === 'upload') {
        usageStats.totalUploads++;
        usageStats.dailyStats[today].uploads++;
    } else if (type === 'chat') {
        usageStats.totalChats++;
        usageStats.dailyStats[today].chats++;
    }
    
    if (tokens > 0) {
        usageStats.totalTokensUsed += tokens;
        usageStats.dailyStats[today].tokens += tokens;
        
        // Rough cost estimation ($0.03 per 1K tokens for GPT-4)
        const cost = (tokens / 1000) * 0.03;
        usageStats.estimatedCost += cost;
        usageStats.dailyStats[today].cost += cost;
    }
    
    // Clean old daily stats (keep only last 30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    
    Object.keys(usageStats.dailyStats).forEach(date => {
        if (new Date(date) < thirtyDaysAgo) {
            delete usageStats.dailyStats[date];
        }
    });
}

// File upload configuration with enhanced security
const upload = multer({
    dest: 'uploads/',
    fileFilter: (req, file, cb) => {
        // Allowed MIME types
        const allowedTypes = [
            'application/pdf',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        ];
        
        // Check MIME type
        if (!allowedTypes.includes(file.mimetype)) {
            return cb(new Error('Only PDF and Word documents are allowed'), false);
        }
        
        // Check file extension
        const allowedExtensions = ['.pdf', '.docx', '.doc'];
        const fileExtension = path.extname(file.originalname).toLowerCase();
        
        if (!allowedExtensions.includes(fileExtension)) {
            return cb(new Error('Invalid file extension'), false);
        }
        
        cb(null, true);
    },
    limits: {
        fileSize: 10 * 1024 * 1024, // 10MB limit
        files: 1 // Only one file at a time
    }
});

// Create necessary directories
['uploads', 'public'].forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir);
    }
});

// In-memory storage with session-like behavior
let documents = [];
let conversations = [];

// Simple session tracking by IP (basic security measure)
const sessions = new Map();

function getSession(ip) {
    if (!sessions.has(ip)) {
        sessions.set(ip, {
            documentCount: 0,
            chatCount: 0,
            createdAt: new Date(),
            lastActivity: new Date()
        });
    }
    
    const session = sessions.get(ip);
    session.lastActivity = new Date();
    return session;
}

// Clean old sessions (older than 24 hours)
setInterval(() => {
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    for (const [ip, session] of sessions.entries()) {
        if (session.lastActivity < oneDayAgo) {
            sessions.delete(ip);
        }
    }
}, 60 * 60 * 1000); // Clean every hour

// Routes

// Health check with basic stats
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'Morpha MVP Server is running!',
        uptime: process.uptime(),
        timestamp: new Date().toISOString()
    });
});

// Admin stats endpoint (basic protection)
app.get('/admin/stats', (req, res) => {
    // Basic auth check (in production, use proper authentication)
    const authHeader = req.headers.authorization;
    if (!authHeader || authHeader !== `Bearer ${process.env.ADMIN_SECRET || 'admin123'}`) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    res.json({
        usage: usageStats,
        activeSessions: sessions.size,
        totalDocuments: documents.length
    });
});

// Upload document with enhanced security
app.post('/upload', uploadLimiter, upload.single('document'), async (req, res) => {
    try {
        const clientIP = req.ip || req.connection.remoteAddress;
        const session = getSession(clientIP);
        
        // Additional session limits
        if (session.documentCount >= 10) {
            return res.status(429).json({ 
                error: 'Daily document limit reached. Please try again tomorrow.' 
            });
        }
        
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        console.log('File uploaded:', req.file.originalname, 'by IP:', clientIP);
        
        // Extract text from PDF with better error handling
        let extractedText = '';
        if (req.file.mimetype === 'application/pdf') {
            try {
                const fileBuffer = fs.readFileSync(req.file.path);
                const pdfData = await pdfParse(fileBuffer);
                extractedText = pdfData.text;
                
                if (extractedText.trim().length < 100) {
                    console.log('Detected possible scanned PDF with minimal text');
                    extractedText = `This appears to be a scanned or image-based PDF document. 
                    While I can see there is content in the document, the text extraction was limited. 
                    Please describe the key sections you'd like me to focus on, or ask specific questions 
                    about terms, dates, or clauses you're concerned about.`;
                }
            } catch (pdfError) {
                console.error('PDF parsing error:', pdfError);
                return res.status(400).json({ error: 'Failed to parse PDF. Please ensure it\'s a valid PDF file.' });
            }
        } else {
            extractedText = 'Word document processing coming soon...';
        }

        // Enhanced analysis prompt with token estimation
const analysisPrompt = `
You are a legal contract expert analyzing a document. Analyze the provided text and classify it into one of these specific categories with INTELLIGENT RISK ASSESSMENT.

DOCUMENT TYPES TO CHOOSE FROM:
1. "Rental/Lease Agreement" - Residential or commercial property rental, lease agreements, tenancy contracts
2. "Employment Contract" - Job offers, employment agreements, work contracts, salary agreements
3. "Brand Partnership/Sponsorship" - Influencer deals, sponsored content, brand ambassador agreements, marketing partnerships
4. "Service Agreement" - Freelance contracts, consulting agreements, professional services, contractor agreements
5. "Purchase Agreement" - Real estate purchases, vehicle sales, major purchases, sales contracts
6. "Loan Document" - Personal loans, mortgages, credit agreements, financing contracts
7. "NDA/Confidentiality" - Non-disclosure agreements, confidentiality contracts, privacy agreements
8. "Other" - Any contract that doesn't clearly fit the above categories

CLASSIFICATION KEYWORDS TO LOOK FOR:
- Rental/Lease: "tenant", "landlord", "rent", "lease term", "premises", "property", "occupancy"
- Employment: "employee", "employer", "salary", "wages", "position", "job title", "benefits", "termination"
- Brand Partnership: "influencer", "sponsor", "brand", "content creation", "social media", "promotion", "campaign", "deliverables"
- Service Agreement: "contractor", "freelancer", "consultant", "services", "scope of work", "project", "independent contractor"
- Purchase: "buyer", "seller", "purchase price", "sale", "transfer of ownership", "closing"
- Loan: "borrower", "lender", "principal", "interest rate", "loan amount", "repayment", "mortgage"
- NDA: "confidential", "non-disclosure", "proprietary", "trade secrets", "confidentiality"

INTELLIGENT RISK ASSESSMENT CRITERIA:

FOR RENTAL/LEASE AGREEMENTS:
HIGH RISK: Security deposit >200% monthly rent, unlimited rent increases, tenant liable for most repairs, <30 days termination notice, late fees >10% rent
MEDIUM RISK: Security deposit 150-200% monthly rent, rent increases 5-10% annually, mixed repair responsibilities, 30-60 day notices, late fees 5-10% rent
LOW RISK: Security deposit ≤150% monthly rent, rent increases ≤5% annually, landlord handles major repairs, 60+ days notice, late fees ≤5% rent

FOR EMPLOYMENT CONTRACTS:
HIGH RISK: No specified salary, non-compete >12 months or unlimited geography, company owns all personal work, no termination notice, personal liability for losses
MEDIUM RISK: Basic salary specified, non-compete 6-12 months with reasonable geography, some unclear personal work ownership, 1-4 weeks notice, standard confidentiality
LOW RISK: Clear compensation package, non-compete ≤6 months with limited scope, employee retains personal rights, 4+ weeks notice/severance, fair IP terms

FOR BRAND PARTNERSHIP/SPONSORSHIP:
HIGH RISK: Payment below market rate, exclusive rights without guarantees, unlimited usage rights, can terminate without paying completed work, personal liability for brand performance
MEDIUM RISK: Payment 50-80% of market rate, limited exclusivity with fair compensation, standard usage rights, some protection for completed work, reasonable expectations
LOW RISK: Market-rate compensation, balanced exclusivity, creator retains content rights, payment protected for delivered work, mutual performance standards

FOR SERVICE AGREEMENTS:
HIGH RISK: No payment schedule, unlimited scope creep, contractor liable for all project risks, can terminate without payment, no IP protection
MEDIUM RISK: Basic payment terms, some scope definition, shared project risks, reasonable termination clause, standard IP terms
LOW RISK: Clear payment milestones, well-defined scope, client assumes project risks, fair termination with payment, contractor retains some IP

FOR PURCHASE AGREEMENTS:
HIGH RISK: No price protection, buyer assumes all risks, no inspection rights, immediate payment required, no recourse for defects
MEDIUM RISK: Some price protection, shared risks, limited inspection period, standard payment terms, basic warranty coverage
LOW RISK: Strong price protection, seller assumes major risks, thorough inspection rights, protected payment schedule, comprehensive warranties

FOR LOAN DOCUMENTS:
HIGH RISK: Interest rate significantly above market, personal guarantees required, immediate acceleration clauses, no grace periods, severe penalties
MEDIUM RISK: Market-rate interest, limited personal guarantees, standard acceleration terms, short grace periods, reasonable penalties
LOW RISK: Below-market interest, no personal guarantees, fair acceleration terms, adequate grace periods, minimal penalties

FOR NDA/CONFIDENTIALITY:
HIGH RISK: Unlimited time period, overly broad definition of confidential info, severe penalties, no mutual protection, covers publicly available info
MEDIUM RISK: 2-5 year period, reasonably defined confidential info, standard penalties, some mutual aspects, some public info exclusions
LOW RISK: Limited time period (≤2 years), narrowly defined confidential info, reasonable penalties, mutual protection, clear public info exclusions

RISK FACTOR WEIGHTING (Most to Least Important):
1. Payment/Financial terms (highest weight)
2. Termination/Exit clauses
3. Liability/Legal exposure  
4. Scope/Deliverables clarity
5. Standard protective clauses (lowest weight)

MISSING INFORMATION HANDLING:
- Critical clauses missing (payment, termination) → Minimum MEDIUM risk
- Standard clauses missing → Low impact on risk assessment
- Protective clauses missing → Slight risk increase

INSTRUCTIONS:
1. Read the document text carefully
2. Classify the document type using the keywords above
3. Apply the specific risk criteria for that document type
4. Weight the risk factors by importance (payment terms matter most)
5. Consider missing critical information as a risk factor
6. Provide specific reasoning for the risk level assigned

Available text from document:
${extractedText.substring(0, 6000)}

Provide analysis in JSON format:
{
    "documentType": "EXACT category name from list above",
    "summary": "string (include note if scanned/limited text)",
    "risks": ["array of specific risk strings based on the criteria above"],
    "keyDates": ["array of important dates if found"],
    "financialTerms": ["array of financial terms if found"],
    "riskLevel": "low|medium|high",
    "isScanned": boolean (true if appears to be scanned with limited text),
    "classificationConfidence": "high|medium|low",
    "classificationReason": "Brief explanation of why this classification was chosen",
    "riskAssessmentReason": "Detailed explanation of why this risk level was assigned, citing specific clauses or missing protections"
}
`;

        const analysis = await openai.chat.completions.create({
            model: "gpt-4",
            messages: [{ role: "user", content: analysisPrompt }],
            temperature: 0.3,
            max_tokens: 1000
        });

        // Track usage
        const tokensUsed = analysis.usage?.total_tokens || 0;
        trackUsage('upload', tokensUsed);
        session.documentCount++;

        let analysisResult;
        try {
            analysisResult = JSON.parse(analysis.choices[0].message.content);
        } catch (e) {
            analysisResult = {
                documentType: "Unknown",
                summary: analysis.choices[0].message.content,
                risks: [],
                keyDates: [],
                financialTerms: [],
                riskLevel: "medium",
                isScanned: false
            };
        }

        // Store document info with enhanced metadata
        const documentId = Date.now().toString();
        const pdfPath = `uploads/${documentId}.pdf`;
        
        if (req.file.mimetype === 'application/pdf') {
            fs.copyFileSync(req.file.path, pdfPath);
        }
        
        const documentInfo = {
            id: documentId,
            filename: sanitizeInput(req.file.originalname),
            uploadDate: new Date(),
            clientIP: clientIP,
            extractedText: extractedText,
            analysis: analysisResult,
            pdfPath: req.file.mimetype === 'application/pdf' ? pdfPath : null,
            tokensUsed: tokensUsed
        };
        
        documents.push(documentInfo);

        // Clean up original uploaded file
        fs.unlinkSync(req.file.path);

        res.json({
            success: true,
            documentId: documentId,
            analysis: analysisResult,
            tokensUsed: tokensUsed
        });

    } catch (error) {
        console.error('Upload error:', error);
        
        // Clean up file if it exists
        if (req.file && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }
        
        res.status(500).json({ error: 'Failed to process document: ' + error.message });
    }
});

// Chat with document with enhanced security
app.post('/chat', chatLimiter, async (req, res) => {
    try {
        const clientIP = req.ip || req.connection.remoteAddress;
        const session = getSession(clientIP);
        
        // Additional session limits
        if (session.chatCount >= 50) {
            return res.status(429).json({ 
                error: 'Daily chat limit reached. Please try again tomorrow.' 
            });
        }
        
        const { documentId, message } = req.body;
        
        if (!documentId || !message) {
            return res.status(400).json({ error: 'Document ID and message are required' });
        }

        // Sanitize user input
        const sanitizedMessage = sanitizeInput(message);
        
        if (sanitizedMessage.length === 0) {
            return res.status(400).json({ error: 'Invalid message content' });
        }
        
        if (sanitizedMessage.length > 500) {
            return res.status(400).json({ error: 'Message too long. Please keep it under 500 characters.' });
        }

        // Find document with IP verification
        const document = documents.find(doc => doc.id === documentId && doc.clientIP === clientIP);
        if (!document) {
            return res.status(404).json({ error: 'Document not found or access denied' });
        }

        const chatPrompt = `
You are a legal contract expert helping a consumer understand their contract. 

Contract Summary:
- Type: ${document.analysis.documentType}
- Summary: ${document.analysis.summary}

User Question: ${sanitizedMessage}

Contract Text (first 3000 chars):
${document.extractedText.substring(0, 3000)}

Provide a helpful, clear answer in plain English. Be specific and reference the contract when possible.
Keep your response under 300 words.
`;

        const response = await openai.chat.completions.create({
            model: "gpt-4",
            messages: [{ role: "user", content: chatPrompt }],
            temperature: 0.3,
            max_tokens: 500
        });

        // Track usage
        const tokensUsed = response.usage?.total_tokens || 0;
        trackUsage('chat', tokensUsed);
        session.chatCount++;

        const chatResponse = {
            id: Date.now().toString(),
            documentId: documentId,
            clientIP: clientIP,
            userMessage: sanitizedMessage,
            aiResponse: response.choices[0].message.content,
            timestamp: new Date(),
            tokensUsed: tokensUsed
        };

        conversations.push(chatResponse);

        res.json({
            success: true,
            response: response.choices[0].message.content,
            tokensUsed: tokensUsed
        });

    } catch (error) {
        console.error('Chat error:', error);
        res.status(500).json({ error: 'Failed to process chat: ' + error.message });
    }
});

// Get suggested questions with IP verification
app.get('/suggestions/:documentId', (req, res) => {
    const clientIP = req.ip || req.connection.remoteAddress;
    const document = documents.find(doc => doc.id === req.params.documentId && doc.clientIP === clientIP);
    
    if (!document) {
        return res.status(404).json({ error: 'Document not found or access denied' });
    }

    const suggestions = {
        lease: [
            "What happens if I break the lease early?",
            "Can the landlord increase my rent?",
            "What are my responsibilities for repairs?",
            "How much notice do I need to give before moving out?"
        ],
        employment: [
            "What is my probation period?",
            "Can I work for competitors after leaving?",
            "What happens to my benefits if I'm terminated?",
            "How much vacation time do I get?"
        ],
        loan: [
            "What is my total interest cost?",
            "Can I pay off the loan early?",
            "What happens if I miss a payment?",
            "Are there any hidden fees?"
        ],
        default: [
            "What are the most important terms I should know?",
            "Are there any red flags in this contract?",
            "What are my main obligations?",
            "What happens if I want to cancel?"
        ]
    };

    const docType = document.analysis.documentType.toLowerCase();
    const questionSet = suggestions[docType] || suggestions.default;

    res.json({
        success: true,
        suggestions: questionSet
    });
});

// Serve PDF files with access control
app.get('/pdf/:documentId', (req, res) => {
    const clientIP = req.ip || req.connection.remoteAddress;
    const document = documents.find(doc => doc.id === req.params.documentId && doc.clientIP === clientIP);
    
    if (!document || !document.pdfPath) {
        return res.status(404).json({ error: 'PDF not found or access denied' });
    }

    if (!fs.existsSync(document.pdfPath)) {
        return res.status(404).json({ error: 'PDF file not found on disk' });
    }

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `inline; filename="${document.filename}"`);
    res.setHeader('Cache-Control', 'private, no-cache');
    
    const fileStream = fs.createReadStream(document.pdfPath);
    fileStream.pipe(res);
});

// Get document list with access control
app.get('/documents', (req, res) => {
    const clientIP = req.ip || req.connection.remoteAddress;
    const userDocuments = documents.filter(doc => doc.clientIP === clientIP);
    
    const documentList = userDocuments.map(doc => ({
        id: doc.id,
        filename: doc.filename,
        uploadDate: doc.uploadDate,
        type: doc.analysis.documentType,
        riskLevel: doc.analysis.riskLevel
    }));

    res.json({
        success: true,
        documents: documentList
    });
});


// Serve legal pages
app.get('/privacy', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'privacy.html'));
});

app.get('/terms', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'terms.html'));
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Error:', error);
    
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File too large. Maximum size is 10MB.' });
        }
        if (error.code === 'LIMIT_FILE_COUNT') {
            return res.status(400).json({ error: 'Too many files. Please upload one file at a time.' });
        }
    }
    
    res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Morpha MVP Server running on http://localhost:${PORT}`);
    console.log(`🔒 Security features enabled`);
    console.log(`📊 Usage tracking active`);
    console.log(`⚡ Rate limiting configured`);
});

module.exports = app;