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

// New code for custom logging in Railway
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';
const ENABLE_IP_LOGGING = process.env.ENABLE_IP_LOGGING === 'true';
const ENABLE_USER_DATA_LOGGING = process.env.ENABLE_USER_DATA_LOGGING === 'true';

const logger = {
    error: (message, data = {}) => {
        if (['error', 'warn', 'info', 'debug'].includes(LOG_LEVEL)) {
            console.error(JSON.stringify({
                level: 'error',
                message: sanitizeLogData(message),
                timestamp: new Date().toISOString(),
                data: sanitizeLogData(data)
            }));
        }
    },
    
    warn: (message, data = {}) => {
        if (['warn', 'info', 'debug'].includes(LOG_LEVEL)) {
            console.warn(JSON.stringify({
                level: 'warn',
                message: sanitizeLogData(message),
                timestamp: new Date().toISOString(),
                data: sanitizeLogData(data)
            }));
        }
    },
    
    info: (message, data = {}) => {
        if (['info', 'debug'].includes(LOG_LEVEL)) {
            console.log(JSON.stringify({
                level: 'info',
                message: sanitizeLogData(message),
                timestamp: new Date().toISOString(),
                data: sanitizeLogData(data)
            }));
        }
    },
    
    debug: (message, data = {}) => {
        if (LOG_LEVEL === 'debug') {
            console.log(JSON.stringify({
                level: 'debug',
                message: sanitizeLogData(message),
                timestamp: new Date().toISOString(),
                data: sanitizeLogData(data)
            }));
        }
    }
};

function sanitizeLogData(data) {
    if (typeof data === 'string') return data;
    if (!data || typeof data !== 'object') return data;
    
    const sanitized = { ...data };
    
    const sensitiveFields = ['password', 'token', 'apiKey', 'secret', 'auth'];
    sensitiveFields.forEach(field => {
        if (sanitized[field]) {
            sanitized[field] = '[REDACTED]';
        }
    });
    
    if (!ENABLE_IP_LOGGING && sanitized.ip) {
        sanitized.ip = '[REDACTED]';
    }
    if (!ENABLE_IP_LOGGING && sanitized.clientIP) {
        sanitized.clientIP = '[REDACTED]';
    }
    
    if (!ENABLE_USER_DATA_LOGGING) {
        if (sanitized.email) sanitized.email = '[REDACTED]';
        if (sanitized.userId) sanitized.userId = '[REDACTED]';
        if (sanitized.filename) sanitized.filename = '[REDACTED]';
        if (sanitized.originalname) sanitized.originalname = '[REDACTED]';
    }
    
    return sanitized;
}

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


// Error tracking
const errorLog = [];
const MAX_ERROR_LOG = 100;

function logError(error, context = {}) {
    const errorEntry = {
        timestamp: new Date().toISOString(),
        message: error.message,
        stack: error.stack,
        context: context
    };
    
    errorLog.unshift(errorEntry);
    if (errorLog.length > MAX_ERROR_LOG) {
        errorLog.pop();
    }
    
    console.error('Error logged:', errorEntry);
}


// Session-based metrics (no device tracking)
const sessionMetrics = {
    sessions: {}, // Active sessions
    daily: {}, // Daily aggregates
    
    recordEvent: function(sessionId, event) {
        const today = new Date().toISOString().split('T')[0];
        
        // Initialize daily metrics
        if (!this.daily[today]) {
            this.daily[today] = {
                total_visitors: 0,
                personal_uploads: 0,
                sessions_with_upload: new Set(),
                sessions_with_multiple_actions: new Set(),
                action_counts: {}
            };
        }
        
        // Initialize session
        if (!this.sessions[sessionId]) {
            this.sessions[sessionId] = {
                started: new Date(),
                actions: [],
                has_upload: false
            };
            this.daily[today].total_visitors++;
        }
        
        // Record action
        this.sessions[sessionId].actions.push(event);
        
        // Track specific events
        if (event === 'personal_upload') {
            this.sessions[sessionId].has_upload = true;
            this.daily[today].personal_uploads++;
            this.daily[today].sessions_with_upload.add(sessionId);
        }
        
        // Check for multiple meaningful actions
        const meaningfulActions = this.sessions[sessionId].actions.filter(
            a => ['personal_upload', 'used_chat', 'view_red_flags'].includes(a)
        );
        
        if (meaningfulActions.length > 1) {
            this.daily[today].sessions_with_multiple_actions.add(sessionId);
        }
        
        // Count action types
        this.daily[today].action_counts[event] = 
            (this.daily[today].action_counts[event] || 0) + 1;
    },
    
    cleanOldData: function() {
        // Remove data older than 2 weeks
        const twoWeeksAgo = new Date();
        twoWeeksAgo.setDate(twoWeeksAgo.getDate() - 14);
        const cutoff = twoWeeksAgo.toISOString().split('T')[0];
        
        Object.keys(this.daily).forEach(date => {
            if (date < cutoff) delete this.daily[date];
        });
        
        // Clean old sessions (older than 24 hours)
        const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
        Object.keys(this.sessions).forEach(sid => {
            if (new Date(this.sessions[sid].started) < oneDayAgo) {
                delete this.sessions[sid];
            }
        });
    }
};

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

// Log document count periodically
setInterval(() => {
    console.log('Current documents in memory:', {
        count: documents.length,
        documents: documents.map(d => ({
            id: d.id,
            filename: d.filename,
            uploadTime: d.uploadDate
        }))
    });
}, 60000); // Every minute

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

// Admin stats endpoint with metrics
app.get('/admin/stats', (req, res) => {
    const authHeader = req.headers.authorization;
    const token = req.query.token || (authHeader ? authHeader.replace('Bearer ', '') : '');
    
    if (!token || token !== process.env.ADMIN_SECRET) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    // Calculate metrics with explanations
    const today = new Date().toISOString().split('T')[0];
    const todayMetrics = sessionMetrics.daily[today] || {
        total_visitors: 0,
        personal_uploads: 0,
        sessions_with_upload: new Set(),
        sessions_with_multiple_actions: new Set(),
        action_counts: {}
    };

    // Create readable dashboard
    const dashboardData = {
        overall_performance: {
            total_documents_uploaded: usageStats.totalUploads,
            total_chat_conversations: usageStats.totalChats,
            total_ai_cost: `$${usageStats.estimatedCost.toFixed(2)}`,
            ai_tokens_used: usageStats.totalTokensUsed
        },
        today_snapshot: {
            visitors_today: todayMetrics.total_visitors,
            documents_uploaded_today: todayMetrics.personal_uploads,
            upload_conversion_rate: todayMetrics.total_visitors > 0 
                ? `${((todayMetrics.sessions_with_upload.size / todayMetrics.total_visitors) * 100).toFixed(1)}%`
                : '0%',
            engaged_users_rate: todayMetrics.total_visitors > 0
                ? `${((todayMetrics.sessions_with_multiple_actions.size / todayMetrics.total_visitors) * 100).toFixed(1)}%`
                : '0%'
        },
        business_insights: {
            average_cost_per_upload: usageStats.totalUploads > 0 
                ? `$${(usageStats.estimatedCost / usageStats.totalUploads).toFixed(3)}`
                : '$0',
            chat_usage_rate: usageStats.totalUploads > 0
                ? `${((usageStats.totalChats / usageStats.totalUploads) * 100).toFixed(1)}%`
                : '0%',
            active_sessions: sessions.size,
            documents_in_memory: documents.length
        },
        explanations: {
            upload_conversion_rate: "Percentage of visitors who upload their own documents",
            engaged_users_rate: "Percentage of visitors who do multiple actions (upload + chat, etc)",
            chat_usage_rate: "Percentage of uploaded documents that generate chat conversations",
            average_cost_per_upload: "AI processing cost per document upload"
        }
    };

    // Return HTML dashboard instead of JSON
    const htmlDashboard = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Morpha Admin Dashboard</title>
        <style>
            body { 
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                margin: 40px;
                background: #f8f9fa;
                color: #333;
            }
            .container { max-width: 1200px; margin: 0 auto; }
            .header { 
                background: #667eea; 
                color: white; 
                padding: 30px; 
                border-radius: 12px; 
                margin-bottom: 30px;
                text-align: center;
            }
            .metrics-grid { 
                display: grid; 
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
                gap: 20px; 
                margin-bottom: 30px;
            }
            .metric-card { 
                background: white; 
                padding: 25px; 
                border-radius: 12px; 
                box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                border-left: 4px solid #667eea;
            }
            .metric-title { 
                font-size: 1.1em; 
                font-weight: 600; 
                color: #667eea; 
                margin-bottom: 15px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            .metric-item { 
                display: flex; 
                justify-content: space-between; 
                margin-bottom: 10px; 
                padding: 8px 0;
                border-bottom: 1px solid #f0f0f0;
            }
            .metric-label { color: #666; }
            .metric-value { 
                font-weight: 600; 
                color: #333;
                font-size: 1.1em;
            }
            .explanation { 
                background: #f8f9ff; 
                padding: 20px; 
                border-radius: 8px; 
                margin-top: 15px;
                font-size: 0.9em;
                color: #666;
                border-left: 3px solid #667eea;
            }
            .refresh-btn {
                background: #667eea;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 6px;
                cursor: pointer;
                font-weight: 600;
                margin-bottom: 20px;
            }
            .refresh-btn:hover { background: #5a6fd8; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Morpha Admin Dashboard</h1>
                <p>Real-time business metrics and insights</p>
                <button class="refresh-btn" onclick="window.location.reload()">Refresh Data</button>
            </div>
            
            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-title">Overall Performance</div>
                    <div class="metric-item">
                        <span class="metric-label">Total Documents Uploaded</span>
                        <span class="metric-value">${dashboardData.overall_performance.total_documents_uploaded}</span>
                    </div>
                    <div class="metric-item">
                        <span class="metric-label">Total Chat Conversations</span>
                        <span class="metric-value">${dashboardData.overall_performance.total_chat_conversations}</span>
                    </div>
                    <div class="metric-item">
                        <span class="metric-label">Total AI Cost</span>
                        <span class="metric-value">${dashboardData.overall_performance.total_ai_cost}</span>
                    </div>
                    <div class="metric-item">
                        <span class="metric-label">AI Tokens Used</span>
                        <span class="metric-value">${dashboardData.overall_performance.ai_tokens_used}</span>
                    </div>
                </div>

                <div class="metric-card">
                    <div class="metric-title">Today's Activity</div>
                    <div class="metric-item">
                        <span class="metric-label">Visitors Today</span>
                        <span class="metric-value">${dashboardData.today_snapshot.visitors_today}</span>
                    </div>
                    <div class="metric-item">
                        <span class="metric-label">Documents Uploaded Today</span>
                        <span class="metric-value">${dashboardData.today_snapshot.documents_uploaded_today}</span>
                    </div>
                    <div class="metric-item">
                        <span class="metric-label">Upload Conversion Rate</span>
                        <span class="metric-value">${dashboardData.today_snapshot.upload_conversion_rate}</span>
                    </div>
                    <div class="metric-item">
                        <span class="metric-label">Engaged Users Rate</span>
                        <span class="metric-value">${dashboardData.today_snapshot.engaged_users_rate}</span>
                    </div>
                </div>

                <div class="metric-card">
                    <div class="metric-title">Business Insights</div>
                    <div class="metric-item">
                        <span class="metric-label">Average Cost Per Upload</span>
                        <span class="metric-value">${dashboardData.business_insights.average_cost_per_upload}</span>
                    </div>
                    <div class="metric-item">
                        <span class="metric-label">Chat Usage Rate</span>
                        <span class="metric-value">${dashboardData.business_insights.chat_usage_rate}</span>
                    </div>
                    <div class="metric-item">
                        <span class="metric-label">Active Sessions</span>
                        <span class="metric-value">${dashboardData.business_insights.active_sessions}</span>
                    </div>
                    <div class="metric-item">
                        <span class="metric-label">Documents in Memory</span>
                        <span class="metric-value">${dashboardData.business_insights.documents_in_memory}</span>
                    </div>
                </div>
            </div>

            <div class="explanation">
                <h3>Metric Explanations:</h3>
                <p><strong>Upload Conversion Rate:</strong> ${dashboardData.explanations.upload_conversion_rate}</p>
                <p><strong>Engaged Users Rate:</strong> ${dashboardData.explanations.engaged_users_rate}</p>
                <p><strong>Chat Usage Rate:</strong> ${dashboardData.explanations.chat_usage_rate}</p>
                <p><strong>Average Cost Per Upload:</strong> ${dashboardData.explanations.average_cost_per_upload}</p>
            </div>
        </div>
    </body>
    </html>`;

    res.send(htmlDashboard);
});


// Admin endpoint to view errors (protect this!)
app.get('/admin/errors', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || authHeader !== `Bearer ${process.env.ADMIN_SECRET || 'admin123'}`) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    res.json({
        errors: errorLog,
        count: errorLog.length,
        maxErrors: MAX_ERROR_LOG
    });
});

// TEST ENDPOINT - Remove in production
app.get('/test-error', (req, res) => {
    try {
        throw new Error('This is a test error');
    } catch (error) {
        logError(error, { 
            endpoint: '/test-error',
            ip: req.ip,
            purpose: 'testing error logging'
        });
        res.json({ message: 'Error logged successfully' });
    }
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

        logger.info('File uploaded successfully', { 
            filename: req.file.originalname, 
            clientIP: clientIP 
        });
        
        // Extract text from PDF with better error handling
let extractedText = '';
if (req.file.mimetype === 'application/pdf') {
    try {
        const fileBuffer = fs.readFileSync(req.file.path);
        
        // Check if it's actually a text file masquerading as PDF (for privacy demo)
        const fileContent = fileBuffer.toString('utf8');
        if (fileContent.includes('Morpha Privacy Policy')) {
            // It's our privacy policy demo
            extractedText = fileContent;
        } else {
            // Try to parse as actual PDF
            const pdfData = await pdfParse(fileBuffer);
            extractedText = pdfData.text;
        }
        
        if (extractedText.trim().length < 100) {
            console.log('Detected possible scanned PDF with minimal text');
            extractedText = `This appears to be a scanned or image-based PDF document...`;
        }
    } catch (pdfError) {
        // Log error but try to read as text
        console.log('PDF parse failed, trying as text:', pdfError.message);
        try {
            extractedText = fs.readFileSync(req.file.path, 'utf8');
        } catch (textError) {
            logError(pdfError, {
                endpoint: '/upload',
                step: 'pdf-parsing',
                filename: req.file.originalname,
                ip: req.ip
            });
            return res.status(400).json({ error: 'Failed to parse document. Please ensure it\'s a valid PDF file.' });
        }
    }
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
8. "User Agreement" - Website Terms of Service, App ToS, Privacy Policies, Subscription Agreements, End-User License Agreements (EULA)
9. "Other" - Any contract that doesn't clearly fit the above categories

CLASSIFICATION KEYWORDS TO LOOK FOR:
- Rental/Lease: "tenant", "landlord", "rent", "lease term", "premises", "property", "occupancy"
- Employment: "employee", "employer", "salary", "wages", "position", "job title", "benefits", "termination"
- Brand Partnership: "influencer", "sponsor", "brand", "content creation", "social media", "promotion", "campaign", "deliverables"
- Service Agreement: "contractor", "freelancer", "consultant", "services", "scope of work", "project", "independent contractor"
- Purchase: "buyer", "seller", "purchase price", "sale", "transfer of ownership", "closing"
- Loan: "borrower", "lender", "principal", "interest rate", "loan amount", "repayment", "mortgage"
- NDA: "confidential", "non-disclosure", "proprietary", "trade secrets", "confidentiality"
- User Agreement: "terms of service", "privacy policy", "user agreement", "account", "data collection", "cookies", "arbitration", "delete account", "opt-out", "license", "EULA", "subscriber agreement", "acceptable use", "user content", "GDPR", "CCPA"

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

FOR USER AGREEMENTS:
HIGH RISK: 
- Data Collection: Indefinite data retention, broad "any information" collection, tracking across third-party sites, shadow profiling, collecting sensitive data without clear need
- Data Sharing: Selling user data, sharing with "partners" without specifics, broad third-party sharing without consent, data brokers mentioned
- User Rights: No right to delete account/data, cannot opt out of data collection, forced arbitration/class action waiver, unilateral terms changes without notice
- Security: No encryption mentioned, weak security practices, data stored indefinitely
- Specific Red Flags: "We may collect any information," "share with business partners," "retain data indefinitely," "cannot guarantee security"
MEDIUM RISK: 
- Data Collection: Standard web analytics, first-party cookies for functionality, limited logging (30+ days), email addresses for service delivery
- Data Sharing: Sharing with service providers under contract, compliance with legal requests, anonymized data sharing
- User Rights: Basic account deletion, some opt-out options, standard dispute resolution, terms changes with notice
- Security: Standard security measures mentioned, reasonable retention periods
- Typical Clauses: Age gates (13+), cookie notifications, basic privacy controls
LOW RISK: 
- Data Collection: Minimal purpose-specific collection, clear data minimization, session-only storage, no tracking cookies
- Data Sharing: No selling/brokering, explicit opt-in for any sharing, transparent about all third parties
- User Rights: Easy account deletion, comprehensive privacy controls, data portability, clear consent mechanisms  
- Security: End-to-end encryption, security best practices detailed, regular security audits mentioned
- Best Practices: "We don't sell your data," "delete anytime," "minimal collection," "transparent practices"

PRIVACY POLICY SPECIFIC GUIDANCE:
- GOOD clauses that should NOT be flagged: GDPR compliance, user rights explanations, contact information for privacy questions, data minimization statements, encryption usage, clear retention limits
- BAD clauses to flag: Vague data sharing, unclear retention, broad collection permissions, weak security language, difficult opt-out processes

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
            temperature: 0.15,
            max_tokens: 1000,
            seed: 12345
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
    logError(error, { 
        endpoint: '/upload', 
        ip: req.ip,
        filename: req.file?.originalname,
        step: 'general-upload'
    });
    logger.error('Upload error occurred', { error: error.message });
        
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
        
        logger.info('Chat request received', { 
            documentId: documentId, 
            messageLength: message?.length, 
            clientIP: clientIP 
        });
        
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

        // Find document
        let document = documents.find(doc => doc.id === documentId);
        
        if (!document) {
            console.log('Document not found:', {
                requestedId: documentId,
                availableDocuments: documents.map(d => ({ id: d.id, filename: d.filename })),
                totalDocs: documents.length
            });
            
            return res.status(404).json({
                error: 'Document not found. Please upload a new document.'
            });
        }
        
        // Check if we have text to analyze
        if (!document.extractedText || document.extractedText.length < 10) {
            return res.status(400).json({
                error: 'Document text is missing or too short to analyze.'
            });
        }

        const chatPrompt = `
You are a legal contract expert helping a consumer understand their contract.

Contract Summary:
- Type: ${document.analysis?.documentType || 'Unknown'}
- Summary: ${document.analysis?.summary || 'No summary available'}

User Question: ${sanitizedMessage}

Contract Text (first 3000 chars):
${document.extractedText.substring(0, 3000)}

RESPONSE FORMAT REQUIREMENTS:
- Answer the question directly and naturally (no "Direct Answer:" labels)
- Use clear paragraph breaks between different points
- Use bullet points for lists or multiple items  
- Use **bold text** for key terms or important points
- Keep sentences concise and scannable
- Reference specific contract sections when possible
- End with actionable advice if relevant
- Write in a conversational, helpful tone

Provide a helpful, clear answer in plain English. Use the formatting guidelines above but write naturally without rigid labels or prefixes. Be specific and reference the contract when possible.

Keep your response under 200 words but make it visually easy to scan.
`;

        console.log('Sending request to OpenAI...');
        
        const openaiResponse = await openai.chat.completions.create({
            model: "gpt-4",
            messages: [{ role: "user", content: chatPrompt }],
            temperature: 0.3,
            max_tokens: 500
        });

        console.log('OpenAI response received successfully');

        // Track usage
        const tokensUsed = openaiResponse.usage?.total_tokens || 0;
        trackUsage('chat', tokensUsed);
        session.chatCount++;

        const chatResponse = {
            id: Date.now().toString(),
            documentId: documentId,
            clientIP: clientIP,
            userMessage: sanitizedMessage,
            aiResponse: openaiResponse.choices[0].message.content,
            timestamp: new Date(),
            tokensUsed: tokensUsed
        };

        conversations.push(chatResponse);

        console.log('Sending response to frontend:', {
            success: true,
            responseLength: openaiResponse.choices[0].message.content?.length,
            hasResponse: !!openaiResponse.choices[0].message.content
        });

        res.json({
            success: true,
            response: openaiResponse.choices[0].message.content,
            tokensUsed: tokensUsed
        });

    } catch (error) {
        console.error('Chat error full details:', {
            message: error.message,
            stack: error.stack,
            documentId: req.body?.documentId
        });
        
        logError(error, {
            endpoint: '/chat',
            ip: req.ip,
            documentId: req.body?.documentId,
            messageLength: req.body?.message?.length,
            step: 'chat-processing'
        });
        
        // Send more specific error message
        let errorMessage = 'Failed to process chat.';
        if (error.message?.includes('API')) {
            errorMessage = 'AI service temporarily unavailable. Please try again.';
        } else if (error.message?.includes('rate')) {
            errorMessage = 'Too many requests. Please wait a moment.';
        }
        
        res.status(500).json({ error: errorMessage });
    }
});


// Feedback submission endpoint
app.post('/feedback', express.json(), async (req, res) => {
    try {
        const { type, message, userEmail, currentPage, timestamp } = req.body;
        
        // Validate required fields
        if (!type || !message) {
            return res.status(400).json({ error: 'Feedback type and message are required' });
        }

        // Sanitize inputs
        const sanitizedData = {
            type: sanitizeInput(type),
            message: sanitizeInput(message),
            userEmail: userEmail ? sanitizeInput(userEmail) : 'Not provided',
            currentPage: sanitizeInput(currentPage),
            timestamp: timestamp,
            clientIP: req.ip
        };

        // Create email content
        const emailSubject = `Morpha Feedback: ${sanitizedData.type}`;
        const emailBody = `
New feedback received from Morpha MVP:

Type: ${sanitizedData.type}
Timestamp: ${sanitizedData.timestamp}
Page: ${sanitizedData.currentPage}
User Email: ${sanitizedData.userEmail}
User IP: ${sanitizedData.clientIP}

Message:
${sanitizedData.message}

---
This feedback was sent via the Morpha MVP feedback system.
        `;

        // Log the feedback (for now we'll log it, then add email sending)
        console.log('FEEDBACK RECEIVED:');
        console.log('Subject:', emailSubject);
        console.log('Body:', emailBody);

        // For now, we'll just log it. Next we'll add actual email sending.
        
        res.json({ 
            success: true, 
            message: 'Feedback received successfully' 
        });

    } catch (error) {
        console.error('Feedback submission error:', error);
        res.status(500).json({ error: 'Failed to submit feedback' });
    }
});



// Tracking endpoint - session-based, no personal data
app.post('/track', express.json(), (req, res) => {
    const { session_id, event } = req.body;
    
    if (!session_id || !event) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    
    // Record event
    sessionMetrics.recordEvent(session_id, event);
    
    // Occasionally clean old data
    if (Math.random() < 0.05) { // 5% chance
        sessionMetrics.cleanOldData();
    }
    
    res.json({ success: true });
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
        user_agreement: [
            "What data is collected and shared?",
            "How is the data protected and stored?",
            "What tracking tools are used?",
            "What options do I have to opt out or delete data?"
        ],
        default: [
            "What are the most important terms I should know?",,
            "What are my main obligations?",
            "What happens if I want to cancel?"
        ]
    };

    // Map document types to suggestion sets
    const docType = document.analysis.documentType.toLowerCase();
    let questionSet;
    
    if (docType.includes('lease') || docType.includes('rental')) {
        questionSet = suggestions.lease;
    } else if (docType.includes('employment')) {
        questionSet = suggestions.employment;
    } else if (docType.includes('loan')) {
        questionSet = suggestions.loan;
    } else if (docType.includes('user agreement')) {
        questionSet = suggestions.user_agreement;
    } else {
        questionSet = suggestions.default;
    }

    res.json({
        success: true,
        suggestions: questionSet
    });
});




// Serve PDF files with access control
app.get('/pdf/:documentId', (req, res) => {
    const clientIP = req.ip || req.connection.remoteAddress;
    const document = documents.find(doc => doc.id === req.params.documentId && doc.clientIP === clientIP);
   
    if (!document) {
        return res.status(404).json({ error: 'PDF not found or access denied' });
    }

    // Special handling for privacy policy demo
    if (document.filename === 'Morpha_Privacy_Policy.pdf') {
        // Return the privacy policy as HTML for better viewing
        const htmlContent = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Privacy Policy - Morpha</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
           
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                line-height: 1.6;
                color: #333;
                background-color: #f8f9fa;
            }
           
            .container {
                max-width: 800px;
                margin: 0 auto;
                padding: 20px;
                background-color: white;
                box-shadow: 0 0 20px rgba(0,0,0,0.1);
                border-radius: 8px;
                margin-top: 20px;
                margin-bottom: 40px;
            }
           
            .header {
                text-align: center;
                border-bottom: 3px solid #007bff;
                padding-bottom: 20px;
                margin-bottom: 30px;
            }
           
            .header h1 {
                color: #007bff;
                font-size: 2.5em;
                margin-bottom: 10px;
            }
           
            .last-updated {
                background-color: #e9ecef;
                padding: 10px;
                border-radius: 5px;
                margin-bottom: 30px;
                text-align: center;
                font-weight: 600;
            }
           
            h1 {
                color: #007bff;
                margin-bottom: 20px;
                font-size: 2em;
            }
           
            h2 {
                color: #495057;
                margin-top: 40px;
                margin-bottom: 20px;
                font-size: 1.4em;
                border-left: 4px solid #007bff;
                padding-left: 15px;
            }
           
            h3 {
                color: #6c757d;
                margin-top: 25px;
                margin-bottom: 15px;
            }
           
            p {
                margin-bottom: 15px;
                text-align: justify;
            }
           
            ul, ol {
                margin-left: 20px;
                margin-bottom: 15px;
            }
           
            li {
                margin-bottom: 8px;
            }
           
            .summary-box {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 8px;
                padding: 25px;
                margin: 25px 0;
            }
           
            .summary-box h2 {
                margin-top: 0;
                color: #007bff;
            }
           
            .section {
                margin-bottom: 40px;
                scroll-margin-top: 20px;
            }
           
            a {
                color: #007bff;
                text-decoration: none;
            }
           
            a:hover {
                text-decoration: underline;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Privacy Policy</h1>
                <p><strong>Morpha</strong></p>
            </div>
            <div class="last-updated">
                Last updated: September 06, 2025
            </div>
            <div class="section">
                ${document.extractedText
    .split('\n\n')
    .map(paragraph => {
        if (paragraph.trim() === '') return '';
        if (paragraph.startsWith('# ')) {
            return `<h2>${paragraph.substring(2)}</h2>`;
        }
        if (paragraph.startsWith('## ')) {
            return `<h3>${paragraph.substring(3)}</h3>`;
        }
        if (paragraph.startsWith('- ') || paragraph.includes('\n- ')) {
            const items = paragraph.split('\n').filter(line => line.trim())
                .map(line => line.startsWith('- ') ? `<li>${line.substring(2)}</li>` : `<li>${line}</li>`)
                .join('');
            return `<ul>${items}</ul>`;
        }
        return `<p>${paragraph.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>').replace(/\n/g, '<br>')}</p>`;
    })
    .join('')
}
            </div>
        </div>
    </body>
    </html>`;
       
        res.setHeader('Content-Type', 'text/html');
        return res.send(htmlContent);
    }

    // Regular PDF handling for actual PDF files
    if (!document.pdfPath) {
        return res.status(404).json({ error: 'PDF file not available' });
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
    const privacyPath = path.join(__dirname, 'public', 'Privacy.html');
    console.log('Serving privacy policy from:', privacyPath);
    res.sendFile(privacyPath);
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