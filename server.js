require('dotenv').config();
const express = require('express');
const multer = require('multer');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const OpenAI = require('openai');
const pdfParse = require('pdf-parse');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize OpenAI
const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// File upload configuration
const upload = multer({
    dest: 'uploads/',
    fileFilter: (req, file, cb) => {
        if (file.mimetype === 'application/pdf' || 
            file.mimetype === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
            cb(null, true);
        } else {
            cb(new Error('Only PDF and Word documents are allowed!'), false);
        }
    },
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB limit
    }
});

// Create uploads directory if it doesn't exist
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// Create public directory if it doesn't exist
if (!fs.existsSync('public')) {
    fs.mkdirSync('public');
}

// In-memory storage for demo (in production, use a real database)
let documents = [];
let conversations = [];

// Routes

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'OK', message: 'Morpha MVP Server is running!' });
});

// Upload document
app.post('/upload', upload.single('document'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        console.log('File uploaded:', req.file.originalname);
        
        // Extract text from PDF
        let extractedText = '';
        if (req.file.mimetype === 'application/pdf') {
            const fileBuffer = fs.readFileSync(req.file.path);
            const pdfData = await pdfParse(fileBuffer);
            extractedText = pdfData.text;
        } else {
            // For Word docs, we'll add support later
            extractedText = 'Word document processing coming soon...';
        }

        // Analyze document with OpenAI
        const analysisPrompt = `
You are a legal contract expert. Analyze this contract and provide:

1. Document Type (lease, employment, loan, etc.)
2. Key Terms Summary (in plain English)
3. Risk Assessment (red flags or concerning clauses)
4. Important Dates/Deadlines
5. Financial Terms

Contract text:
${extractedText.substring(0, 4000)} // Limit text to avoid token limits

Respond in JSON format:
{
    "documentType": "string",
    "summary": "string",
    "risks": ["array of risk strings"],
    "keyDates": ["array of important dates"],
    "financialTerms": ["array of financial terms"],
    "riskLevel": "low|medium|high"
}
`;

        const analysis = await openai.chat.completions.create({
            model: "gpt-4",
            messages: [{ role: "user", content: analysisPrompt }],
            temperature: 0.3
        });

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
                riskLevel: "medium"
            };
        }

        // Store document info
        const documentId = Date.now().toString();
        const documentInfo = {
            id: documentId,
            filename: req.file.originalname,
            uploadDate: new Date(),
            extractedText: extractedText,
            analysis: analysisResult
        };
        
        documents.push(documentInfo);

        // Clean up uploaded file
        fs.unlinkSync(req.file.path);

        res.json({
            success: true,
            documentId: documentId,
            analysis: analysisResult
        });

    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'Failed to process document: ' + error.message });
    }
});

// Chat with document
app.post('/chat', async (req, res) => {
    try {
        const { documentId, message } = req.body;
        
        if (!documentId || !message) {
            return res.status(400).json({ error: 'Document ID and message are required' });
        }

        // Find document
        const document = documents.find(doc => doc.id === documentId);
        if (!document) {
            return res.status(404).json({ error: 'Document not found' });
        }

        const chatPrompt = `
You are a legal contract expert helping a consumer understand their contract. 

Contract Summary:
- Type: ${document.analysis.documentType}
- Summary: ${document.analysis.summary}

User Question: ${message}

Contract Text (first 3000 chars):
${document.extractedText.substring(0, 3000)}

Provide a helpful, clear answer in plain English. Be specific and reference the contract when possible.
`;

        const response = await openai.chat.completions.create({
            model: "gpt-4",
            messages: [{ role: "user", content: chatPrompt }],
            temperature: 0.3,
            max_tokens: 500
        });

        const chatResponse = {
            id: Date.now().toString(),
            documentId: documentId,
            userMessage: message,
            aiResponse: response.choices[0].message.content,
            timestamp: new Date()
        };

        conversations.push(chatResponse);

        res.json({
            success: true,
            response: response.choices[0].message.content
        });

    } catch (error) {
        console.error('Chat error:', error);
        res.status(500).json({ error: 'Failed to process chat: ' + error.message });
    }
});

// Get suggested questions
app.get('/suggestions/:documentId', (req, res) => {
    const document = documents.find(doc => doc.id === req.params.documentId);
    if (!document) {
        return res.status(404).json({ error: 'Document not found' });
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

// Get document list
app.get('/documents', (req, res) => {
    const documentList = documents.map(doc => ({
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

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Morpha MVP Server running on http://localhost:${PORT}`);
    console.log(`📁 Upload endpoint: http://localhost:${PORT}/upload`);
    console.log(`💬 Chat endpoint: http://localhost:${PORT}/chat`);
});

module.exports = app;