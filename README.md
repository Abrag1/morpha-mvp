Morpha MVP

AI-powered contract assistant — upload a contract, ask questions, and get instant AI-driven insights.


Overview
Morpha is a minimal viable product (MVP) for an AI contract assistant. It allows users to upload contract documents (PDF), which are then parsed and analyzed using OpenAI's API. Users can interact with the assistant to review, summarize, or ask questions about contract contents — making legal document review faster and more accessible.

Features

PDF Contract Upload — Upload contracts directly through the web interface
AI-Powered Analysis — Powered by OpenAI to answer questions and surface key contract details
Simple Web UI — Clean HTML/JS frontend served from the public/ directory
Rate Limiting — Built-in request throttling via express-rate-limit to prevent abuse
Security Hardened — Uses helmet for HTTP security headers and xss for input sanitization
CORS Support — Configurable cross-origin resource sharing


Tech Stack
LayerTechnologyRuntimeNode.jsServerExpress.jsAIOpenAI API (v4)PDF Parsingpdf-parseFile UploadsMulterSecurityHelmet, XSS, express-rate-limitFrontendHTML / JavaScript

Prerequisites

Node.js v16 or higher
An OpenAI API key


Getting Started
1. Clone the repository
bashgit clone https://github.com/Abrag1/morpha-mvp.git
cd morpha-mvp
2. Install dependencies
bashnpm install
3. Configure environment variables
Create a .env file in the root of the project:
envOPENAI_API_KEY=your_openai_api_key_here
PORT=3000
4. Start the server
bashnpm start
The app will be running at http://localhost:3000.
For development:
bashnpm run dev

Project Structure
morpha-mvp/
├── public/             # Static frontend files (HTML, CSS, JS)
├── server.js           # Express server & API routes
├── package.json        # Dependencies and scripts
├── .gitignore
└── .env                # Environment variables (not committed)

Usage

Open the app in your browser at http://localhost:3000
Upload a contract PDF using the file input
Ask the AI assistant questions about the contract (e.g., "What are the termination clauses?", "Summarize the payment terms")
Review the AI-generated responses in the chat interface


Environment Variables
VariableDescriptionRequiredOPENAI_API_KEYYour OpenAI API key✅ YesPORTPort for the Express server (default: 3000)
