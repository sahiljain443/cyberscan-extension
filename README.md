# CyberGuard - Chrome Security Extension

A powerful Chrome extension designed for cybersecurity professionals that performs real-time webpage analysis, threat intelligence lookups, and AI-powered security assessments.

![CyberGuard](https://img.shields.io/badge/CyberGuard-Security%20Extension-orange?style=for-the-badge)
![Chrome Extension](https://img.shields.io/badge/Chrome-Extension-4285F4?style=for-the-badge&logo=googlechrome)
![AI Powered](https://img.shields.io/badge/AI-Powered-00D4AA?style=for-the-badge)

## 🛡️ Features

### 🔍 **Automated Network Analysis**
- **IP Address Detection**: Automatically extracts and analyzes all IP addresses found on webpages
- **Domain Intelligence**: Scans and evaluates external domains with comprehensive threat assessment
- **Real-time Scanning**: Instantly processes webpage content, scripts, CSS, and network resources

### 🌐 **Threat Intelligence Integration**
- **VirusTotal Integration**: Leverages VirusTotal's extensive malware database for IP and domain analysis
- **AbuseIPDB Lookup**: Cross-references IPs against abuse and malicious activity databases
- **Multi-source Verification**: Combines multiple threat intelligence sources for accurate assessments

### 🧠 **AI-Powered Security Analysis**
- **OpenAI Integration**: Uses advanced AI models for intelligent threat correlation and analysis
- **Risk Assessment**: Provides automated risk scoring with confidence levels
- **Security Recommendations**: Generates actionable security advice based on findings
- **Pattern Recognition**: Identifies suspicious patterns and relationships between network resources

### 🎨 **Professional Interface**
- **Clean Orange Theme**: Professional cybersecurity-focused design
- **Tabbed Interface**: Separate views for IPs, Domains, and AI Analysis
- **Real-time Updates**: Live scanning status and progress indicators
- **Copy Functionality**: One-click copying of IPs and domains for further investigation

## 📋 Requirements

- **Chrome Browser**: Version 88 or higher
- **API Keys** (Optional but recommended for full functionality):
  - OpenAI API Key (for AI analysis)
  - VirusTotal API Key (for comprehensive threat intelligence)
  - AbuseIPDB API Key (for IP abuse intelligence)

## 🚀 Installation

### Method 1: Load Unpacked Extension (Development)

1. **Download the Extension**:
   ```bash
   git clone https://github.com/yourusername/cyberguard-extension.git
   cd cyberguard-extension
   ```

2. **Open Chrome Extensions**:
   - Navigate to `chrome://extensions/`
   - Enable "Developer mode" (toggle in top-right corner)

3. **Load the Extension**:
   - Click "Load unpacked"
   - Select the `chrome-extension` folder from the project directory

4. **Verify Installation**:
   - The CyberGuard icon should appear in your Chrome toolbar
   - Extension is ready to use!

### Method 2: Install from Chrome Web Store
*Coming soon - extension will be published to Chrome Web Store*

## ⚙️ Configuration

### Setting Up API Keys

For full functionality, configure the following API keys in your backend environment:

1. **OpenAI API Key** (Required for AI analysis):
   ```bash
   export OPENAI_API_KEY="your_openai_api_key_here"
   ```

2. **VirusTotal API Key** (Optional):
   ```bash
   export VIRUSTOTAL_API_KEY="your_virustotal_api_key_here"
   ```

3. **AbuseIPDB API Key** (Optional):
   ```bash
   export ABUSEIPDB_API_KEY="your_abuseipdb_api_key_here"
   ```

### Getting API Keys

#### OpenAI API Key
1. Visit [OpenAI Platform](https://platform.openai.com/)
2. Create an account or sign in
3. Navigate to API Keys section
4. Generate a new API key

#### VirusTotal API Key
1. Visit [VirusTotal](https://www.virustotal.com/)
2. Create a free account
3. Go to your profile and find the API key section
4. Copy your personal API key

#### AbuseIPDB API Key
1. Visit [AbuseIPDB](https://www.abuseipdb.com/)
2. Create a free account
3. Navigate to the API section
4. Generate a new API key

## 🖥️ Backend Server Setup

The extension requires a backend server for API integrations:

1. **Install Dependencies**:
   ```bash
   npm install
   ```

2. **Set Environment Variables**:
   ```bash
   cp .env.example .env
   # Edit .env with your API keys
   ```

3. **Start the Server**:
   ```bash
   npm run dev
   ```

4. **Verify Server**:
   - Server runs on `http://localhost:5000`
   - Visit the URL to see the project documentation page

## 📖 Usage Guide

### Basic Usage

1. **Navigate to Any Website**: Open any webpage you want to analyze
2. **Click CyberGuard Icon**: Find the orange shield icon in your Chrome toolbar
3. **View Analysis**: The extension will automatically scan and analyze the page

### Understanding the Interface

#### **IPs Tab**
- Lists all detected IP addresses
- Shows threat levels: Safe (Green), Suspicious (Yellow), Malicious (Red)
- Displays geographic location, ISP information, and threat intelligence data
- Click copy button to copy IP addresses for further investigation

#### **Domains Tab**
- Shows all external domains found on the webpage
- Provides domain reputation, registrar information, and creation dates
- Displays threat categories and security ratings
- Includes WHOIS and threat intelligence data

#### **AI Analysis Tab**
- Comprehensive AI-powered security assessment
- Overall risk level with confidence scoring
- Key security findings with severity levels
- Actionable security recommendations
- Analysis metadata and processing information

### Interpreting Results

#### Threat Levels
- **🟢 Safe**: No threats detected, clean reputation
- **🟡 Suspicious**: Some concerns, requires monitoring
- **🔴 Malicious**: Confirmed threats, immediate action required

#### Risk Assessment
- **Low Risk**: Minimal security concerns
- **Medium Risk**: Some suspicious activity detected
- **High Risk**: Significant threats identified, investigation needed

## 🏗️ Project Structure

```
cyberguard-extension/
├── chrome-extension/          # Chrome extension files
│   ├── manifest.json         # Extension manifest
│   ├── popup.html           # Extension popup interface
│   ├── popup.js             # Popup functionality
│   ├── background.js        # Background service worker
│   ├── content.js           # Content script for page analysis
│   └── styles.css           # Extension styling
├── server/                   # Backend API server
│   ├── apis/                # API route handlers
│   │   ├── threat-intelligence.ts
│   │   └── openai-analysis.ts
│   ├── index.ts             # Server entry point
│   └── routes.ts            # Route configuration
├── client/                   # Web interface (documentation)
│   └── src/
│       └── pages/
│           └── home.tsx     # Landing page
├── shared/                   # Shared types and schemas
│   ├── types.ts             # TypeScript interfaces
│   └── schema.ts            # Data schemas
└── README.md                # This file
```

## 🔧 Development

### Prerequisites
- Node.js 18+ 
- Chrome Browser
- TypeScript knowledge (optional)

### Development Setup

1. **Clone Repository**:
   ```bash
   git clone https://github.com/yourusername/cyberguard-extension.git
   cd cyberguard-extension
   ```

2. **Install Dependencies**:
   ```bash
   npm install
   ```

3. **Start Development Server**:
   ```bash
   npm run dev
   ```

4. **Load Extension in Chrome**:
   - Follow the installation steps above
   - Reload extension after making changes

### Making Changes

- **Extension UI**: Modify files in `chrome-extension/`
- **Backend Logic**: Update files in `server/apis/`
- **Styling**: Edit `chrome-extension/styles.css`
- **Types**: Update interfaces in `shared/types.ts`

## 🛠️ Troubleshooting

### Common Issues

#### Extension Won't Load
- Ensure all files are present in `chrome-extension/` folder
- Check Chrome Developer Console for errors
- Verify manifest.json syntax

#### API Errors
- Confirm API keys are properly set in environment variables
- Check server is running on port 5000
- Verify network connectivity

#### No Data Displayed
- Ensure webpage has loaded completely before clicking extension
- Check if webpage contains external resources to analyze
- Verify content script permissions in manifest

### Debug Mode

Enable debug logging by opening Chrome DevTools:
1. Right-click on extension icon → "Inspect popup"
2. Check Console tab for detailed logs
3. Monitor Network tab for API requests

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow TypeScript best practices
- Maintain the orange theme consistency
- Add appropriate error handling
- Update documentation for new features

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔒 Security & Privacy

- **No Data Storage**: Extension doesn't store personal browsing data
- **API Security**: All API keys are handled server-side
- **Privacy First**: Only analyzes network resources, not personal content
- **Secure Communication**: All API calls use HTTPS encryption

## 📞 Support

For issues, questions, or feature requests:
- Create an issue on GitHub
- Check the troubleshooting section above
- Review Chrome extension development documentation

## 🙏 Acknowledgments

- **VirusTotal**: For comprehensive malware intelligence
- **AbuseIPDB**: For IP abuse and threat data
- **OpenAI**: For advanced AI analysis capabilities
- **Chrome Extensions Team**: For the robust extension platform

---

**Built with ❤️ for the cybersecurity community**

*Stay secure, stay vigilant! 🛡️*