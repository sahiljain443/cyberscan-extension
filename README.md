# CyberScan - Chrome Security Extension

A powerful Chrome extension designed for cybersecurity professionals that performs real-time webpage analysis, threat intelligence lookups, and AI-powered security assessments with privacy-first PII protection.


## 🛡️ Features

### 🔍 **Automated Network Analysis**
- **IP Address Detection**: Automatically extracts and analyzes all IP addresses found on webpages (IPv4 & IPv6)
- **Domain Intelligence**: Scans and evaluates external domains with comprehensive threat assessment
- **Real-time Scanning**: Instantly processes webpage content, scripts, meta tags, data attributes, and network resources
- **Enhanced Content Extraction**: Deep analysis of structured content including headings, alerts, and links

### 🌐 **Threat Intelligence Integration**
- **VirusTotal Integration**: Leverages VirusTotal's extensive malware database for IP and domain analysis
- **AbuseIPDB Lookup**: Cross-references IPs against abuse and malicious activity databases
- **Multi-source Verification**: Combines multiple threat intelligence sources for accurate assessments
- **Geographic Intelligence**: Country location data and ISP information for network resources

### 🧠 **AI-Powered Security Analysis**
- **Anthropic Claude Integration**: Uses Claude 3.5 Sonnet for intelligent threat correlation and analysis
- **Manual AI Analysis**: User-triggered AI analysis for better control and resource management
- **Risk Assessment**: Provides automated risk scoring with confidence levels (Low/Medium/High)
- **Security Recommendations**: Generates actionable security advice based on findings
- **Pattern Recognition**: Identifies suspicious patterns and relationships between network resources
- **Structured Analysis**: JSON-formatted findings with severity levels and threat context

### 🔒 **Privacy-First PII Protection**
- **Comprehensive Deidentification**: Removes personally identifiable information before AI analysis
- **Email Address Sanitization**: Replaces email addresses with anonymized placeholders
- **Username Protection**: Anonymizes social media handles and user IDs
- **Phone Number Removal**: Sanitizes various phone number formats
- **Identifier Anonymization**: Removes SSNs, credit card numbers, and account identifiers
- **Consistent Mapping**: Maintains consistent replacements throughout analysis
- **Real-time Processing**: PII removal with zero data retention

### 🎨 **Professional Interface**
- **Tabbed Interface**: Separate views for IPs, Domains, and AI Analysis
- **Real-time Updates**: Live scanning status and progress indicators
- **Copy Functionality**: One-click copying of IPs and domains for further investigation
- **Settings Management**: Built-in API key configuration with secure storage
- **API Status Monitoring**: Real-time status indicators for all connected services

## 📋 Requirements

- **Chrome Browser**: Version 88 or higher
- **API Keys** (Optional but recommended for full functionality):
  - **Anthropic API Key** (for AI analysis with Claude 3.5 Sonnet)
  - **VirusTotal API Key** (for comprehensive threat intelligence)
  - **AbuseIPDB API Key** (for IP abuse intelligence)

## 🚀 Installation

### Method 1: Load Unpacked Extension (Development)

1. **Download the Extension**:
   ```bash
   git clone https://github.com/sahiljain443/cyberscan-extension.git
   cd cyberscan-extension
   ```

2. **Open Chrome Extensions**:
   - Navigate to `chrome://extensions/`
   - Enable "Developer mode" (toggle in top-right corner)

3. **Load the Extension**:
   - Click "Load unpacked"
   - Select the `chrome-extension` folder from the project directory

4. **Verify Installation**:
   - The cyberscan icon should appear in your Chrome toolbar
   - Extension is ready to use!

### Method 2: Install from Chrome Web Store
*Coming soon - extension will be published to Chrome Web Store*

## ⚙️ Configuration

### Setting Up API Keys

Configure API keys directly in the extension settings (click the gear icon):

1. **Anthropic API Key** (Required for AI analysis):
   - Powers Claude 3.5 Sonnet AI analysis
   - Provides intelligent threat correlation and recommendations

2. **VirusTotal API Key** (Optional but recommended):
   - Enables comprehensive malware database lookups
   - Provides detailed threat intelligence for IPs and domains

3. **AbuseIPDB API Key** (Optional but recommended):
   - Cross-references IPs against abuse databases
   - Provides abuse confidence scoring

### Getting API Keys

#### Anthropic API Key
1. Visit [Anthropic Console](https://console.anthropic.com/)
2. Create an account or sign in
3. Navigate to API Keys section
4. Generate a new API key
5. Copy the key (starts with `sk-ant-`)

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

## 📖 Usage Guide

### Basic Usage

1. **Navigate to Any Website**: Open any webpage you want to analyze
2. **Click CyberScan Icon**: Find the orange shield icon in your Chrome toolbar
3. **Automatic Scanning**: The extension automatically scans for IPs and domains
4. **Manual AI Analysis**: Click "Start AI Analysis" for comprehensive AI-powered insights

### Understanding the Interface

#### **IPs Tab**
- Lists all detected IP addresses (IPv4 and IPv6)
- Shows threat levels: Safe (Green), Suspicious (Yellow), Malicious (Red)
- Displays geographic location, ISP information, and ASN data
- VirusTotal detections and AbuseIPDB abuse confidence scores
- Click copy button to copy IP addresses for further investigation

#### **Domains Tab**
- Shows all external domains found on the webpage
- Provides domain reputation and threat intelligence data
- Displays WHOIS country information and threat categories
- Includes creation dates and registrar information
- Real-time threat level assessment

#### **AI Analysis Tab**
- **Manual Trigger**: Click "Start AI Analysis" to begin comprehensive analysis
- **Risk Assessment**: Overall risk level (Low/Medium/High) with confidence scoring
- **Key Findings**: Specific security concerns with severity classifications
- **Threat Context**: Analysis of potential attack vectors and incident types
- **Actionable Recommendations**: Specific next steps for security analysts
- **PII-Protected**: All sensitive data removed before analysis

### Privacy & Security Features

#### **PII Deidentification Process**
The extension automatically removes personally identifiable information before sending any data to external AI services:

- **Email Addresses**: `user@domain.com` → `user1@example.com`
- **Usernames**: `@john_doe` → `@user2`
- **Phone Numbers**: `(555) 123-4567` → `555-0001`
- **SSN/IDs**: `123-45-6789` → `ID3`
- **Account Numbers**: `Account: 98765` → `Account: ID4`

This ensures complete privacy protection while maintaining analysis effectiveness.

#### **Data Handling**
- **No Storage**: Extension doesn't store personal browsing data
- **Real-time Processing**: PII removal happens instantly before AI analysis
- **Consistent Anonymization**: Same PII items get same replacement tokens
- **Secure Communication**: All API calls use HTTPS encryption

### Interpreting Results

#### Threat Levels
- **🟢 Safe**: No threats detected, clean reputation
- **🟡 Suspicious**: Some concerns detected, requires monitoring
- **🔴 Malicious**: Confirmed threats identified, immediate action required

#### AI Risk Assessment
- **Low Risk**: Minimal security concerns, standard web activity
- **Medium Risk**: Some suspicious activity detected, warrants investigation
- **High Risk**: Significant threats identified, immediate investigation needed

## 🏗️ Project Structure

```
cyberscan-extension/
├── chrome-extension/          # Chrome extension files
│   ├── manifest.json         # Extension manifest
│   ├── popup.html           # Extension popup interface
│   ├── popup.js             # Popup functionality and UI logic
│   ├── background.js        # Background service worker and API integration
│   ├── content.js           # Content script for webpage analysis
│   ├── styles.css           # Extension styling and themes
│   └── icons/               # Extension icons
├── .cursor/                  # Cursor IDE configuration
│   └── rules/               # Development rules and guidelines
├── generated-icon.png        # Extension icon
├── manifest.json            # Root manifest file
├── package.json             # Project configuration
├── README.md                # Comprehensive project documentation
├── INSTALLATION.md          # Step-by-step installation guide
├── CONTRIBUTING.md          # Contribution guidelines
├── LICENSE                  # MIT license
└── .gitignore              # Git ignore rules
```

## 🔧 Development

### Prerequisites
- Node.js 18+ 
- Chrome Browser
- TypeScript knowledge (optional)

### Development Setup

1. **Clone Repository**:
   ```bash
   git clone https://github.com/sahiljain443/cyberscan-extension.git
   cd cyberscan-extension
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
- **Anthropic Issues**: Verify API key format (starts with `sk-ant-`)
- **VirusTotal Issues**: Check rate limits and key validity
- **AbuseIPDB Issues**: Verify account status and key permissions
- Check extension settings for proper API key configuration

#### AI Analysis Not Working
- Ensure Anthropic API key is properly configured in Settings
- Check that you have sufficient API credits/quota
- Verify network connectivity
- Look for error messages in the AI Analysis tab

#### No Data Displayed
- Ensure webpage has loaded completely before clicking extension
- Check if webpage contains external resources to analyze
- Verify content script permissions in manifest
- Some sites may block content extraction due to CSP policies

#### PII Protection Issues
- PII deidentification runs automatically - no user action needed
- Check browser console for deidentification logs
- Sensitive data removal happens before AI analysis

### Debug Mode

Enable debug logging by opening Chrome DevTools:
1. Right-click on extension icon → "Inspect popup"
2. Check Console tab for detailed logs
3. Monitor Network tab for API requests
4. Look for PII deidentification logs (🔒 emoji)

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

### Privacy-First Architecture
- **Zero Data Retention**: No personal data stored or transmitted without anonymization
- **PII Deidentification**: Comprehensive removal of sensitive information before AI analysis
- **Local Processing**: Initial data extraction and anonymization happens locally
- **Encrypted Communication**: All API communications use HTTPS/TLS encryption
- **Minimal Data Sharing**: Only anonymized, security-relevant data shared with AI services

### PII Protection Details

The extension implements a comprehensive PII deidentification system:

#### **Protected Data Types**
1. **Email Addresses**: Various formats including international domains
2. **User Identifiers**: Social media handles, usernames, login IDs
3. **Phone Numbers**: US and international formats, various separators
4. **Financial Data**: Credit card patterns, account numbers
5. **Government IDs**: SSN patterns, ID numbers
6. **Company References**: Automatic anonymization of company-specific terms

#### **Anonymization Process**
1. **Pattern Detection**: Advanced regex patterns identify sensitive data
2. **Consistent Mapping**: Same data gets same replacement across analysis
3. **Context Preservation**: Maintains analytical value while removing sensitivity
4. **Real-time Processing**: No temporary storage of original sensitive data

#### **Security Benefits**
- **Compliance**: Helps meet privacy regulations and corporate policies
- **Risk Reduction**: Eliminates accidental data exposure to third-party AI services
- **Audit Trail**: Logs number of PII items removed (not the items themselves)
- **Transparency**: Clear indication when PII protection is active

## 📞 Support

For issues, questions, or feature requests:
- Create an issue on GitHub
- Check the troubleshooting section above
- Review Chrome extension development documentation

## 🙏 Acknowledgments

- **VirusTotal**: For comprehensive malware intelligence
- **AbuseIPDB**: For IP abuse and threat data
- **Anthropic**: For Claude AI analysis capabilities
- **Chrome Extensions Team**: For the robust extension platform
- **Cybersecurity Community**: For continuous feedback and testing

---

**Built with ❤️ and 🔒 for the cybersecurity community**

*Stay secure, stay private, stay vigilant! 🛡️*
