# CyberScanAI Installation Guide

This guide provides step-by-step instructions for installing and configuring the CyberScanAI Chrome extension with AI-powered security analysis and privacy-first PII protection.

## 📋 Prerequisites

- **Chrome Browser**: Version 88 or higher
- **Git**: For cloning the repository (optional)

## 🚀 Quick Installation

### Method 1: Load Unpacked Extension (Development)

#### Step 1: Download the Extension

**Option A: Clone with Git**
```bash
git clone https://github.com/sahiljain443/cyberscan-extension.git
cd cyberscan-extension
```

**Option B: Download ZIP**
1. Visit the [GitHub repository](https://github.com/sahiljain443/cyberscan-extension)
2. Click "Code" → "Download ZIP"
3. Extract the ZIP file to your desired location

#### Step 2: Load Extension in Chrome

1. **Open Chrome Extensions**:
   - Navigate to `chrome://extensions/`
   - Enable "Developer mode" (toggle in top-right corner)

2. **Load the Extension**:
   - Click "Load unpacked"
   - Select the `chrome-extension` folder from the project directory

3. **Verify Installation**:
   - The CyberScanAI icon should appear in your Chrome toolbar
   - Extension is ready to use!

### Method 2: Chrome Web Store (Coming Soon)
The extension will be published to the Chrome Web Store for easier installation.

## 🔑 Setting Up API Keys

CyberScanAI works without any API keys for basic functionality, but API keys unlock advanced features:

### Configure Keys in Extension Settings

1. **Click the CyberScanAI icon** in your Chrome toolbar
2. **Click the gear icon** (⚙️) to open settings
3. **Enter your API keys** in the respective fields:
   - Anthropic API Key (for AI analysis)
   - VirusTotal API Key (for enhanced threat intelligence)
   - AbuseIPDB API Key (for IP abuse intelligence)
4. **Click "Save Settings"**

### Getting API Keys

#### Anthropic API Key (Required for AI Analysis)

1. Visit [Anthropic Console](https://console.anthropic.com/)
2. Create an account or sign in
3. Navigate to API Keys section
4. Generate a new API key
5. Copy the key (starts with `sk-ant-`)
6. Paste into extension settings

**Benefits:**
- AI-powered security analysis with Claude 3.5 Sonnet
- Intelligent threat correlation and risk assessment
- Actionable security recommendations

#### VirusTotal API Key (Optional)

1. Visit [VirusTotal](https://www.virustotal.com/)
2. Create a free account
3. Go to your profile settings
4. Find the "API Key" section
5. Copy your personal API key
6. Paste into extension settings

**Benefits:**
- Comprehensive malware database lookups
- Enhanced IP and domain threat intelligence
- Detection results from multiple security engines

#### AbuseIPDB API Key (Optional)

1. Visit [AbuseIPDB](https://www.abuseipdb.com/)
2. Register for a free account
3. Navigate to your account settings
4. Generate an API key in the API section
5. Copy the key
6. Paste into extension settings

**Benefits:**
- IP abuse confidence scoring
- Blacklist and reputation data
- Community-driven threat intelligence

## ✅ Verification & Testing

### Basic Functionality Test

1. **Navigate to any website** (e.g., `google.com`)
2. **Click the CyberScanAI icon** in your Chrome toolbar
3. **Automatic scanning** should begin immediately
4. **Check the IPs tab** - should show detected IP addresses
5. **Check the Domains tab** - should show external domains
6. **Try AI Analysis** - click "Start AI Analysis" (requires Anthropic API key)

### API Status Check

1. **Open extension popup**
2. **Click settings gear icon** (⚙️)
3. **Check API status indicators**:
   - 🟢 Green = API working correctly
   - 🔴 Red = API key missing or invalid
   - 🟡 Yellow = API available but not configured

### Privacy Protection Test

1. **Open browser developer console**:
   - Right-click CyberScanAI icon → "Inspect popup"
   - Go to Console tab
2. **Trigger AI analysis** on a page with some text content
3. **Look for logs** with 🔒 emoji showing PII deidentification in action

## 🛠️ Troubleshooting

### Extension Issues

**Problem**: Extension won't load
- **Solution**: Ensure all files are in the `chrome-extension` folder
- **Solution**: Check that Developer mode is enabled in `chrome://extensions/`
- **Solution**: Try reloading the extension (click reload button in extensions page)

**Problem**: No data appears in popup
- **Solution**: Wait for the webpage to fully load before opening extension
- **Solution**: Check if the webpage contains external resources to analyze
- **Solution**: Some sites may block content extraction due to security policies

**Problem**: Extension icon not visible
- **Solution**: Check if the extension is enabled in `chrome://extensions/`
- **Solution**: Pin the extension icon (puzzle piece icon → pin CyberScanAI)

### AI Analysis Issues

**Problem**: "Start AI Analysis" button doesn't work
- **Solution**: Configure Anthropic API key in extension settings
- **Solution**: Verify API key format (should start with `sk-ant-`)
- **Solution**: Check that you have sufficient API credits/quota
- **Solution**: Ensure network connectivity

**Problem**: AI analysis returns errors
- **Solution**: Check browser console for detailed error messages
- **Solution**: Verify Anthropic API key permissions
- **Solution**: Try again if rate limits are exceeded

### API Key Issues

**Problem**: API status shows red/invalid
- **Solution**: Double-check API key format and validity
- **Solution**: Ensure API keys are active and have proper permissions
- **Solution**: Check API provider account status and credit balance

**Problem**: Limited threat intelligence data
- **Solution**: This is normal without VirusTotal/AbuseIPDB keys
- **Solution**: Add optional API keys for enhanced functionality
- **Solution**: Free tier API keys have rate limits

## 🔄 Updates & Maintenance

### Updating the Extension

**For Git Users:**
```bash
cd cyberscan-extension
git pull origin main
```

**For ZIP Users:**
1. Download the latest version from GitHub
2. Extract to the same location (overwrite existing files)

**After updating:**
1. Go to `chrome://extensions/`
2. Find CyberScanAI extension
3. Click the reload button (🔄)
4. Extension will restart with new features

### Extension Permissions

CyberScanAI requires these permissions:
- **activeTab**: Read webpage content for analysis
- **storage**: Save API keys and settings securely
- **Host permissions**: Access threat intelligence APIs

## 🔒 Privacy & Security

### Data Protection Features

- **PII Deidentification**: Automatically removes sensitive data before AI analysis
- **Local Processing**: Initial data extraction happens in your browser
- **No Data Storage**: Extension doesn't store personal browsing data
- **Encrypted Communication**: All API calls use HTTPS
- **Manual AI Trigger**: AI analysis only runs when you click the button

### What Data is Processed

**Locally (in your browser):**
- Webpage text content
- IP addresses and domains found on pages
- Structured content (headings, alerts, links)

**Sent to External APIs (after PII removal):**
- Anonymized page content for AI analysis
- IP addresses for threat intelligence lookup
- Domain names for reputation checks

**Never Sent:**
- Full webpage URLs
- Personal information (emails, phone numbers, SSNs)
- Browser history or personal data

## 🆘 Getting Help

### Debug Information

1. **Extension Console**: Right-click extension icon → "Inspect popup" → Console tab
2. **Background Console**: `chrome://extensions/` → CyberScanAI → "Inspect views: background page"
3. **Look for logs** with emojis: 📋 (content), 🔒 (privacy), 🚀 (AI analysis)

### Support Channels

- **GitHub Issues**: Report bugs and request features
- **Documentation**: Check README.md for detailed usage guide
- **Console Logs**: Include browser console output when reporting issues

## 📚 Next Steps

After successful installation:

1. **Read the [Usage Guide](README.md#usage-guide)** for detailed instructions
2. **Configure API keys** for enhanced functionality
3. **Test on different websites** to see various analysis results
4. **Explore privacy features** by checking console logs
5. **Review security findings** and recommendations

---

**Installation complete! Your CyberScanAI extension is ready to provide AI-powered security analysis with privacy protection.** 🛡️🔒