# CyberGuard Installation Guide

This guide provides step-by-step instructions for installing and configuring the CyberGuard Chrome extension.

## 📋 Prerequisites

- Chrome Browser (Version 88 or higher)
- Node.js 18+ (for backend server)
- Git (for cloning the repository)

## 🚀 Quick Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/cyberguard-extension.git
cd cyberguard-extension
```

### Step 2: Install Dependencies

```bash
npm install
```

### Step 3: Set Up Environment Variables

Create a `.env` file in the root directory:

```bash
# Required for AI Analysis
OPENAI_API_KEY=your_openai_api_key_here

# Optional - For enhanced threat intelligence
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
```

### Step 4: Start the Backend Server

```bash
npm run dev
```

The server will start on `http://localhost:5000`

### Step 5: Load Extension in Chrome

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable "Developer mode" (toggle in top-right corner)
3. Click "Load unpacked"
4. Select the `chrome-extension` folder from your project directory
5. The CyberGuard icon should appear in your Chrome toolbar

## 🔑 Getting API Keys

### OpenAI API Key (Required for AI Analysis)

1. Visit [OpenAI Platform](https://platform.openai.com/)
2. Sign up or log in to your account
3. Navigate to the API section
4. Click "Create new secret key"
5. Copy the key and add it to your `.env` file

### VirusTotal API Key (Optional)

1. Visit [VirusTotal](https://www.virustotal.com/)
2. Create a free account
3. Go to your profile settings
4. Find the "API Key" section
5. Copy your personal API key

### AbuseIPDB API Key (Optional)

1. Visit [AbuseIPDB](https://www.abuseipdb.com/)
2. Register for a free account
3. Navigate to your account settings
4. Generate an API key in the API section
5. Copy the key for your configuration

## ✅ Verification

### Test the Extension

1. Visit any website (e.g., `google.com`)
2. Click the CyberGuard icon in your Chrome toolbar
3. The popup should open and start scanning the page
4. You should see detected IPs, domains, and AI analysis

### Test the Backend

1. Open `http://localhost:5000` in your browser
2. You should see the CyberGuard documentation page
3. Check `http://localhost:5000/api/health` for API status

## 🛠️ Troubleshooting

### Extension Issues

**Problem**: Extension won't load
- **Solution**: Check that all files are in the `chrome-extension` folder
- **Solution**: Verify Developer mode is enabled
- **Solution**: Check Chrome console for errors

**Problem**: No data appears in popup
- **Solution**: Ensure the backend server is running
- **Solution**: Check that the webpage has external resources
- **Solution**: Wait for the page to fully load before opening extension

### Backend Issues

**Problem**: Server won't start
- **Solution**: Check that port 5000 is available
- **Solution**: Verify Node.js is properly installed
- **Solution**: Run `npm install` to ensure dependencies are installed

**Problem**: API errors in extension
- **Solution**: Verify API keys are correctly set in `.env`
- **Solution**: Check server logs for detailed error messages
- **Solution**: Ensure server is accessible at `http://localhost:5000`

### API Key Issues

**Problem**: OpenAI analysis not working
- **Solution**: Verify OPENAI_API_KEY is set correctly
- **Solution**: Check that your OpenAI account has sufficient credits
- **Solution**: Ensure the API key has proper permissions

**Problem**: Limited threat intelligence data
- **Solution**: This is normal if VirusTotal/AbuseIPDB keys aren't configured
- **Solution**: Add the optional API keys for enhanced functionality

## 🔄 Updates

To update the extension:

1. Pull latest changes: `git pull origin main`
2. Install new dependencies: `npm install`
3. Restart the backend server
4. Reload the extension in Chrome (`chrome://extensions/` → click reload button)

## 🆘 Getting Help

If you encounter issues:

1. Check the troubleshooting section above
2. Review the server logs in your terminal
3. Open Chrome DevTools for the extension popup
4. Create an issue on GitHub with detailed error information

## 📚 Next Steps

After successful installation:

1. Read the [Usage Guide](README.md#usage-guide)
2. Explore the different analysis tabs
3. Test on various websites
4. Configure additional API keys for enhanced functionality

---

**Installation complete! Your CyberGuard extension is ready to protect your browsing experience.** 🛡️