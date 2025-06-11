# Contributing to CyberScanAI

Thank you for your interest in contributing to CyberScanAI! This document provides guidelines for contributing to the project.

## 🤝 How to Contribute

### Reporting Issues
- Use the GitHub issue tracker to report bugs
- Include detailed steps to reproduce the issue
- Provide browser version and extension version information
- Include screenshots if applicable
- Include browser console logs when relevant

### Suggesting Features
- Open an issue with the "enhancement" label
- Describe the feature and its benefits
- Explain how it fits with the project's security analysis goals
- Consider privacy implications of new features

### Code Contributions
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test thoroughly across different websites
5. Commit with descriptive messages
6. Push to your fork
7. Open a Pull Request

## 🔧 Development Setup

1. Follow the [Installation Guide](INSTALLATION.md)
2. Load the extension in Chrome with Developer mode
3. Test on various websites to ensure functionality
4. Configure API keys for testing AI analysis features

## 📝 Code Style

### JavaScript
- Use modern JavaScript (ES6+) features
- Follow existing code formatting and structure
- Add meaningful comments for complex logic
- Use descriptive variable and function names
- Handle errors gracefully with try-catch blocks

### CSS
- Maintain the orange theme consistency (#FF6B35)
- Use existing CSS classes when possible
- Follow BEM naming convention where applicable
- Ensure responsive design for different popup sizes

### Chrome Extension
- Follow Chrome extension best practices and security guidelines
- Handle permissions appropriately
- Respect user privacy and data protection
- Use Chrome APIs efficiently
- Test manifest v3 compatibility

## 🔒 Privacy & Security Guidelines

### PII Protection
- Never log or expose personally identifiable information
- Ensure all new features respect the PII deidentification system
- Test that sensitive data is properly anonymized before external API calls
- Follow the principle of data minimization

### API Integration
- Secure handling of API keys in local storage
- Implement proper error handling for API failures
- Follow rate limiting best practices
- Validate all external API responses

### Content Security
- Sanitize all user input and webpage content
- Prevent XSS and injection vulnerabilities
- Use Content Security Policy appropriately
- Handle malicious webpage content safely

## 🧪 Testing

### Manual Testing
- Test the extension on different types of websites:
  - Corporate websites
  - E-commerce sites
  - Social media platforms
  - News websites
  - Technical documentation sites
- Verify all tabs (IPs, Domains, AI Analysis) work correctly
- Test with and without various API keys configured
- Check error handling with invalid or malicious content

### Privacy Testing
- Verify PII deidentification works correctly
- Check console logs for proper anonymization
- Test that no sensitive data is sent to external APIs
- Verify local storage security

### Performance Testing
- Test on pages with large amounts of content
- Verify extension doesn't slow down page loading
- Check memory usage and resource consumption
- Test responsiveness of the popup interface

## 📋 Pull Request Guidelines

### Before Submitting
- [ ] Code follows project style guidelines
- [ ] Extension loads without errors in Chrome Developer mode
- [ ] All features work as expected across different websites
- [ ] Privacy features (PII deidentification) are working
- [ ] Documentation updated if needed
- [ ] No console errors or warnings
- [ ] API integrations are secure and handle errors properly

### PR Description Template
```
## What Changes Were Made
- Brief description of changes

## Why These Changes Were Necessary
- Explanation of the problem being solved

## How to Test
- Step-by-step testing instructions

## Security Considerations
- Any privacy or security implications

## Screenshots (if applicable)
- Before/after screenshots for UI changes
```

## 🛡️ Security Considerations

### Critical Security Requirements
- **Never commit API keys** or sensitive credentials
- **Follow secure coding practices** to prevent vulnerabilities
- **Report security vulnerabilities privately** before public disclosure
- **Test for XSS, injection, and other web security issues**
- **Validate all external data** before processing

### Privacy Requirements
- All webpage content must be processed through PII deidentification
- No personal data should be logged or stored permanently
- API calls must use anonymized data only
- User consent and transparency are paramount

## 📖 Documentation

### Required Documentation Updates
- Update README.md for new features or significant changes
- Add inline code comments for complex functions
- Update installation guides if setup process changes
- Document new API integrations or configuration options
- Include privacy impact assessments for new features

### Code Documentation
- JSDoc comments for all public functions
- Clear variable naming and function descriptions
- Explanation of any complex algorithms or security measures
- API integration documentation with error handling examples

## 🎯 Project Goals

Keep these goals in mind when contributing:

### Primary Goals
- **Security First**: All features should enhance cybersecurity analysis
- **Privacy Protection**: User data privacy is non-negotiable
- **Accuracy**: Threat intelligence should be reliable and actionable
- **User Experience**: Interface should be intuitive for security professionals

### Technical Goals
- **Performance**: Extension should be fast and responsive
- **Reliability**: Graceful error handling and fallback mechanisms
- **Maintainability**: Clean, documented, and testable code
- **Extensibility**: Architecture that supports future enhancements

## 🚫 What Not to Contribute

### Unacceptable Contributions
- Features that compromise user privacy or data protection
- Code that bypasses or weakens security measures
- Changes that break existing functionality without proper migration
- Non-security related features that don't align with project goals
- Code that introduces dependencies on external servers or databases

### Discouraged Contributions
- Features that significantly increase resource consumption
- Changes that make the extension incompatible with Chrome policies
- Code that hardcodes configuration or removes flexibility
- Features that require complex setup or additional software

## 🔄 Development Workflow

### Branch Naming
- `feature/description` - New features
- `fix/description` - Bug fixes
- `security/description` - Security improvements
- `docs/description` - Documentation updates

### Commit Messages
Follow conventional commit format:
```
type(scope): description

- feat: New feature
- fix: Bug fix
- docs: Documentation changes
- security: Security improvements
- refactor: Code refactoring
- test: Testing improvements
```

### Code Review Process
1. Automated checks must pass
2. Manual testing verification
3. Security review for sensitive changes
4. Privacy impact assessment
5. Documentation review
6. Final approval and merge

## ❓ Questions and Support

### Getting Help
- Open an issue for questions about contributing
- Check existing issues and pull requests before creating new ones
- Join discussions respectfully and constructively
- Follow the code of conduct in all interactions

### Resources
- [Chrome Extension Documentation](https://developer.chrome.com/docs/extensions/)
- [Anthropic Claude API Documentation](https://docs.anthropic.com/)
- [VirusTotal API Documentation](https://developers.virustotal.com/)
- [AbuseIPDB API Documentation](https://docs.abuseipdb.com/)

## 🏆 Recognition

Contributors who make significant improvements to security, privacy, or functionality will be recognized in:
- Project README acknowledgments
- Release notes for major contributions
- Special thanks for security vulnerability reports

Thank you for helping make CyberScanAI a better tool for cybersecurity professionals! 🛡️🔒