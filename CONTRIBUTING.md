# Contributing to CyberGuard

Thank you for your interest in contributing to CyberGuard! This document provides guidelines for contributing to the project.

## 🤝 How to Contribute

### Reporting Issues
- Use the GitHub issue tracker to report bugs
- Include detailed steps to reproduce the issue
- Provide browser version and extension version information
- Include screenshots if applicable

### Suggesting Features
- Open an issue with the "enhancement" label
- Describe the feature and its benefits
- Explain how it fits with the project's goals

### Code Contributions
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test thoroughly
5. Commit with descriptive messages
6. Push to your fork
7. Open a Pull Request

## 🔧 Development Setup

1. Follow the [Installation Guide](INSTALLATION.md)
2. Make sure all tests pass
3. Verify the extension loads correctly in Chrome

## 📝 Code Style

### JavaScript/TypeScript
- Use TypeScript for type safety
- Follow existing code formatting
- Add comments for complex logic
- Use meaningful variable names

### CSS
- Maintain the orange theme consistency
- Use existing CSS classes when possible
- Follow BEM naming convention

### Chrome Extension
- Follow Chrome extension best practices
- Handle errors gracefully
- Respect user privacy

## 🧪 Testing

- Test the extension on different websites
- Verify all tabs (IPs, Domains, AI Analysis) work correctly
- Check error handling with invalid data
- Test with and without API keys

## 📋 Pull Request Guidelines

### Before Submitting
- [ ] Code follows project style guidelines
- [ ] Extension loads without errors
- [ ] All features work as expected
- [ ] Documentation updated if needed
- [ ] No console errors or warnings

### PR Description
Include:
- What changes were made
- Why the changes were necessary
- How to test the changes
- Screenshots if UI changes were made

## 🛡️ Security Considerations

- Never commit API keys or sensitive data
- Follow secure coding practices
- Report security vulnerabilities privately
- Test for potential XSS or injection issues

## 📖 Documentation

- Update README.md for new features
- Add inline code comments
- Update API documentation if applicable
- Include examples for new functionality

## 🎯 Project Goals

Keep these goals in mind when contributing:
- **Security First**: All features should enhance security analysis
- **User Experience**: Interface should be clean and intuitive
- **Performance**: Extension should be fast and responsive
- **Accuracy**: Threat intelligence should be reliable

## 🚫 What Not to Contribute

- Features that compromise user privacy
- Code that bypasses security measures
- Changes that break existing functionality
- Non-security related features

## ❓ Questions?

- Open an issue for questions about contributing
- Check existing issues before creating new ones
- Be respectful and constructive in discussions

Thank you for helping make CyberGuard better! 🛡️