// Content script for extracting network data from webpages
(function() {
    'use strict';

    const DOMAIN_REGEX = /(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?/gi;
    const IP_REGEX = /(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/g;

    // Extract all text content from the page
    function extractPageText() {
        const walker = document.createTreeWalker(
            document.body,
            NodeFilter.SHOW_TEXT,
            {
                acceptNode: function(node) {
                    // Skip script and style elements
                    const parent = node.parentElement;
                    if (parent && (parent.tagName === 'SCRIPT' || parent.tagName === 'STYLE')) {
                        return NodeFilter.FILTER_REJECT;
                    }
                    return NodeFilter.FILTER_ACCEPT;
                }
            }
        );

        let textContent = '';
        let node;
        while (node = walker.nextNode()) {
            textContent += node.textContent + ' ';
        }

        return textContent;
    }

    // Extract network resources from various sources
    function extractNetworkData() {
        const ips = new Set();
        const domains = new Set();

        // 1. Extract from page text content
        const pageText = extractPageText();
        const textIPs = pageText.match(IP_REGEX) || [];
        const textDomains = pageText.match(DOMAIN_REGEX) || [];

        textIPs.forEach(ip => {
            if (isValidIP(ip)) {
                ips.add(ip);
            }
        });

        textDomains.forEach(domain => {
            if (isValidDomain(domain)) {
                domains.add(domain.toLowerCase());
            }
        });

        // 2. Extract from HTML attributes
        const elementsWithUrls = document.querySelectorAll('[src], [href], [action], [data-url]');
        elementsWithUrls.forEach(element => {
            ['src', 'href', 'action', 'data-url'].forEach(attr => {
                const url = element.getAttribute(attr);
                if (url) {
                    extractFromUrl(url, ips, domains);
                }
            });
        });

        // 3. Extract from inline scripts and styles
        const scripts = document.querySelectorAll('script:not([src])');
        scripts.forEach(script => {
            const content = script.textContent;
            if (content) {
                const scriptIPs = content.match(IP_REGEX) || [];
                const scriptDomains = content.match(DOMAIN_REGEX) || [];
                
                scriptIPs.forEach(ip => {
                    if (isValidIP(ip)) {
                        ips.add(ip);
                    }
                });

                scriptDomains.forEach(domain => {
                    if (isValidDomain(domain)) {
                        domains.add(domain.toLowerCase());
                    }
                });
            }
        });

        // 4. Extract from CSS (background images, @import, etc.)
        const styles = document.querySelectorAll('style');
        styles.forEach(style => {
            const content = style.textContent;
            if (content) {
                extractFromCSS(content, ips, domains);
            }
        });

        // 5. Extract from meta tags
        const metaTags = document.querySelectorAll('meta[content]');
        metaTags.forEach(meta => {
            const content = meta.getAttribute('content');
            if (content) {
                extractFromUrl(content, ips, domains);
            }
        });

        // Filter out current domain and localhost
        const currentDomain = window.location.hostname;
        domains.delete(currentDomain);
        domains.delete('localhost');
        domains.delete('127.0.0.1');
        
        // Filter out private IP ranges
        const filteredIPs = Array.from(ips).filter(ip => !isPrivateIP(ip));
        
        return {
            ips: filteredIPs,
            domains: Array.from(domains).filter(domain => 
                domain !== currentDomain && 
                domain.length > 3 && 
                domain.includes('.')
            ),
            currentUrl: window.location.href,
            currentDomain: currentDomain,
            timestamp: Date.now()
        };
    }

    function extractFromUrl(url, ips, domains) {
        try {
            // Handle relative URLs
            if (url.startsWith('//')) {
                url = window.location.protocol + url;
            } else if (url.startsWith('/')) {
                url = window.location.origin + url;
            }

            const urlObj = new URL(url, window.location.origin);
            const hostname = urlObj.hostname;

            if (isValidIP(hostname)) {
                ips.add(hostname);
            } else if (isValidDomain(hostname)) {
                domains.add(hostname.toLowerCase());
            }
        } catch (e) {
            // Invalid URL, try to extract with regex
            const urlIPs = url.match(IP_REGEX) || [];
            const urlDomains = url.match(DOMAIN_REGEX) || [];
            
            urlIPs.forEach(ip => {
                if (isValidIP(ip)) {
                    ips.add(ip);
                }
            });

            urlDomains.forEach(domain => {
                if (isValidDomain(domain)) {
                    domains.add(domain.toLowerCase());
                }
            });
        }
    }

    function extractFromCSS(cssContent, ips, domains) {
        // Extract URLs from CSS
        const urlMatches = cssContent.match(/url\s*\(\s*['"]*([^'")]+)['"]*\s*\)/gi) || [];
        urlMatches.forEach(match => {
            const url = match.replace(/url\s*\(\s*['"]*([^'")]+)['"]*\s*\)/i, '$1');
            extractFromUrl(url, ips, domains);
        });

        // Extract @import URLs
        const importMatches = cssContent.match(/@import\s+['"]*([^'";]+)['"]*[^;]*;/gi) || [];
        importMatches.forEach(match => {
            const url = match.replace(/@import\s+['"]*([^'";]+)['"]*[^;]*;/i, '$1');
            extractFromUrl(url, ips, domains);
        });
    }

    function isValidIP(ip) {
        const parts = ip.split('.');
        if (parts.length !== 4) return false;
        
        return parts.every(part => {
            const num = parseInt(part, 10);
            return num >= 0 && num <= 255 && part === num.toString();
        });
    }

    function isValidDomain(domain) {
        if (!domain || domain.length < 4 || domain.length > 253) return false;
        if (domain.startsWith('.') || domain.endsWith('.')) return false;
        if (domain.includes('..')) return false;
        
        // Must contain at least one dot
        if (!domain.includes('.')) return false;
        
        // Check for valid characters
        return /^[a-z0-9.-]+$/i.test(domain);
    }

    function isPrivateIP(ip) {
        const parts = ip.split('.').map(Number);
        
        // 127.x.x.x (localhost)
        if (parts[0] === 127) return true;
        
        // 10.x.x.x
        if (parts[0] === 10) return true;
        
        // 172.16.x.x - 172.31.x.x
        if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
        
        // 192.168.x.x
        if (parts[0] === 192 && parts[1] === 168) return true;
        
        // 169.254.x.x (link-local)
        if (parts[0] === 169 && parts[1] === 254) return true;
        
        return false;
    }

    // Listen for messages from popup
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.action === 'extractNetworkData') {
            try {
                const data = extractNetworkData();
                sendResponse({ success: true, data });
            } catch (error) {
                console.error('Error extracting network data:', error);
                sendResponse({ success: false, error: error.message });
            }
        }
        return true; // Keep message channel open for async response
    });

    // Auto-extract on page load
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            setTimeout(() => {
                const data = extractNetworkData();
                chrome.runtime.sendMessage({
                    action: 'networkDataExtracted',
                    data: data
                });
            }, 1000);
        });
    } else {
        setTimeout(() => {
            const data = extractNetworkData();
            chrome.runtime.sendMessage({
                action: 'networkDataExtracted',
                data: data
            });
        }, 1000);
    }

})();
