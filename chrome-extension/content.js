// Content script for extracting IPs, domains, and webpage content for security analysis
(function() {
    'use strict';

    const DOMAIN_REGEX = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;
    const IPV4_REGEX = /(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/g;
    const IPV6_REGEX = /(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|::(?:ffff(?::0{1,4})?:)?(?:(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9]))/g;

    // List of valid top-level domains
    const VALID_TLDS = [
        'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'co', 'io', 'ai', 'app', 'dev',
        'uk', 'ca', 'au', 'de', 'fr', 'jp', 'cn', 'ru', 'br', 'in', 'mx', 'nl', 'se',
        'info', 'biz', 'name', 'pro', 'museum', 'travel', 'jobs', 'tel', 'mobi',
        'asia', 'cat', 'coop', 'aero', 'xxx', 'xxx', 'post', 'geo'
    ];

    // Extract all visible text content from the page for analysis
    function extractPageContent() {
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
                    // Skip hidden elements
                    if (parent && window.getComputedStyle(parent).display === 'none') {
                        return NodeFilter.FILTER_REJECT;
                    }
                    return NodeFilter.FILTER_ACCEPT;
                }
            }
        );

        let textContent = '';
        let node;
        while (node = walker.nextNode()) {
            const text = node.textContent.trim();
            if (text) {
                textContent += text + ' ';
            }
        }

        return textContent.trim();
    }

    // Extract structured content for better context
    function extractStructuredContent() {
        const content = {
            title: document.title || '',
            url: window.location.href,
            domain: window.location.hostname,
            headings: [],
            paragraphs: [],
            lists: [],
            tables: [],
            alerts: [],
            links: []
        };

        // Extract headings
        document.querySelectorAll('h1, h2, h3, h4, h5, h6').forEach(heading => {
            const text = heading.textContent.trim();
            if (text) {
                content.headings.push({
                    level: heading.tagName.toLowerCase(),
                    text: text
                });
            }
        });

        // Extract paragraphs
        document.querySelectorAll('p').forEach(p => {
            const text = p.textContent.trim();
            if (text && text.length > 20) { // Only meaningful paragraphs
                content.paragraphs.push(text);
            }
        });

        // Extract lists
        document.querySelectorAll('ul, ol').forEach(list => {
            const items = Array.from(list.querySelectorAll('li')).map(li => li.textContent.trim());
            if (items.length > 0) {
                content.lists.push(items);
            }
        });

        // Extract table data
        document.querySelectorAll('table').forEach(table => {
            const rows = Array.from(table.querySelectorAll('tr')).map(row => {
                return Array.from(row.querySelectorAll('td, th')).map(cell => cell.textContent.trim());
            });
            if (rows.length > 0) {
                content.tables.push(rows);
            }
        });

        // Extract potential alert/notification content
        document.querySelectorAll('.alert, .notification, .warning, .error, .danger, [class*="alert"], [class*="warning"], [class*="error"]').forEach(alert => {
            const text = alert.textContent.trim();
            if (text) {
                content.alerts.push(text);
            }
        });

        // Extract links with context
        document.querySelectorAll('a[href]').forEach(link => {
            const text = link.textContent.trim();
            const href = link.getAttribute('href');
            if (text && href) {
                content.links.push({
                    text: text,
                    url: href
                });
            }
        });

        return content;
    }


    
    // Extract IPs and domains from script tags and JSON data
    function extractFromScriptTags() {
        const ips = new Set();
        const domains = new Set();
        
        try {
            // Get all script tags
            const scripts = document.querySelectorAll('script');
            
            scripts.forEach(script => {
                const scriptContent = script.textContent || script.innerText || '';
                
                // Skip if script is too large (performance)
                if (scriptContent.length > 50000) return;
                
                // Extract IPs from script content
                const scriptIPv4s = scriptContent.match(IPV4_REGEX) || [];
                const scriptIPv6s = scriptContent.match(IPV6_REGEX) || [];
                [...scriptIPv4s, ...scriptIPv6s].forEach(ip => {
                    if (isValidIP(ip)) {
                        ips.add(ip);
                    }
                });
                
                // Extract domains from script content
                const scriptDomains = scriptContent.match(DOMAIN_REGEX) || [];
                scriptDomains.forEach(domain => {
                    if (isValidDomain(domain)) {
                        const rootDomain = extractRootDomain(domain);
                        if (rootDomain) {
                            domains.add(rootDomain.toLowerCase());
                        }
                    }
                });
            });
            
            console.log(`📜 Script extraction found ${ips.size} IPs and ${domains.size} domains`);
            
        } catch (error) {
            console.error('Error extracting from scripts:', error);
        }
        
        return { ips: Array.from(ips), domains: Array.from(domains) };
    }
    
    // Extract IPs and domains from meta tags and data attributes
    function extractFromMetaAndDataAttributes() {
        const ips = new Set();
        const domains = new Set();
        
        try {
            // Check meta tags
            const metaTags = document.querySelectorAll('meta[content]');
            metaTags.forEach(meta => {
                const content = meta.getAttribute('content') || '';
                
                // Extract IPs from meta content
                const metaIPv4s = content.match(IPV4_REGEX) || [];
                const metaIPv6s = content.match(IPV6_REGEX) || [];
                [...metaIPv4s, ...metaIPv6s].forEach(ip => {
                    if (isValidIP(ip)) {
                        ips.add(ip);
                    }
                });
                
                // Extract domains from meta content
                const metaDomains = content.match(DOMAIN_REGEX) || [];
                metaDomains.forEach(domain => {
                    if (isValidDomain(domain)) {
                        const rootDomain = extractRootDomain(domain);
                        if (rootDomain) {
                            domains.add(rootDomain.toLowerCase());
                        }
                    }
                });
            });
            
            // Check data attributes on important elements
            const elementsWithData = document.querySelectorAll('[data-ip], [data-domain], [data-url], [data-host]');
            elementsWithData.forEach(element => {
                // Get all data attributes
                const dataAttrs = element.dataset;
                const dataContent = Object.values(dataAttrs).join(' ');
                
                // Extract IPs from data attributes
                const dataIPv4s = dataContent.match(IPV4_REGEX) || [];
                const dataIPv6s = dataContent.match(IPV6_REGEX) || [];
                [...dataIPv4s, ...dataIPv6s].forEach(ip => {
                    if (isValidIP(ip)) {
                        ips.add(ip);
                    }
                });
                
                // Extract domains from data attributes
                const dataDomains = dataContent.match(DOMAIN_REGEX) || [];
                dataDomains.forEach(domain => {
                    if (isValidDomain(domain)) {
                        const rootDomain = extractRootDomain(domain);
                        if (rootDomain) {
                            domains.add(rootDomain.toLowerCase());
                        }
                    }
                });
            });
            
            console.log(`🏷️ Meta/Data extraction found ${ips.size} IPs and ${domains.size} domains`);
            
        } catch (error) {
            console.error('Error extracting from meta/data attributes:', error);
        }
        
        return { ips: Array.from(ips), domains: Array.from(domains) };
    }

    // Extract root domain from subdomain (e.g., api.example.com -> example.com)
    function extractRootDomain(domain) {
        if (!domain) return domain;
        
        // List of known TLDs that should be treated as single domains
        const multiPartTLDs = [
            'co.uk', 'com.au', 'co.jp', 'co.kr', 'com.br', 'co.za', 'co.in',
            'com.mx', 'co.nz', 'com.ar', 'com.tr', 'com.sg', 'co.th', 'com.my',
            'org.uk', 'net.au', 'gov.uk', 'edu.au', 'ac.uk', 'gov.au'
        ];
        
        const parts = domain.toLowerCase().split('.');
        
        // Check for multi-part TLDs
        for (const tld of multiPartTLDs) {
            if (domain.endsWith('.' + tld)) {
                const tldParts = tld.split('.');
                const domainParts = parts.length - tldParts.length - 1;
                if (domainParts >= 0) {
                    return parts.slice(domainParts).join('.');
                }
            }
        }
        
        // Standard TLD (e.g., .com, .org, .net)
        if (parts.length >= 2) {
            return parts.slice(-2).join('.');
        }
        
        return domain;
    }

    // Extract IPs and domains from webpage content, scripts, and data attributes
    function extractNetworkEntities() {
        const ips = new Set();
        const rootDomains = new Set();

        // Get full page content
        const pageText = extractPageContent();
        
        // Extract IPs from JSON data and script tags (for dynamic sites)
        const scriptData = extractFromScriptTags();
        scriptData.ips.forEach(ip => ips.add(ip));
        scriptData.domains.forEach(domain => rootDomains.add(domain));
        
        // Extract from data attributes and meta tags
        const metaData = extractFromMetaAndDataAttributes();
        metaData.ips.forEach(ip => ips.add(ip));
        metaData.domains.forEach(domain => rootDomains.add(domain));
        
        // Extract IPs from page content (both IPv4 and IPv6)
        const textIPv4s = pageText.match(IPV4_REGEX) || [];
        const textIPv6s = pageText.match(IPV6_REGEX) || [];
        const allIPs = [...textIPv4s, ...textIPv6s];
        
        allIPs.forEach(ip => {
            if (isValidIP(ip)) {
                ips.add(ip);
            }
        });

        // Extract domains from page content and convert to root domains
        const textDomains = pageText.match(DOMAIN_REGEX) || [];
        textDomains.forEach(domain => {
            if (isValidDomain(domain)) {
                const rootDomain = extractRootDomain(domain);
                if (rootDomain) {
                    rootDomains.add(rootDomain.toLowerCase());
                }
            }
        });

        // Also check structured content for IPs/domains
        const structuredContent = extractStructuredContent();
        
        // Check links for domains and extract root domains
        structuredContent.links.forEach(link => {
            try {
                const url = new URL(link.url, window.location.origin);
                const hostname = url.hostname;
                if (isValidDomain(hostname)) {
                    const rootDomain = extractRootDomain(hostname);
                    if (rootDomain) {
                        rootDomains.add(rootDomain.toLowerCase());
                    }
                }
            } catch (e) {
                // Invalid URL, ignore
            }
        });

        // Filter out current domain
        const currentDomain = window.location.hostname;
        const currentRootDomain = extractRootDomain(currentDomain);
        rootDomains.delete(currentRootDomain?.toLowerCase());
        
        return {
            ips: Array.from(ips),
            domains: Array.from(rootDomains).filter(domain => 
                domain && 
                domain.length > 3 && 
                domain.includes('.') &&
                domain !== currentRootDomain?.toLowerCase()
            ),
            pageContent: {
                fullText: pageText,
                structured: structuredContent
            },
            currentUrl: window.location.href,
            currentDomain: currentDomain,
            timestamp: Date.now()
        };
    }

    function isValidIP(ip) {
        if (!ip) return false;
        
        // Check if it's IPv4
        if (ip.includes('.')) {
            return isValidIPv4(ip);
        }
        
        // Check if it's IPv6
        if (ip.includes(':')) {
            return isValidIPv6(ip);
        }
        
        return false;
    }

    function isValidIPv4(ip) {
        const parts = ip.split('.');
        if (parts.length !== 4) return false;
        
        return parts.every(part => {
            const num = parseInt(part, 10);
            return num >= 0 && num <= 255 && part === num.toString();
        });
    }

    function isValidIPv6(ip) {
        // Remove any zone identifier (e.g., %eth0)
        const cleanIP = ip.split('%')[0];
        
        // Basic IPv6 validation
        if (cleanIP.length > 39) return false;
        
        // Check for valid IPv6 characters
        if (!/^[0-9a-fA-F:]+$/.test(cleanIP)) {
            // Check if it's IPv4-mapped IPv6 (::ffff:192.168.1.1)
            if (!/^[0-9a-fA-F:.]+$/.test(cleanIP)) return false;
        }
        
        // Split by colons
        const parts = cleanIP.split(':');
        
        // IPv6 should have at most 8 parts (before compression)
        if (parts.length > 8) return false;
        
        // Check for double colon (compression)
        const doubleColonCount = (cleanIP.match(/::/g) || []).length;
        if (doubleColonCount > 1) return false;
        
        // If there's a double colon, we can have fewer parts
        if (doubleColonCount === 1) {
            // Special cases
            if (cleanIP === '::') return true;
            if (cleanIP.startsWith('::') || cleanIP.endsWith('::')) {
                return parts.length <= 8;
            }
            return parts.length <= 8;
        }
        
        // Without compression, should have exactly 8 parts
        if (doubleColonCount === 0 && parts.length !== 8) return false;
        
        // Check each part
        for (const part of parts) {
            if (part === '') continue; // Empty parts are OK due to ::
            
            // Check for IPv4 in IPv6 (last part might be IPv4)
            if (part.includes('.')) {
                return isValidIPv4(part);
            }
            
            // Regular IPv6 part should be 1-4 hex digits
            if (!/^[0-9a-fA-F]{1,4}$/.test(part)) return false;
        }
        
        return true;
    }

    function isValidDomain(domain) {
        if (!domain || domain.length < 4 || domain.length > 253) return false;
        if (domain.startsWith('.') || domain.endsWith('.')) return false;
        if (domain.includes('..')) return false;
        
        // Must contain at least one dot
        if (!domain.includes('.')) return false;
        
        // Check for valid characters (only letters, numbers, dots, hyphens)
        if (!/^[a-z0-9.-]+$/i.test(domain)) return false;
        
        // Split into parts
        const parts = domain.toLowerCase().split('.');
        
        // Must have at least 2 parts
        if (parts.length < 2) return false;
        
        // Check if TLD is valid
        const tld = parts[parts.length - 1];
        const secondLevelTld = parts.length > 2 ? parts[parts.length - 2] + '.' + tld : null;
        
        // Check against known TLDs (including multi-part TLDs)
        const multiPartTLDs = ['co.uk', 'com.au', 'co.jp', 'co.kr', 'com.br', 'co.za', 'co.in'];
        const hasValidTld = VALID_TLDS.includes(tld) || 
                           (secondLevelTld && multiPartTLDs.includes(secondLevelTld));
        
        if (!hasValidTld) return false;
        
        // Reject if it looks like a number/coordinate (e.g., "35.66758135")
        if (/^\d+\.\d+$/.test(domain)) return false;
        
        // Reject if all parts before TLD are numeric
        const domainParts = secondLevelTld ? parts.slice(0, -2) : parts.slice(0, -1);
        if (domainParts.length > 0 && domainParts.every(part => /^\d+$/.test(part))) return false;
        
        // Reject single character domains before TLD (e.g., "a.com" is unlikely in content)
        const mainDomain = secondLevelTld ? parts[parts.length - 3] : parts[parts.length - 2];
        if (!mainDomain || mainDomain.length < 2) return false;
        
        // Reject if it looks like an email username (common pattern: firstname.lastname)
        if (parts.length === 2 && /^[a-z]+\.[a-z]+$/.test(domain) && domain.length < 15) {
            // Allow known tech domains that might match this pattern
            const knownDomains = ['bit.ly', 'get.app', 'dev.to', 'is.gd', 'me.com'];
            if (!knownDomains.includes(domain)) return false;
        }
        
        // Reject domains that are too short and look suspicious
        if (domain.length < 6 && !['io', 'ai', 'co'].includes(tld)) return false;
        
        return true;
    }

    // Auto-extract data when page loads or script is injected
    function performAutoExtraction() {
        try {
            const data = extractNetworkEntities();
            
            // Enhanced logging for debugging
            const totalIPs = data.ips.length;
            const totalDomains = data.domains.length;
            console.log(`🎯 CyberScan extraction complete: ${totalIPs} IPs, ${totalDomains} domains from ${window.location.href}`);
            
            if (totalIPs > 0) {
                console.log('📍 IPs found:', data.ips);
            }
            if (totalDomains > 0) {
                console.log('🌐 Domains found:', data.domains);
            }
            
            chrome.runtime.sendMessage({
                action: 'networkDataExtracted',
                data: data
            }).catch(error => {
                console.log('Could not send to background script:', error);
            });
        } catch (error) {
            console.error('❌ Error during auto-extraction:', error);
        }
    }

    // Execute immediately if DOM is ready, otherwise wait
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            // Multiple extractions with increasing delays for dynamic content
            setTimeout(performAutoExtraction, 500);   // Initial quick extraction
            setTimeout(performAutoExtraction, 2000);  // Wait for dynamic content (VirusTotal, etc.)
            setTimeout(performAutoExtraction, 5000);  // Final extraction for slow sites
        });
    } else {
        // DOM is already ready, extract with multiple timing
        setTimeout(performAutoExtraction, 100);   // Immediate
        setTimeout(performAutoExtraction, 1500);  // After dynamic content
        setTimeout(performAutoExtraction, 4000);  // Final pass
    }

    // Also listen for page changes (for SPAs)
    let lastUrl = location.href;
    const observer = new MutationObserver(() => {
        const url = location.href;
        if (url !== lastUrl) {
            lastUrl = url;
            console.log('🔄 SPA navigation detected, re-extracting...');
            setTimeout(performAutoExtraction, 1000);  // Quick extraction after navigation
            setTimeout(performAutoExtraction, 3000);  // Follow-up for dynamic content
        }
    });
    
    observer.observe(document, { 
        subtree: true, 
        childList: true,
        attributes: true,
        attributeFilter: ['data-ip', 'data-domain', 'data-url', 'data-host']
    });

    // Listen for messages from popup/background for manual extraction
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.action === 'extractNetworkData') {
            try {
                const data = extractNetworkEntities();
                sendResponse({ success: true, data: data });
            } catch (error) {
                console.error('Error extracting network data:', error);
                sendResponse({ success: false, error: error.message });
            }
        }
        return true;
    });

})();
