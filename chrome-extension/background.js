// Background service worker for API calls and data processing
let VIRUSTOTAL_API_KEY = '';
let ABUSEIPDB_API_KEY = '';
let ANTHROPIC_API_KEY = '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';

// Store scan results
let lastScanData = null;

// Domain validation regex
const DOMAIN_REGEX = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i;

// Load API keys from storage on startup
async function loadApiKeys() {
    try {
        console.log('🔄 Loading API keys from storage...');
        console.log('🔍 Current ANTHROPIC_API_KEY before loading:', ANTHROPIC_API_KEY ? ANTHROPIC_API_KEY.substring(0, 15) + '...' : 'N/A');
        
        const result = await chrome.storage.local.get(['apiKeys']);
        console.log('📦 Storage result:', result);
        
        const apiKeys = result.apiKeys || {};
        console.log('🔑 API keys from storage:', {
            virustotal: apiKeys.virustotal ? 'present' : 'empty',
            abuseipdb: apiKeys.abuseipdb ? 'present' : 'empty',
            anthropic: apiKeys.anthropic ? 'present' : 'empty'
        });
        
        VIRUSTOTAL_API_KEY = apiKeys.virustotal || '';
        ABUSEIPDB_API_KEY = apiKeys.abuseipdb || '';
        ANTHROPIC_API_KEY = apiKeys.anthropic || '';
        
        console.log('🔍 ANTHROPIC_API_KEY after loading:', ANTHROPIC_API_KEY ? ANTHROPIC_API_KEY.substring(0, 15) + '...' : 'N/A');
        console.log('✅ API keys loaded from storage');
    } catch (error) {
        console.error('❌ Error loading API keys:', error);
    }
}

// Initialize API keys on startup
loadApiKeys();

// Listen for messages from content script and popup
chrome.runtime.onMessage.addListener((request, _sender, sendResponse) => {
    console.log('Background received message:', request.action);
    
    if (request.action === 'networkDataExtracted') {
        handleNetworkDataExtracted(request.data);
    } else if (request.action === 'analyzeNetworkData') {
        analyzeNetworkData(request.data)
            .then(result => sendResponse({ success: true, data: result }))
            .catch(error => sendResponse({ success: false, error: error.message }));
        return true; // Keep message channel open
    } else if (request.action === 'getLastScanData') {
        sendResponse({ success: true, data: lastScanData });
    } else if (request.action === 'checkApiStatus') {
        checkApiStatus()
            .then(status => sendResponse({ success: true, status: status }))
            .catch(error => sendResponse({ success: false, error: error.message }));
        return true;
    } else if (request.action === 'updateApiKeys') {
        updateApiKeys(request.keys);
        sendResponse({ success: true });
    } else if (request.action === 'startAIAnalysis') {
        startAIAnalysis(request.data)
            .then(result => sendResponse({ success: true, data: result }))
            .catch(error => sendResponse({ success: false, error: error.message }));
        return true; // Keep message channel open
    }
});

async function handleNetworkDataExtracted(data) {
    console.log('Network data extracted:', data);
    
    try {
        const analysisResult = await analyzeNetworkData(data);
        lastScanData = {
            ...data,
            analysis: analysisResult,
            scanTime: Date.now()
        };
        
        // Notify popup if it's open
        try {
            await chrome.runtime.sendMessage({
                action: 'scanComplete',
                data: lastScanData
            });
        } catch (e) {
            // Popup might not be open, that's fine
        }
    } catch (error) {
        console.error('Error analyzing network data:', error);
    }
}

async function analyzeNetworkData(data) {
    const { ips, domains, pageContent } = data;
    
    // Remove duplicates and filter out invalid domains
    const uniqueIPs = [...new Set(ips)].filter(ip => ip && ip.trim());
    const uniqueDomains = [...new Set(domains)].filter(domain => domain && DOMAIN_REGEX.test(domain));
    
    console.log(`Analyzing ${uniqueIPs.length} unique IPs and ${uniqueDomains.length} unique root domains`);
    
    try {
        // Analyze IPs (parallel processing in batches to avoid rate limiting)
        const ipAnalysis = await Promise.all(
            uniqueIPs.map(ip => analyzeIP(ip))
        );
        
        // Analyze domains (parallel processing in batches to avoid rate limiting)
        const domainAnalysis = await Promise.all(
            uniqueDomains.map(domain => analyzeDomain(domain))
        );

        // AI analysis is now manual - don't run automatically
        
        return {
            ips: ipAnalysis,
            domains: domainAnalysis,
            aiAnalysis: null, // Will be populated when user clicks "Start AI Analysis"
            summary: generateSummary(ipAnalysis, domainAnalysis)
        };
    } catch (error) {
        console.error('Error in analyzeNetworkData:', error);
        throw error;
    }
}

async function analyzeIP(ip) {
    console.log(`Analyzing IP: ${ip}`);
    
    try {
        // Determine if IPv6 and encode accordingly
        const isIPv6 = ip.includes(':');
        const encodedIP = isIPv6 ? encodeURIComponent(ip) : ip;
        
        // VirusTotal API v3 call
        const vtResponse = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${encodedIP}`, {
            method: 'GET',
            headers: {
                'x-apikey': VIRUSTOTAL_API_KEY,
                'Accept': 'application/json'
            }
        });
        
        // AbuseIPDB API call (supports both IPv4 and IPv6)
        const abuseResponse = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}`, {
            method: 'GET',
            headers: {
                'Key': ABUSEIPDB_API_KEY,
                'Accept': 'application/json'
            }
        });
        
        const vtData = await vtResponse.json();
        const abuseData = await abuseResponse.json();
        
        // Extract data from VirusTotal v3 response
        const stats = vtData.data?.attributes?.last_analysis_stats || {};
        const detections = (stats.malicious || 0) + (stats.suspicious || 0);
        const totalEngines = Object.values(stats).reduce((sum, count) => sum + count, 0);
        
        // Extract country information from AbuseIPDB (preferred) or fallback to VirusTotal
        const abuseCountryCode = abuseData.data?.countryCode;
        const abuseCountryName = abuseData.data?.countryName;
        const vtCountry = vtData.data?.attributes?.country;
        
        // Use AbuseIPDB country data if available, otherwise fallback to VirusTotal
        const countryInfo = abuseCountryName || abuseCountryCode || vtCountry || 'Unknown';
        
        return {
            ip,
            ip_type: isIPv6 ? 'IPv6' : 'IPv4',
            detections: detections,
            total_engines: totalEngines,
            location: countryInfo,
            whois_country: countryInfo, // Using AbuseIPDB country data
            asn: vtData.data?.attributes?.asn || 'Unknown',
            isp: vtData.data?.attributes?.as_owner || 'Unknown',
            categories: Object.keys(vtData.data?.attributes?.last_analysis_results || {}).filter(engine => 
                ['malicious', 'suspicious'].includes(vtData.data.attributes.last_analysis_results[engine]?.category)
            ),
            abuse_confidence: abuseData.data?.abuseConfidenceScore || 0,
            threat_level: calculateThreatLevel(detections, totalEngines, abuseData.data?.abuseConfidenceScore || 0),
            timestamp: Date.now()
        };
    } catch (error) {
        console.error(`Error analyzing IP ${ip}:`, error);
        return {
            ip,
            ip_type: ip.includes(':') ? 'IPv6' : 'IPv4',
            error: error.message,
            detections: 0,
            total_engines: 0,
            threat_level: 'unknown',
            timestamp: Date.now()
        };
    }
}

async function analyzeDomain(domain) {
    console.log(`Analyzing domain: ${domain}`);
    
    try {
        // VirusTotal API v3 call
        const response = await fetch(`https://www.virustotal.com/api/v3/domains/${domain}`, {
            method: 'GET',
            headers: {
                'x-apikey': VIRUSTOTAL_API_KEY,
                'Accept': 'application/json'
            }
        });
        
        if (!response.ok) {
            throw new Error(`VirusTotal API error: ${response.status}`);
        }

        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            throw new Error('Invalid response format from VirusTotal API');
        }
        
        const data = await response.json();
        
        // Extract data from VirusTotal v3 response
        const stats = data.data?.attributes?.last_analysis_stats || {};
        const detections = (stats.malicious || 0) + (stats.suspicious || 0);
        const totalEngines = Object.values(stats).reduce((sum, count) => sum + count, 0);
        
        // Extract whois country information - need to parse from whois text
        const whoisData = data.data?.attributes?.whois || '';
        const whoisCountry = extractCountryFromWhois(whoisData);
        
        return {
            domain,
            detections: detections,
            total_engines: totalEngines,
            whois_country: whoisCountry, // Country from whois data
            categories: Object.keys(data.data?.attributes?.last_analysis_results || {}).filter(engine => 
                ['malicious', 'suspicious'].includes(data.data.attributes.last_analysis_results[engine]?.category)
            ),
            registrar: data.data?.attributes?.registrar || 'Unknown',
            creation_date: data.data?.attributes?.creation_date ? 
                new Date(data.data.attributes.creation_date * 1000).toLocaleDateString() : 'Unknown',
            reputation: data.data?.attributes?.reputation || 'Unknown',
            threat_level: calculateDomainThreatLevel(detections, totalEngines),
            timestamp: Date.now()
        };
    } catch (error) {
        console.error(`Error analyzing domain ${domain}:`, error);
        return {
            domain,
            error: error.message,
            detections: 0,
            total_engines: 0,
            threat_level: 'unknown',
            timestamp: Date.now()
        };
    }
}

function extractCountryFromWhois(whoisText) {
    if (!whoisText || typeof whoisText !== 'string') {
        return 'Unknown';
    }
    
    // Common patterns to extract country from whois data
    const patterns = [
        /Country:\s*([A-Z]{2})/i,           // "Country: US"
        /country:\s*([A-Z]{2})/i,           // "country: us" 
        /^Country:\s*(.+)$/im,              // "Country: United States"
        /Registrant Country:\s*([A-Z]{2})/i, // "Registrant Country: US"
        /Admin Country:\s*([A-Z]{2})/i,     // "Admin Country: US"
        /Tech Country:\s*([A-Z]{2})/i,      // "Tech Country: US"
        /\bC:\s*([A-Z]{2})\b/i,            // "C: US" (common abbreviation)
        /Country Code:\s*([A-Z]{2})/i       // "Country Code: US"
    ];
    
    for (const pattern of patterns) {
        const match = whoisText.match(pattern);
        if (match && match[1]) {
            const country = match[1].trim().toUpperCase();
            // Return 2-letter country codes or convert common long names
            if (country.length === 2) {
                return country;
            }
            // Convert some common country names to codes
            const countryMap = {
                'UNITED STATES': 'US',
                'CANADA': 'CA',
                'UNITED KINGDOM': 'GB',
                'GERMANY': 'DE',
                'FRANCE': 'FR',
                'JAPAN': 'JP',
                'CHINA': 'CN',
                'RUSSIA': 'RU'
            };
            return countryMap[country] || country;
        }
    }
    
    return 'Unknown';
}

function calculateThreatLevel(detections, totalEngines, abuseScore) {
    // VirusTotal threat assessment
    let vtThreat = 'safe';
    if (detections >= 2) {
        vtThreat = 'malicious';
    } else if (detections >= 1) {
        vtThreat = 'suspicious';
    }
    
    // AbuseIPDB threat assessment
    let abuseThreat = 'safe';
    if (abuseScore > 5) {
        abuseThreat = 'malicious';
    } else if (abuseScore > 0) {
        abuseThreat = 'suspicious';
    }
    
    // Return the highest threat level between the two sources
    if (vtThreat === 'malicious' || abuseThreat === 'malicious') {
        return 'malicious';
    }
    if (vtThreat === 'suspicious' || abuseThreat === 'suspicious') {
        return 'suspicious';
    }
    return 'safe';
}

function calculateDomainThreatLevel(detections, totalEngines) {
    // For domains, only use VirusTotal data
    if (detections >= 2) {
        return 'malicious';
    } else if (detections >= 1) {
        return 'suspicious';
    }
    return 'safe';
}

function generateSummary(ipAnalysis, domainAnalysis) {
    const safeIPs = ipAnalysis.filter(ip => ip.threat_level === 'safe').length;
    const suspiciousIPs = ipAnalysis.filter(ip => ip.threat_level === 'suspicious').length;
    const maliciousIPs = ipAnalysis.filter(ip => ip.threat_level === 'malicious').length;
    
    const safeDomains = domainAnalysis.filter(domain => domain.threat_level === 'safe').length;
    const suspiciousDomains = domainAnalysis.filter(domain => domain.threat_level === 'suspicious').length;
    const maliciousDomains = domainAnalysis.filter(domain => domain.threat_level === 'malicious').length;
    
    return {
        ips: {
            total: ipAnalysis.length,
            safe: safeIPs,
            suspicious: suspiciousIPs,
            malicious: maliciousIPs
        },
        domains: {
            total: domainAnalysis.length,
            safe: safeDomains,
            suspicious: suspiciousDomains,
            malicious: maliciousDomains
        },
        overallThreat: maliciousIPs > 0 || maliciousDomains > 0 ? 'high' : 
                      suspiciousIPs > 0 || suspiciousDomains > 0 ? 'medium' : 'low'
    };
}

// New function to handle manual AI analysis requests
async function startAIAnalysis(scanData) {
    console.log('🚀 Starting manual AI analysis...');
    
    if (!scanData || !scanData.analysis) {
        throw new Error('No scan data available for AI analysis');
    }
    
    const { pageContent, analysis } = scanData;
    const { ips, domains } = analysis;
    
    const aiAnalysis = await generateAIAnalysis(pageContent, ips, domains, scanData);
    
    // Update the stored scan data with AI analysis
    if (lastScanData) {
        lastScanData.analysis.aiAnalysis = aiAnalysis;
    }
    
    return aiAnalysis;
}

async function generateAIAnalysis(pageContent, ipAnalysis, domainAnalysis, originalData) {
    console.log('🔍 Starting AI Analysis...');
    console.log('📊 API Key present:', !!ANTHROPIC_API_KEY);
    console.log('📏 API Key length:', ANTHROPIC_API_KEY ? ANTHROPIC_API_KEY.length : 0);
    console.log('🔑 API Key starts with:', ANTHROPIC_API_KEY ? ANTHROPIC_API_KEY.substring(0, 15) + '...' : 'N/A');
    console.log('🔑 API Key ends with:', ANTHROPIC_API_KEY ? '...' + ANTHROPIC_API_KEY.substring(ANTHROPIC_API_KEY.length - 10) : 'N/A');
    console.log('🔍 API Key format check:', ANTHROPIC_API_KEY ? (ANTHROPIC_API_KEY.startsWith('sk-ant-') ? '✅ Correct format' : '❌ Wrong format') : 'N/A');
    
    // Debug the condition check
    console.log('🧪 Condition Debug:');
    console.log('   !ANTHROPIC_API_KEY:', !ANTHROPIC_API_KEY);
    console.log('   ANTHROPIC_API_KEY === "your-anthropic-api-key-here":', ANTHROPIC_API_KEY === 'your-anthropic-api-key-here');
    console.log('   ANTHROPIC_API_KEY.trim() === "":', ANTHROPIC_API_KEY ? ANTHROPIC_API_KEY.trim() === '' : 'N/A');
    console.log('   Overall condition result:', (!ANTHROPIC_API_KEY || ANTHROPIC_API_KEY === 'your-anthropic-api-key-here' || ANTHROPIC_API_KEY.trim() === ''));
    
    if (!ANTHROPIC_API_KEY || ANTHROPIC_API_KEY === 'your-anthropic-api-key-here' || ANTHROPIC_API_KEY.trim() === '') {
        console.error('❌ No valid API key found');
        return {
            error: 'Anthropic API key not configured',
            summary: 'AI analysis unavailable - please configure Anthropic API key in Settings'
        };
    }

    try {
        const prompt = buildAnalysisPrompt(pageContent, ipAnalysis, domainAnalysis, originalData);
        console.log('📝 Generated prompt length:', prompt.length);
        
        const requestPayload = {
            model: 'claude-3-5-sonnet-20241022',
            max_tokens: 1500,
            temperature: 0.3,
            system: 'You are a cybersecurity analyst AI assistant. Analyze the provided webpage content and threat intelligence data to provide security insights and recommendations for security analysts investigating potential threats.',
            messages: [
                {
                    role: 'user',
                    content: prompt
                }
            ]
        };
        
        console.log('🚀 Making API request to Anthropic...');
        console.log('📦 Request payload structure:', {
            model: requestPayload.model,
            max_tokens: requestPayload.max_tokens,
            temperature: requestPayload.temperature,
            system_prompt_length: requestPayload.system.length,
            messageCount: requestPayload.messages.length,
            user_message_length: prompt.length
        });
        console.log('🤖 System Prompt:', requestPayload.system);
        console.log('💬 User Message (Already logged above as "COMPLETE PROMPT")');
        console.log('📡 Full Request Payload (without content to avoid duplication):');
        console.log({
            ...requestPayload,
            messages: requestPayload.messages.map(msg => ({
                role: msg.role,
                content_length: msg.content.length,
                content_preview: msg.content.substring(0, 100) + '...'
            }))
        });
        
        const response = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': ANTHROPIC_API_KEY,
                'anthropic-version': '2023-06-01',
                'anthropic-dangerous-direct-browser-access': 'true'
            },
            body: JSON.stringify(requestPayload)
        });

        console.log('📡 Response status:', response.status);
        console.log('📋 Response headers:', Object.fromEntries(response.headers.entries()));

        if (!response.ok) {
            let errorData = null;
            try {
                errorData = await response.json();
                console.error('❌ API Error Response:', errorData);
                
                // Log specific error details from Anthropic
                if (errorData?.error) {
                    console.error('🔍 Anthropic Error Details:');
                    console.error('   Type:', errorData.error.type);
                    console.error('   Message:', errorData.error.message);
                    if (errorData.error.details) {
                        console.error('   Details:', errorData.error.details);
                    }
                }
            } catch (e) {
                console.error('❌ Could not parse error response as JSON');
                // Try to get raw response text
                try {
                    const rawText = await response.text();
                    console.error('📄 Raw error response:', rawText);
                } catch (textError) {
                    console.error('❌ Could not get response text either');
                }
            }
            
            let errorMessage = `Anthropic API error: ${response.status}`;
            
            if (response.status === 401) {
                errorMessage = 'Invalid Anthropic API key. Please check your API key in Settings.';
                console.error('🔑 401 Error - Check API key validity and permissions');
            } else if (response.status === 429) {
                errorMessage = 'Anthropic API rate limit exceeded. Please try again later.';
                console.error('⏱️ 429 Error - Rate limit exceeded');
            } else if (response.status === 403) {
                errorMessage = 'Anthropic API access denied. Please check your API key permissions.';
                console.error('🚫 403 Error - Access denied');
            } else if (response.status === 400) {
                const badRequestMsg = errorData?.error?.message || 'Bad request';
                errorMessage = `Bad request: ${badRequestMsg}`;
                console.error('📝 400 Error - Bad request:', badRequestMsg);
            } else if (errorData?.error?.message) {
                errorMessage = `Anthropic API error: ${errorData.error.message}`;
                console.error('🔍 API Error Details:', errorData.error);
            }
            
            throw new Error(errorMessage);
        }

        const data = await response.json();
        console.log('✅ Successful API response received');
        console.log('📊 Response structure:', {
            hasContent: !!data.content,
            contentLength: data.content ? data.content.length : 0,
            firstContentType: data.content && data.content[0] ? data.content[0].type : 'N/A'
        });
        
        if (!data.content || !data.content[0] || !data.content[0].text) {
            console.error('❌ Invalid response format:', data);
            throw new Error('Invalid response format from Anthropic API');
        }
        
        const analysisText = data.content[0].text;
        console.log('📄 Analysis text length:', analysisText.length);

        // Parse the AI response into structured format
        const parsedResult = parseAIResponse(analysisText);
        console.log('✅ AI Analysis completed successfully');
        return parsedResult;

    } catch (error) {
        console.error('💥 AI Analysis failed:', error);
        console.error('📚 Error stack:', error.stack);
        return {
            error: error.message,
            summary: 'AI analysis failed due to API error'
        };
    }
}

// Data deidentification functions for privacy protection
function createDeidentificationMap() {
    return {
        emails: new Map(),
        userids: new Map(),
        phones: new Map(),
        identifiers: new Map(),
        counter: 0
    };
}

function generateRandomReplacement(type, counter) {
    const generators = {
        email: () => `user${counter}@example.com`,
        userid: () => `user${counter}`,
        phone: () => `555-0${String(counter).padStart(3, '0')}`,
        identifier: () => `ID${counter}`
    };
    return generators[type] ? generators[type]() : `${type}${counter}`;
}

function deidentifyEmails(text, deidentMap) {
    // Enhanced email regex to catch various email formats
    const emailRegex = /\b[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?@[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}\b/g;
    
    return text.replace(emailRegex, (match) => {
        if (!deidentMap.emails.has(match)) {
            deidentMap.counter++;
            deidentMap.emails.set(match, generateRandomReplacement('email', deidentMap.counter));
        }
        return deidentMap.emails.get(match);
    });
}

function deidentifyUserids(text, deidentMap) {
    // Common userid patterns
    const useridPatterns = [
        // @username patterns (social media, mentions)
        /@([a-zA-Z0-9_]{3,20})\b/g,
        // user= or username= patterns
        /(?:user|username|userid|login)[\s]*[=:]\s*([a-zA-Z0-9_.-]{3,30})/gi,
        // User: username patterns
        /User:\s*([a-zA-Z0-9_.-]{3,30})/gi
    ];
    
    let result = text;
    
    useridPatterns.forEach(pattern => {
        result = result.replace(pattern, (match, userid) => {
            if (!deidentMap.userids.has(userid)) {
                deidentMap.counter++;
                deidentMap.userids.set(userid, generateRandomReplacement('userid', deidentMap.counter));
            }
            return match.replace(userid, deidentMap.userids.get(userid));
        });
    });
    
    return result;
}

function deidentifyPhoneNumbers(text, deidentMap) {
    // Various phone number formats
    const phonePatterns = [
        /\b\d{3}-\d{3}-\d{4}\b/g,           // 123-456-7890
        /\b\(\d{3}\)\s*\d{3}-\d{4}\b/g,     // (123) 456-7890
        /\b\d{3}\s\d{3}\s\d{4}\b/g,         // 123 456 7890
        /\b\+1[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b/g, // +1-123-456-7890
    ];
    
    let result = text;
    
    phonePatterns.forEach(pattern => {
        result = result.replace(pattern, (match) => {
            if (!deidentMap.phones.has(match)) {
                deidentMap.counter++;
                deidentMap.phones.set(match, generateRandomReplacement('phone', deidentMap.counter));
            }
            return deidentMap.phones.get(match);
        });
    });
    
    return result;
}

function deidentifyIdentifiers(text, deidentMap) {
    // Common identifier patterns
    const identifierPatterns = [
        // SSN patterns (XXX-XX-XXXX)
        /\b\d{3}-\d{2}-\d{4}\b/g,
        // Credit card patterns (basic detection)
        /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g,
        // ID numbers (ID followed by numbers)
        /\b(?:ID|id)[\s:#-]*(\d{4,})\b/g,
        // Account numbers
        /\b(?:account|acct)[\s:#-]*(\d{4,})\b/gi
    ];
    
    let result = text;
    
    identifierPatterns.forEach(pattern => {
        result = result.replace(pattern, (match) => {
            if (!deidentMap.identifiers.has(match)) {
                deidentMap.counter++;
                deidentMap.identifiers.set(match, generateRandomReplacement('identifier', deidentMap.counter));
            }
            return deidentMap.identifiers.get(match);
        });
    });
    
    return result;
}

function deidentifyContent(content) {
    if (!content || typeof content !== 'string') {
        return content;
    }
    
    const deidentMap = createDeidentificationMap();
    let sanitized = content;
    
    // Apply all deidentification functions in sequence
    sanitized = deidentifyEmails(sanitized, deidentMap);
    sanitized = deidentifyUserids(sanitized, deidentMap);
    sanitized = deidentifyPhoneNumbers(sanitized, deidentMap);
    sanitized = deidentifyIdentifiers(sanitized, deidentMap);
    
    console.log(`🔒 Deidentified ${deidentMap.counter} PII items from content`);
    
    return sanitized;
}

function deidentifyStructuredContent(structured) {
    if (!structured) return structured;
    
    const deidentified = { ...structured };
    
    // Deidentify title
    if (deidentified.title) {
        deidentified.title = deidentifyContent(deidentified.title);
    }
    
    // Deidentify headings
    if (deidentified.headings && Array.isArray(deidentified.headings)) {
        deidentified.headings = deidentified.headings.map(heading => ({
            ...heading,
            text: deidentifyContent(heading.text)
        }));
    }
    
    // Deidentify alerts
    if (deidentified.alerts && Array.isArray(deidentified.alerts)) {
        deidentified.alerts = deidentified.alerts.map(alert => deidentifyContent(alert));
    }
    
    return deidentified;
}

function buildAnalysisPrompt(pageContent, ipAnalysis, domainAnalysis, originalData) {
    const threatIPs = ipAnalysis.filter(ip => ip.threat_level === 'malicious' || ip.threat_level === 'suspicious');
    const threatDomains = domainAnalysis.filter(domain => domain.threat_level === 'malicious' || domain.threat_level === 'suspicious');

    // Debug logging: Show original content before deidentification
    console.log('📋 ===== ORIGINAL CONTENT (Before PII Removal) =====');
    console.log('🌐 URL:', originalData.currentUrl);
    console.log('📄 Page Title (Original):', pageContent.structured?.title || 'N/A');
    console.log('📝 Full Text Length:', pageContent.fullText?.length || 0);
    console.log('📝 Full Text Sample (First 500 chars):', pageContent.fullText?.substring(0, 500) || 'N/A');
    console.log('🏷️ Headings (Original):', pageContent.structured?.headings?.map(h => `${h.level}: ${h.text}`).join(', ') || 'None');
    console.log('⚠️ Alerts (Original):', pageContent.structured?.alerts || 'None');
    console.log('🔗 Links Count:', pageContent.structured?.links?.length || 0);

    // Deidentify sensitive content before sending to LLM
    console.log('🔒 Applying data deidentification for AI analysis...');
    const deidentifiedStructured = deidentifyStructuredContent(pageContent.structured);
    const deidentifiedFullText = deidentifyContent(pageContent.fullText);

    // Debug logging: Show content after deidentification
    console.log('🔒 ===== CONTENT AFTER PII REMOVAL =====');
    console.log('📄 Page Title (Deidentified):', deidentifiedStructured?.title || 'N/A');
    console.log('📝 Deidentified Text Length:', deidentifiedFullText?.length || 0);
    console.log('📝 Deidentified Text Sample (First 500 chars):', deidentifiedFullText?.substring(0, 500) || 'N/A');
    console.log('🏷️ Headings (Deidentified):', deidentifiedStructured?.headings?.map(h => `${h.level}: ${h.text}`).join(', ') || 'None');
    console.log('⚠️ Alerts (Deidentified):', deidentifiedStructured?.alerts || 'None');

    const prompt = `
# Security Analysis Request

## Webpage Information
- **Title**: ${deidentifiedStructured.title}

## Page Content Analysis
${deidentifiedStructured.headings && deidentifiedStructured.headings.length > 0 ? `
### Headings Found:
${deidentifiedStructured.headings.map(h => `- ${h.level.toUpperCase()}: ${h.text}`).join('\n')}
` : ''}

${deidentifiedStructured.alerts && deidentifiedStructured.alerts.length > 0 ? `
### Alert/Warning Content:
${deidentifiedStructured.alerts.map(alert => `- ${alert}`).join('\n')}
` : ''}

### Key Content Summary:
${deidentifiedFullText.substring(0, 1000)}${deidentifiedFullText.length > 1000 ? '...' : ''}

## Threat Intelligence Data

### IP Addresses Found (${ipAnalysis.length} total):
${ipAnalysis.map(ip => `
- **${ip.ip}**: ${ip.threat_level}
  - VirusTotal: ${ip.detections}/${ip.total_engines} detections
  - AbuseIPDB: ${ip.abuse_confidence}% abuse confidence
  - Location: ${ip.location}
`).join('')}

### Domains Found (${domainAnalysis.length} total):
${domainAnalysis.map(domain => `
- **${domain.domain}**: ${domain.threat_level}
  - Detections: ${domain.detections}/${domain.total_engines}
`).join('')}

## Analysis Request
As a cybersecurity analyst, please provide:

1. **Risk Assessment**: Overall risk level (LOW/MEDIUM/HIGH) and summary
2. **Key Findings**: Specific security concerns found
3. **Threat Context**: What type of security incident this might be
4. **Recommendations**: Specific next steps for the security analyst

Format your response as JSON:
{
  "risk_level": "low|medium|high",
  "summary": "Brief risk assessment summary",
  "findings": [
    {
      "title": "Finding title",
      "description": "Detailed description",
      "severity": "low|medium|high"
    }
  ],
  "threat_context": "Description of potential threat type",
  "recommendations": [
    "Specific action item 1",
    "Specific action item 2"
  ],
  "confidence": 85,
  "processing_time": "2.3s"
}
`;

    // Debug logging: Show complete prompt being sent to LLM
    console.log('🚀 ===== COMPLETE PROMPT SENT TO CLAUDE =====');
    console.log('📊 Prompt Length:', prompt.length);
    console.log('📋 Complete Prompt:');
    console.log(prompt);
    console.log('🚀 ===== END OF PROMPT =====');

    return prompt;
}

function parseAIResponse(responseText) {
    try {
        // Try to extract JSON from the response
        const jsonMatch = responseText.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
            const parsed = JSON.parse(jsonMatch[0]);
            return {
                risk_level: parsed.risk_level,
                summary: parsed.summary,
                findings: parsed.findings || [],
                threat_context: parsed.threat_context,
                recommendations: parsed.recommendations || [],
                confidence: parsed.confidence || 75,
                processing_time: parsed.processing_time || 'N/A'
            };
        }
    } catch (error) {
        console.error('Error parsing AI response:', error);
    }

    // Fallback to text-based parsing if JSON fails
    return {
        risk_level: 'medium',
        summary: responseText.substring(0, 200) + (responseText.length > 200 ? '...' : ''),
        findings: [],
        threat_context: 'Unable to parse detailed analysis',
        recommendations: ['Review the content manually', 'Check threat intelligence sources'],
        confidence: 50,
        processing_time: 'N/A'
    };
}

async function checkApiStatus() {
    const status = {
        virustotal: false,
        abuseipdb: false,
        anthropic: false
    };

    // Check VirusTotal - only if API key is provided
    if (VIRUSTOTAL_API_KEY && VIRUSTOTAL_API_KEY.trim() !== '') {
        try {
            const vtResponse = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8`, {
                method: 'GET',
                headers: {
                    'x-apikey': VIRUSTOTAL_API_KEY,
                    'Accept': 'application/json'
                }
            });
            status.virustotal = vtResponse.ok;
        } catch (error) {
            console.error('VirusTotal API check failed:', error);
        }
    }

    // Check AbuseIPDB - only if API key is provided
    if (ABUSEIPDB_API_KEY && ABUSEIPDB_API_KEY.trim() !== '') {
        try {
            const abuseResponse = await fetch('https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8', {
                method: 'GET',
                headers: {
                    'Key': ABUSEIPDB_API_KEY,
                    'Accept': 'application/json'
                }
            });
            status.abuseipdb = abuseResponse.ok;
        } catch (error) {
            console.error('AbuseIPDB API check failed:', error);
        }
    }

    // Check Anthropic - test with a simple API call
    if (ANTHROPIC_API_KEY && ANTHROPIC_API_KEY.trim() !== '' && !ANTHROPIC_API_KEY.includes('your-anthropic-api-key-here')) {
        try {
            console.log('🧪 Testing Anthropic API key...');
            const testResponse = await fetch('https://api.anthropic.com/v1/messages', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-api-key': ANTHROPIC_API_KEY,
                    'anthropic-version': '2023-06-01',
                    'anthropic-dangerous-direct-browser-access': 'true'
                },
                body: JSON.stringify({
                    model: 'claude-3-5-sonnet-20241022',
                    max_tokens: 10,
                    messages: [
                        {
                            role: 'user',
                            content: 'Hello'
                        }
                    ]
                })
            });
            
            console.log('🧪 Anthropic test response status:', testResponse.status);
            
            if (testResponse.status === 401) {
                console.error('🔑 Anthropic API key is invalid (401)');
                status.anthropic = false;
            } else if (testResponse.status === 403) {
                console.error('🚫 Anthropic API key lacks permissions (403)');
                status.anthropic = false;
            } else if (testResponse.ok) {
                console.log('✅ Anthropic API key is valid');
                status.anthropic = true;
            } else {
                console.warn('⚠️ Anthropic API returned unexpected status:', testResponse.status);
                status.anthropic = false;
            }
        } catch (error) {
            console.error('💥 Anthropic API test failed:', error);
            status.anthropic = false;
        }
    } else {
        status.anthropic = false;
    }

    return status;
}

// Update API keys from settings
function updateApiKeys(keys) {
    console.log('🔄 Updating API keys from settings...');
    console.log('🔍 Received keys:', {
        virustotal: keys.virustotal ? 'present' : 'empty',
        abuseipdb: keys.abuseipdb ? 'present' : 'empty',
        anthropic: keys.anthropic ? 'present' : 'empty'
    });
    console.log('🔍 Current ANTHROPIC_API_KEY before update:', ANTHROPIC_API_KEY ? ANTHROPIC_API_KEY.substring(0, 15) + '...' : 'N/A');
    
    VIRUSTOTAL_API_KEY = keys.virustotal || '';
    ABUSEIPDB_API_KEY = keys.abuseipdb || '';
    ANTHROPIC_API_KEY = keys.anthropic || '';
    
    console.log('🔍 ANTHROPIC_API_KEY after update:', ANTHROPIC_API_KEY ? ANTHROPIC_API_KEY.substring(0, 15) + '...' : 'N/A');
    console.log('✅ API keys updated from settings');
}
