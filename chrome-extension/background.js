// Background service worker for API calls and data processing
const API_BASE_URL = 'http://localhost:5000/api';

// Store scan results
let lastScanData = null;
let apiStatus = {
    virustotal: false,
    abuseipdb: false,
    openai: false
};

// Listen for messages from content script and popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
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
            .then(status => sendResponse({ success: true, status }))
            .catch(error => sendResponse({ success: false, error: error.message }));
        return true;
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
    const { ips, domains } = data;
    
    console.log(`Analyzing ${ips.length} IPs and ${domains.length} domains`);
    
    try {
        // Analyze IPs
        const ipAnalysis = await Promise.all(
            ips.map(ip => analyzeIP(ip))
        );
        
        // Analyze domains
        const domainAnalysis = await Promise.all(
            domains.map(domain => analyzeDomain(domain))
        );
        
        // Get AI analysis
        const aiAnalysis = await getAIAnalysis({
            ips: ipAnalysis,
            domains: domainAnalysis
        });
        
        return {
            ips: ipAnalysis,
            domains: domainAnalysis,
            aiAnalysis: aiAnalysis,
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
        const response = await fetch(`${API_BASE_URL}/threat-intelligence/ip/${ip}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const result = await response.json();
        return {
            ip,
            ...result,
            timestamp: Date.now()
        };
    } catch (error) {
        console.error(`Error analyzing IP ${ip}:`, error);
        return {
            ip,
            error: error.message,
            status: 'unknown',
            threat_level: 'unknown',
            detections: 0,
            total_engines: 0,
            location: 'Unknown',
            isp: 'Unknown',
            asn: 'Unknown',
            timestamp: Date.now()
        };
    }
}

async function analyzeDomain(domain) {
    console.log(`Analyzing domain: ${domain}`);
    
    try {
        const response = await fetch(`${API_BASE_URL}/threat-intelligence/domain/${domain}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const result = await response.json();
        return {
            domain,
            ...result,
            timestamp: Date.now()
        };
    } catch (error) {
        console.error(`Error analyzing domain ${domain}:`, error);
        return {
            domain,
            error: error.message,
            status: 'unknown',
            threat_level: 'unknown',
            detections: 0,
            total_engines: 0,
            category: 'Unknown',
            registrar: 'Unknown',
            creation_date: 'Unknown',
            timestamp: Date.now()
        };
    }
}

async function getAIAnalysis(data) {
    console.log('Getting AI analysis');
    
    try {
        const response = await fetch(`${API_BASE_URL}/openai/analyze-threats`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const result = await response.json();
        return result;
    } catch (error) {
        console.error('Error getting AI analysis:', error);
        return {
            error: error.message,
            risk_level: 'unknown',
            confidence: 0,
            summary: 'AI analysis unavailable due to error: ' + error.message,
            findings: [],
            recommendations: []
        };
    }
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

async function checkApiStatus() {
    const status = { ...apiStatus };
    
    try {
        const response = await fetch(`${API_BASE_URL}/health`, {
            method: 'GET',
            timeout: 5000
        });
        
        if (response.ok) {
            const health = await response.json();
            status.virustotal = health.virustotal || false;
            status.abuseipdb = health.abuseipdb || false;
            status.openai = health.openai || false;
        }
    } catch (error) {
        console.error('Error checking API status:', error);
        status.virustotal = false;
        status.abuseipdb = false;
        status.openai = false;
    }
    
    apiStatus = status;
    return status;
}

// Initialize on extension startup
chrome.runtime.onStartup.addListener(() => {
    checkApiStatus();
});

chrome.runtime.onInstalled.addListener(() => {
    checkApiStatus();
});

// Periodic API status check
setInterval(checkApiStatus, 60000); // Check every minute
