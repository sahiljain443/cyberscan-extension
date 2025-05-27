import express from 'express';

const router = express.Router();

// VirusTotal API configuration
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY || process.env.VT_API_KEY;
const VIRUSTOTAL_BASE_URL = 'https://www.virustotal.com/vtapi/v2';

// AbuseIPDB API configuration
const ABUSEIPDB_API_KEY = process.env.ABUSEIPDB_API_KEY || process.env.ABUSE_API_KEY;
const ABUSEIPDB_BASE_URL = 'https://api.abuseipdb.com/api/v2';

interface ThreatAnalysisResult {
  status: 'safe' | 'suspicious' | 'malicious' | 'unknown';
  threat_level: string;
  detections: number;
  total_engines: number;
  location?: string;
  isp?: string;
  asn?: string;
  abuse_confidence?: number;
  categories?: string[];
  registrar?: string;
  creation_date?: string;
  reputation?: string;
  sources: {
    virustotal?: any;
    abuseipdb?: any;
  };
}

// Analyze IP address
router.get('/ip/:ip', async (req, res) => {
  const { ip } = req.params;
  
  if (!isValidIP(ip)) {
    return res.status(400).json({ error: 'Invalid IP address format' });
  }

  try {
    console.log(`Analyzing IP: ${ip}`);
    
    const [vtResult, abuseResult] = await Promise.allSettled([
      analyzeIPWithVirusTotal(ip),
      analyzeIPWithAbuseIPDB(ip)
    ]);

    const result: ThreatAnalysisResult = {
      status: 'unknown',
      threat_level: 'unknown',
      detections: 0,
      total_engines: 0,
      sources: {}
    };

    // Process VirusTotal results
    if (vtResult.status === 'fulfilled' && vtResult.value) {
      result.sources.virustotal = vtResult.value;
      result.detections = vtResult.value.positives || 0;
      result.total_engines = vtResult.value.total || 0;
      result.location = vtResult.value.country || undefined;
      result.asn = vtResult.value.asn || undefined;
    } else {
      console.warn(`VirusTotal analysis failed for IP ${ip}:`, 
        vtResult.status === 'rejected' ? vtResult.reason : 'Unknown error');
    }

    // Process AbuseIPDB results
    if (abuseResult.status === 'fulfilled' && abuseResult.value) {
      result.sources.abuseipdb = abuseResult.value;
      result.abuse_confidence = abuseResult.value.abuseConfidencePercentage || 0;
      result.isp = abuseResult.value.isp || undefined;
      result.location = result.location || abuseResult.value.countryCode || undefined;
      
      if (abuseResult.value.usageType) {
        result.categories = [abuseResult.value.usageType];
      }
    } else {
      console.warn(`AbuseIPDB analysis failed for IP ${ip}:`, 
        abuseResult.status === 'rejected' ? abuseResult.reason : 'Unknown error');
    }

    // Determine threat level
    result.threat_level = determineThreatLevel(result.detections, result.total_engines, result.abuse_confidence || 0);
    result.status = result.threat_level as any;

    res.json(result);
  } catch (error) {
    console.error(`Error analyzing IP ${ip}:`, error);
    res.status(500).json({ 
      error: 'Internal server error during IP analysis',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// Analyze domain
router.get('/domain/:domain', async (req, res) => {
  const { domain } = req.params;
  
  if (!isValidDomain(domain)) {
    return res.status(400).json({ error: 'Invalid domain format' });
  }

  try {
    console.log(`Analyzing domain: ${domain}`);
    
    const vtResult = await analyzeDomainWithVirusTotal(domain);
    
    const result: ThreatAnalysisResult = {
      status: 'unknown',
      threat_level: 'unknown',
      detections: 0,
      total_engines: 0,
      sources: {}
    };

    if (vtResult) {
      result.sources.virustotal = vtResult;
      result.detections = vtResult.positives || 0;
      result.total_engines = vtResult.total || 0;
      
      // Extract additional domain info
      if (vtResult.whois) {
        result.registrar = extractRegistrar(vtResult.whois);
        result.creation_date = extractCreationDate(vtResult.whois);
      }
      
      if (vtResult.categories) {
        result.categories = Object.keys(vtResult.categories);
      }
      
      // Calculate reputation score
      if (vtResult.reputation !== undefined) {
        result.reputation = vtResult.reputation.toString();
      }
    }

    // Determine threat level
    result.threat_level = determineThreatLevel(result.detections, result.total_engines, 0);
    result.status = result.threat_level as any;

    res.json(result);
  } catch (error) {
    console.error(`Error analyzing domain ${domain}:`, error);
    res.status(500).json({ 
      error: 'Internal server error during domain analysis',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// Health check endpoint
router.get('/health', async (req, res) => {
  const health = {
    virustotal: !!VIRUSTOTAL_API_KEY,
    abuseipdb: !!ABUSEIPDB_API_KEY,
    timestamp: new Date().toISOString()
  };
  
  res.json(health);
});

// VirusTotal IP analysis
async function analyzeIPWithVirusTotal(ip: string) {
  if (!VIRUSTOTAL_API_KEY) {
    throw new Error('VirusTotal API key not configured');
  }

  const url = `${VIRUSTOTAL_BASE_URL}/ip-address/report`;
  const params = new URLSearchParams({
    apikey: VIRUSTOTAL_API_KEY,
    ip: ip
  });

  const response = await fetch(`${url}?${params}`, {
    method: 'GET',
    headers: {
      'User-Agent': 'CyberGuard-Extension/1.0'
    }
  });

  if (!response.ok) {
    throw new Error(`VirusTotal API error: ${response.status} ${response.statusText}`);
  }

  const data = await response.json();
  
  if (data.response_code !== 1) {
    console.warn(`VirusTotal: No data found for IP ${ip}`);
    return null;
  }

  return data;
}

// AbuseIPDB IP analysis
async function analyzeIPWithAbuseIPDB(ip: string) {
  if (!ABUSEIPDB_API_KEY) {
    throw new Error('AbuseIPDB API key not configured');
  }

  const url = `${ABUSEIPDB_BASE_URL}/check`;
  const params = new URLSearchParams({
    ipAddress: ip,
    maxAgeInDays: '90',
    verbose: 'true'
  });

  const response = await fetch(`${url}?${params}`, {
    method: 'GET',
    headers: {
      'Key': ABUSEIPDB_API_KEY,
      'Accept': 'application/json',
      'User-Agent': 'CyberGuard-Extension/1.0'
    }
  });

  if (!response.ok) {
    throw new Error(`AbuseIPDB API error: ${response.status} ${response.statusText}`);
  }

  const data = await response.json();
  
  if (!data.data) {
    console.warn(`AbuseIPDB: No data found for IP ${ip}`);
    return null;
  }

  return data.data;
}

// VirusTotal domain analysis
async function analyzeDomainWithVirusTotal(domain: string) {
  if (!VIRUSTOTAL_API_KEY) {
    throw new Error('VirusTotal API key not configured');
  }

  const url = `${VIRUSTOTAL_BASE_URL}/domain/report`;
  const params = new URLSearchParams({
    apikey: VIRUSTOTAL_API_KEY,
    domain: domain
  });

  const response = await fetch(`${url}?${params}`, {
    method: 'GET',
    headers: {
      'User-Agent': 'CyberGuard-Extension/1.0'
    }
  });

  if (!response.ok) {
    throw new Error(`VirusTotal API error: ${response.status} ${response.statusText}`);
  }

  const data = await response.json();
  
  if (data.response_code !== 1) {
    console.warn(`VirusTotal: No data found for domain ${domain}`);
    return null;
  }

  return data;
}

// Helper functions
function isValidIP(ip: string): boolean {
  const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipRegex.test(ip);
}

function isValidDomain(domain: string): boolean {
  const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
  return domainRegex.test(domain) && domain.length <= 253;
}

function determineThreatLevel(detections: number, total: number, abuseConfidence: number): string {
  if (total === 0) {
    // No data available, use abuse confidence
    if (abuseConfidence >= 75) return 'malicious';
    if (abuseConfidence >= 25) return 'suspicious';
    return 'safe';
  }

  const percentage = (detections / total) * 100;
  
  if (percentage >= 15 || abuseConfidence >= 75) {
    return 'malicious';
  } else if (percentage >= 5 || abuseConfidence >= 25) {
    return 'suspicious';
  } else {
    return 'safe';
  }
}

function extractRegistrar(whois: string): string {
  if (!whois) return 'Unknown';
  
  const registrarMatch = whois.match(/Registrar:\s*(.+)/i);
  if (registrarMatch) {
    return registrarMatch[1].trim();
  }
  
  const registrarNameMatch = whois.match(/Registrar Name:\s*(.+)/i);
  if (registrarNameMatch) {
    return registrarNameMatch[1].trim();
  }
  
  return 'Unknown';
}

function extractCreationDate(whois: string): string {
  if (!whois) return 'Unknown';
  
  const createdMatch = whois.match(/Creation Date:\s*(.+)/i);
  if (createdMatch) {
    return new Date(createdMatch[1].trim()).toLocaleDateString();
  }
  
  const registeredMatch = whois.match(/Registered:\s*(.+)/i);
  if (registeredMatch) {
    return new Date(registeredMatch[1].trim()).toLocaleDateString();
  }
  
  return 'Unknown';
}

export default router;
