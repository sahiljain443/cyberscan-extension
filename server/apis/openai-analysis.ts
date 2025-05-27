import express from 'express';
import OpenAI from 'openai';

const router = express.Router();

// the newest OpenAI model is "gpt-4o" which was released May 13, 2024. do not change this unless explicitly requested by the user
const openai = new OpenAI({ 
  apiKey: process.env.OPENAI_API_KEY || process.env.OPENAI_API_KEY_ENV_VAR || "default_key"
});

interface ThreatAnalysisRequest {
  ips: Array<{
    ip: string;
    threat_level: string;
    detections: number;
    total_engines: number;
    location?: string;
    isp?: string;
    abuse_confidence?: number;
    categories?: string[];
  }>;
  domains: Array<{
    domain: string;
    threat_level: string;
    detections: number;
    total_engines: number;
    category?: string;
    registrar?: string;
    reputation?: string;
    categories?: string[];
  }>;
}

interface AIAnalysisResult {
  risk_level: 'low' | 'medium' | 'high';
  confidence: number;
  summary: string;
  findings: Array<{
    title: string;
    description: string;
    severity: 'low' | 'medium' | 'high';
  }>;
  recommendations: string[];
  processing_time: string;
}

router.post('/analyze-threats', async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { ips, domains }: ThreatAnalysisRequest = req.body;
    
    if (!ips || !domains) {
      return res.status(400).json({ 
        error: 'Missing required data: ips and domains arrays are required' 
      });
    }

    console.log(`Analyzing ${ips.length} IPs and ${domains.length} domains with AI`);

    const analysis = await analyzeWithOpenAI(ips, domains);
    
    const processingTime = `${(Date.now() - startTime) / 1000}s`;
    analysis.processing_time = processingTime;
    
    res.json(analysis);
  } catch (error) {
    console.error('Error in AI threat analysis:', error);
    res.status(500).json({
      error: 'Failed to generate AI analysis',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

async function analyzeWithOpenAI(ips: any[], domains: any[]): Promise<AIAnalysisResult> {
  try {
    const prompt = generateAnalysisPrompt(ips, domains);
    
    const response = await openai.chat.completions.create({
      model: "gpt-4o", // the newest OpenAI model is "gpt-4o" which was released May 13, 2024. do not change this unless explicitly requested by the user
      messages: [
        {
          role: "system",
          content: "You are a cybersecurity expert specializing in threat intelligence analysis. Analyze the provided network data and provide a comprehensive security assessment. Respond with valid JSON in the specified format."
        },
        {
          role: "user",
          content: prompt
        }
      ],
      response_format: { type: "json_object" },
      temperature: 0.3,
      max_tokens: 2000
    });

    const content = response.choices[0].message.content;
    if (!content) {
      throw new Error('Empty response from OpenAI');
    }

    const analysis = JSON.parse(content);
    
    // Validate the response structure
    if (!analysis.risk_level || !analysis.summary) {
      throw new Error('Invalid response structure from OpenAI');
    }

    return {
      risk_level: analysis.risk_level || 'medium',
      confidence: Math.min(100, Math.max(0, analysis.confidence || 85)),
      summary: analysis.summary || 'Analysis completed with limited data.',
      findings: analysis.findings || [],
      recommendations: analysis.recommendations || [],
      processing_time: '0s' // Will be set by caller
    };
  } catch (error) {
    console.error('OpenAI analysis error:', error);
    
    // Return a fallback analysis if OpenAI fails
    return generateFallbackAnalysis(ips, domains);
  }
}

function generateAnalysisPrompt(ips: any[], domains: any[]): string {
  const maliciousIPs = ips.filter(ip => ip.threat_level === 'malicious');
  const suspiciousIPs = ips.filter(ip => ip.threat_level === 'suspicious');
  const maliciousDomains = domains.filter(domain => domain.threat_level === 'malicious');
  const suspiciousDomains = domains.filter(domain => domain.threat_level === 'suspicious');

  return `
Analyze this cybersecurity threat intelligence data and provide a comprehensive security assessment:

IP ADDRESSES DETECTED (${ips.length} total):
${ips.map(ip => `
- ${ip.ip} (${ip.location || 'Unknown location'})
  Threat Level: ${ip.threat_level}
  Detections: ${ip.detections}/${ip.total_engines} security engines
  AbuseDB Confidence: ${ip.abuse_confidence || 0}%
  ISP: ${ip.isp || 'Unknown'}
  Categories: ${ip.categories?.join(', ') || 'None'}
`).join('')}

DOMAINS DETECTED (${domains.length} total):
${domains.map(domain => `
- ${domain.domain}
  Threat Level: ${domain.threat_level}
  Detections: ${domain.detections}/${domain.total_engines} security engines
  Category: ${domain.category || 'Unknown'}
  Registrar: ${domain.registrar || 'Unknown'}
  Reputation: ${domain.reputation || 'Unknown'}
  Threat Categories: ${domain.categories?.join(', ') || 'None'}
`).join('')}

SUMMARY STATISTICS:
- Malicious IPs: ${maliciousIPs.length}
- Suspicious IPs: ${suspiciousIPs.length}
- Malicious Domains: ${maliciousDomains.length}
- Suspicious Domains: ${suspiciousDomains.length}

Please provide a JSON response with the following structure:
{
  "risk_level": "low|medium|high",
  "confidence": number (0-100),
  "summary": "string describing overall risk and key concerns",
  "findings": [
    {
      "title": "string",
      "description": "string",
      "severity": "low|medium|high"
    }
  ],
  "recommendations": [
    "string recommendation 1",
    "string recommendation 2"
  ]
}

Focus on:
1. Overall security posture and risk level
2. Specific threats identified and their implications
3. Patterns or relationships between detected resources
4. Immediate actions needed to mitigate risks
5. Long-term security improvements

Be specific about the threats found and provide actionable recommendations for cybersecurity professionals.
  `.trim();
}

function generateFallbackAnalysis(ips: any[], domains: any[]): AIAnalysisResult {
  const maliciousIPs = ips.filter(ip => ip.threat_level === 'malicious');
  const suspiciousIPs = ips.filter(ip => ip.threat_level === 'suspicious');
  const maliciousDomains = domains.filter(domain => domain.threat_level === 'malicious');
  const suspiciousDomains = domains.filter(domain => domain.threat_level === 'suspicious');

  const totalThreats = maliciousIPs.length + maliciousDomains.length;
  const totalSuspicious = suspiciousIPs.length + suspiciousDomains.length;

  let riskLevel: 'low' | 'medium' | 'high' = 'low';
  if (totalThreats > 0) {
    riskLevel = 'high';
  } else if (totalSuspicious > 0) {
    riskLevel = 'medium';
  }

  const findings = [];
  const recommendations = [];

  if (maliciousIPs.length > 0) {
    findings.push({
      title: 'Malicious IP Addresses Detected',
      description: `${maliciousIPs.length} IP address${maliciousIPs.length > 1 ? 'es' : ''} flagged as malicious by multiple security vendors.`,
      severity: 'high' as const
    });
    recommendations.push('Immediately block all malicious IP addresses using firewall rules or network security appliances.');
  }

  if (maliciousDomains.length > 0) {
    findings.push({
      title: 'Malicious Domains Identified',
      description: `${maliciousDomains.length} domain${maliciousDomains.length > 1 ? 's' : ''} identified as malicious, potentially hosting malware or phishing content.`,
      severity: 'high' as const
    });
    recommendations.push('Block access to malicious domains through DNS filtering or web security gateways.');
  }

  if (suspiciousIPs.length > 0 || suspiciousDomains.length > 0) {
    findings.push({
      title: 'Suspicious Network Resources',
      description: `${totalSuspicious} suspicious resource${totalSuspicious > 1 ? 's' : ''} detected that require monitoring and investigation.`,
      severity: 'medium' as const
    });
    recommendations.push('Monitor traffic to suspicious resources and implement enhanced logging for security analysis.');
  }

  if (findings.length === 0) {
    findings.push({
      title: 'No Immediate Threats Detected',
      description: 'All detected network resources appear to be clean based on current threat intelligence.',
      severity: 'low' as const
    });
  }

  if (recommendations.length === 0) {
    recommendations.push('Continue regular security monitoring and threat intelligence updates.');
  }

  recommendations.push('Review and update security policies based on current threat landscape.');

  let summary = '';
  if (riskLevel === 'high') {
    summary = `High-risk webpage detected with ${totalThreats} confirmed malicious resource${totalThreats > 1 ? 's' : ''}. Immediate action required to prevent potential security incidents.`;
  } else if (riskLevel === 'medium') {
    summary = `Medium-risk assessment due to ${totalSuspicious} suspicious resource${totalSuspicious > 1 ? 's' : ''}. Enhanced monitoring recommended.`;
  } else {
    summary = `Low-risk assessment. All detected network resources appear clean, but continued vigilance is recommended.`;
  }

  return {
    risk_level: riskLevel,
    confidence: 85,
    summary,
    findings,
    recommendations,
    processing_time: '0s'
  };
}

export default router;
