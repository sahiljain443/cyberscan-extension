// Shared types for Chrome extension and server

export interface NetworkData {
  ips: string[];
  domains: string[];
  currentUrl: string;
  currentDomain: string;
  timestamp: number;
}

export interface ThreatAnalysis {
  ip?: string;
  domain?: string;
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
  timestamp: number;
  error?: string;
}

export interface AIAnalysis {
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
  error?: string;
}

export interface ScanResults {
  ips: ThreatAnalysis[];
  domains: ThreatAnalysis[];
  aiAnalysis: AIAnalysis;
  summary: {
    ips: {
      total: number;
      safe: number;
      suspicious: number;
      malicious: number;
    };
    domains: {
      total: number;
      safe: number;
      suspicious: number;
      malicious: number;
    };
    overallThreat: 'low' | 'medium' | 'high';
  };
}

export interface ScanData extends NetworkData {
  analysis: ScanResults;
  scanTime: number;
}

export interface ApiStatus {
  virustotal: boolean;
  abuseipdb: boolean;
  openai: boolean;
}

export interface ExtensionMessage {
  action: string;
  data?: any;
  tabId?: number;
}

// Chrome extension specific types
export interface ChromeTab {
  id?: number;
  url?: string;
  title?: string;
  active?: boolean;
}

export interface ChromeMessage {
  action: string;
  data?: any;
}

export interface ChromeResponse {
  success: boolean;
  data?: any;
  error?: string;
}
