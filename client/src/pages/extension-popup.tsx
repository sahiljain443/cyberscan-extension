import { useState, useEffect, useCallback } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Progress } from '@/components/ui/progress';
import { 
  Shield, 
  Globe, 
  Server, 
  Brain, 
  RefreshCw, 
  Settings, 
  Copy, 
  Clock, 
  CheckCircle, 
  AlertTriangle, 
  Ban,
  Search,
  Lightbulb,
  ChartPie,
  TriangleAlert
} from 'lucide-react';

interface NetworkData {
  ips: string[];
  domains: string[];
  currentUrl: string;
  currentDomain: string;
  timestamp: number;
}

interface ThreatAnalysis {
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

interface AIAnalysis {
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

interface ScanResults {
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

interface ScanData extends NetworkData {
  analysis: ScanResults;
  scanTime: number;
}

interface ApiStatus {
  virustotal: boolean;
  abuseipdb: boolean;
  openai: boolean;
}

export default function ExtensionPopup() {
  const [activeTab, setActiveTab] = useState('ips');
  const [scanData, setScanData] = useState<ScanData | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [apiStatus, setApiStatus] = useState<ApiStatus>({ virustotal: false, abuseipdb: false, openai: false });
  const [currentUrl, setCurrentUrl] = useState('Loading...');
  const [error, setError] = useState<string | null>(null);

  // Update current URL
  const updateCurrentUrl = useCallback(async () => {
    try {
      if (typeof chrome !== 'undefined' && chrome.tabs) {
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tabs[0]) {
          const url = new URL(tabs[0].url || '');
          setCurrentUrl(url.hostname);
        }
      } else {
        setCurrentUrl('example.com');
      }
    } catch (error) {
      console.error('Error getting current URL:', error);
      setCurrentUrl('Unknown');
    }
  }, []);

  // Check API status
  const checkApiStatus = useCallback(async () => {
    try {
      if (typeof chrome !== 'undefined' && chrome.runtime) {
        const response = await chrome.runtime.sendMessage({
          action: 'checkApiStatus'
        });

        if (response.success) {
          setApiStatus(response.status);
        } else {
          setApiStatus({ virustotal: false, abuseipdb: false, openai: false });
        }
      }
    } catch (error) {
      console.error('Error checking API status:', error);
      setApiStatus({ virustotal: false, abuseipdb: false, openai: false });
    }
  }, []);

  // Load last scan data
  const loadLastScanData = useCallback(async () => {
    try {
      if (typeof chrome !== 'undefined' && chrome.runtime) {
        const response = await chrome.runtime.sendMessage({
          action: 'getLastScanData'
        });

        if (response.success && response.data) {
          setScanData(response.data);
        }
      }
    } catch (error) {
      console.error('Error loading last scan data:', error);
    }
  }, []);

  // Rescan page
  const rescanPage = useCallback(async () => {
    if (isScanning) return;

    setIsScanning(true);
    setError(null);

    try {
      if (typeof chrome !== 'undefined' && chrome.tabs && chrome.runtime) {
        // Get current tab
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tabs[0]) {
          throw new Error('No active tab found');
        }

        // Extract network data from content script
        const response = await chrome.tabs.sendMessage(tabs[0].id!, {
          action: 'extractNetworkData'
        });

        if (!response.success) {
          throw new Error(response.error || 'Failed to extract network data');
        }

        // Send data to background for analysis
        const analysisResponse = await chrome.runtime.sendMessage({
          action: 'analyzeNetworkData',
          data: response.data
        });

        if (!analysisResponse.success) {
          throw new Error(analysisResponse.error || 'Failed to analyze network data');
        }

        const newScanData: ScanData = {
          ...response.data,
          analysis: analysisResponse.data,
          scanTime: Date.now()
        };

        setScanData(newScanData);
      }
    } catch (error) {
      console.error('Error during rescan:', error);
      setError(error instanceof Error ? error.message : 'Unknown error occurred');
    } finally {
      setIsScanning(false);
    }
  }, [isScanning]);

  // Copy to clipboard
  const copyToClipboard = useCallback(async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch (error) {
      console.error('Failed to copy to clipboard:', error);
    }
  }, []);

  // Format time ago
  const getTimeAgo = useCallback((timestamp: number) => {
    const now = Date.now();
    const diff = now - timestamp;
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    
    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes} min ago`;
    if (hours < 24) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    return new Date(timestamp).toLocaleDateString();
  }, []);

  // Get threat status styles
  const getThreatStatusStyles = useCallback((threatLevel: string) => {
    switch (threatLevel) {
      case 'safe':
        return { badge: 'bg-green-500/10 text-green-600 hover:bg-green-500/20', indicator: 'bg-green-500' };
      case 'suspicious':
        return { badge: 'bg-yellow-500/10 text-yellow-600 hover:bg-yellow-500/20', indicator: 'bg-yellow-500' };
      case 'malicious':
        return { badge: 'bg-red-500/10 text-red-600 hover:bg-red-500/20', indicator: 'bg-red-500 animate-pulse' };
      default:
        return { badge: 'bg-gray-500/10 text-gray-600 hover:bg-gray-500/20', indicator: 'bg-gray-500' };
    }
  }, []);

  // Get risk badge styles
  const getRiskBadgeStyles = useCallback((riskLevel: string) => {
    switch (riskLevel?.toLowerCase()) {
      case 'high':
        return 'bg-red-500 text-white';
      case 'medium':
        return 'bg-yellow-500 text-white';
      case 'low':
        return 'bg-green-500 text-white';
      default:
        return 'bg-gray-500 text-white';
    }
  }, []);

  // Initialize
  useEffect(() => {
    updateCurrentUrl();
    checkApiStatus();
    loadLastScanData();

    // Listen for scan completion
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      const handleMessage = (request: any) => {
        if (request.action === 'scanComplete') {
          setScanData(request.data);
          setIsScanning(false);
        }
      };

      chrome.runtime.onMessage.addListener(handleMessage);
      return () => chrome.runtime.onMessage.removeListener(handleMessage);
    }
  }, [updateCurrentUrl, checkApiStatus, loadLastScanData]);

  const allApiOnline = apiStatus.virustotal && apiStatus.abuseipdb && apiStatus.openai;
  const someApiOnline = apiStatus.virustotal || apiStatus.abuseipdb || apiStatus.openai;

  return (
    <div className="w-[400px] h-[600px] bg-surface font-inter overflow-hidden flex flex-col">
      {/* Header */}
      <div className="bg-gradient-to-r from-primary-orange to-secondary-orange text-white p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center space-x-2">
            <Shield className="w-5 h-5" />
            <div>
              <h1 className="text-lg font-bold leading-none">CyberGuard</h1>
              <p className="text-xs opacity-90 leading-none">Security Analysis</p>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <Button
              size="sm"
              variant="ghost"
              className="h-8 w-8 p-0 text-white hover:bg-white/20"
              onClick={rescanPage}
              disabled={isScanning}
            >
              <RefreshCw className={`w-4 h-4 ${isScanning ? 'animate-spin' : ''}`} />
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className="h-8 w-8 p-0 text-white hover:bg-white/20"
            >
              <Settings className="w-4 h-4" />
            </Button>
          </div>
        </div>
        
        <div className="flex items-center space-x-2 text-sm bg-white/10 rounded-md px-3 py-2 mb-3">
          <Globe className="w-4 h-4 opacity-80" />
          <span className="opacity-90">Analyzing:</span>
          <span className="font-medium truncate max-w-[200px]">{currentUrl}</span>
        </div>

        <div className="flex items-center justify-between text-sm">
          <div className="flex items-center space-x-2">
            {isScanning && <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />}
            <span>{isScanning ? 'Scanning page...' : 'Scan complete'}</span>
          </div>
          <Button
            size="sm"
            variant="ghost"
            className="text-white bg-white/20 hover:bg-white/30 h-6 px-3 text-xs"
            onClick={rescanPage}
            disabled={isScanning}
          >
            <RefreshCw className="w-3 h-3 mr-1" />
            Rescan
          </Button>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <Alert className="mx-4 mt-4 border-red-200 bg-red-50">
          <TriangleAlert className="h-4 w-4 text-red-600" />
          <AlertDescription className="text-red-800">{error}</AlertDescription>
        </Alert>
      )}

      {/* Tab Navigation and Content */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="flex-1 flex flex-col">
        <TabsList className="grid w-full grid-cols-3 bg-light border-b">
          <TabsTrigger 
            value="ips" 
            className="data-[state=active]:bg-surface data-[state=active]:text-primary-orange data-[state=active]:border-b-2 data-[state=active]:border-primary-orange"
          >
            <Server className="w-4 h-4 mr-1" />
            IPs ({scanData?.analysis?.summary?.ips?.total || 0})
          </TabsTrigger>
          <TabsTrigger 
            value="domains"
            className="data-[state=active]:bg-surface data-[state=active]:text-primary-orange data-[state=active]:border-b-2 data-[state=active]:border-primary-orange"
          >
            <Globe className="w-4 h-4 mr-1" />
            Domains ({scanData?.analysis?.summary?.domains?.total || 0})
          </TabsTrigger>
          <TabsTrigger 
            value="analysis"
            className="data-[state=active]:bg-surface data-[state=active]:text-primary-orange data-[state=active]:border-b-2 data-[state=active]:border-primary-orange"
          >
            <Brain className="w-4 h-4 mr-1" />
            AI Analysis
          </TabsTrigger>
        </TabsList>

        <div className="flex-1 overflow-y-auto">
          {/* IPs Tab */}
          <TabsContent value="ips" className="p-4 space-y-3 m-0">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-dark">Detected IP Addresses</h3>
              <span className="text-xs text-medium">
                Last scan: {scanData ? getTimeAgo(scanData.scanTime) : 'Never'}
              </span>
            </div>

            {/* Summary Card */}
            <Card className="bg-gradient-to-r from-primary-orange/10 to-surface border-primary-orange/20">
              <CardContent className="p-3">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-sm font-medium text-dark mb-2">Threat Summary</div>
                    <div className="flex items-center space-x-4 text-sm">
                      <span className="flex items-center text-green-600">
                        <CheckCircle className="w-3 h-3 mr-1" />
                        {scanData?.analysis?.summary?.ips?.safe || 0} Safe
                      </span>
                      <span className="flex items-center text-yellow-600">
                        <AlertTriangle className="w-3 h-3 mr-1" />
                        {scanData?.analysis?.summary?.ips?.suspicious || 0} Suspicious
                      </span>
                      <span className="flex items-center text-red-600">
                        <Ban className="w-3 h-3 mr-1" />
                        {scanData?.analysis?.summary?.ips?.malicious || 0} Malicious
                      </span>
                    </div>
                  </div>
                  <ChartPie className="w-6 h-6 text-primary-orange" />
                </div>
              </CardContent>
            </Card>

            {/* IP List */}
            <div className="space-y-3">
              {!scanData?.analysis?.ips || scanData.analysis.ips.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-8 text-center text-medium">
                  <Search className="w-12 h-12 mb-4 opacity-50" />
                  <p>No IP addresses detected yet. Click "Rescan" to analyze the page.</p>
                </div>
              ) : (
                scanData.analysis.ips.map((ip, index) => {
                  const styles = getThreatStatusStyles(ip.threat_level);
                  return (
                    <Card key={index} className="border hover:shadow-md transition-shadow">
                      <CardContent className="p-3">
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center space-x-3">
                            <div className={`w-2 h-2 rounded-full ${styles.indicator}`} />
                            <div>
                              <div className="font-mono text-sm font-medium text-dark">{ip.ip}</div>
                              <div className="text-xs text-medium">{ip.location || 'Unknown Location'}</div>
                            </div>
                          </div>
                          <div className="flex items-center space-x-2">
                            <Badge className={styles.badge}>
                              {ip.threat_level === 'safe' ? 'Clean' : 
                               ip.threat_level === 'suspicious' ? 'Suspicious' : 
                               ip.threat_level === 'malicious' ? 'Malicious' : 'Unknown'}
                            </Badge>
                            <Button
                              size="sm"
                              variant="ghost"
                              className="h-6 w-6 p-0 text-medium hover:text-dark"
                              onClick={() => copyToClipboard(ip.ip!)}
                            >
                              <Copy className="w-3 h-3" />
                            </Button>
                          </div>
                        </div>
                        <div className="border-t pt-2 mt-2">
                          <div className="grid grid-cols-2 gap-2 text-xs">
                            <div className="flex justify-between">
                              <span className="text-medium">VirusTotal:</span>
                              <span className="font-medium">{ip.detections}/{ip.total_engines} engines</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-medium">AbuseIPDB:</span>
                              <span className="font-medium">{ip.abuse_confidence || 0}% confidence</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-medium">ASN:</span>
                              <span className="font-medium font-mono">{ip.asn || 'Unknown'}</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-medium">ISP:</span>
                              <span className="font-medium">{ip.isp || 'Unknown'}</span>
                            </div>
                          </div>
                          {ip.categories && ip.categories.length > 0 && (
                            <div className="mt-2">
                              <div className="text-xs text-medium mb-1">Threat Categories:</div>
                              <div className="flex flex-wrap gap-1">
                                {ip.categories.map((cat, catIndex) => (
                                  <Badge key={catIndex} variant="outline" className="text-xs px-2 py-0 text-red-600 border-red-200">
                                    {cat}
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      </CardContent>
                    </Card>
                  );
                })
              )}
            </div>
          </TabsContent>

          {/* Domains Tab */}
          <TabsContent value="domains" className="p-4 space-y-3 m-0">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-dark">Detected Domains</h3>
              <span className="text-xs text-medium">
                Last scan: {scanData ? getTimeAgo(scanData.scanTime) : 'Never'}
              </span>
            </div>

            {/* Summary Card */}
            <Card className="bg-gradient-to-r from-primary-orange/10 to-surface border-primary-orange/20">
              <CardContent className="p-3">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-sm font-medium text-dark mb-2">Domain Summary</div>
                    <div className="flex items-center space-x-4 text-sm">
                      <span className="flex items-center text-green-600">
                        <CheckCircle className="w-3 h-3 mr-1" />
                        {scanData?.analysis?.summary?.domains?.safe || 0} Safe
                      </span>
                      <span className="flex items-center text-yellow-600">
                        <AlertTriangle className="w-3 h-3 mr-1" />
                        {scanData?.analysis?.summary?.domains?.suspicious || 0} Suspicious
                      </span>
                      <span className="flex items-center text-red-600">
                        <Ban className="w-3 h-3 mr-1" />
                        {scanData?.analysis?.summary?.domains?.malicious || 0} Malicious
                      </span>
                    </div>
                  </div>
                  <Globe className="w-6 h-6 text-primary-orange" />
                </div>
              </CardContent>
            </Card>

            {/* Domain List */}
            <div className="space-y-3">
              {!scanData?.analysis?.domains || scanData.analysis.domains.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-8 text-center text-medium">
                  <Search className="w-12 h-12 mb-4 opacity-50" />
                  <p>No external domains detected yet. Click "Rescan" to analyze the page.</p>
                </div>
              ) : (
                scanData.analysis.domains.map((domain, index) => {
                  const styles = getThreatStatusStyles(domain.threat_level);
                  return (
                    <Card key={index} className="border hover:shadow-md transition-shadow">
                      <CardContent className="p-3">
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center space-x-3">
                            <div className={`w-2 h-2 rounded-full ${styles.indicator}`} />
                            <div>
                              <div className="font-mono text-sm font-medium text-dark">{domain.domain}</div>
                              <div className="text-xs text-medium">{domain.registrar || 'Unknown Category'}</div>
                            </div>
                          </div>
                          <div className="flex items-center space-x-2">
                            <Badge className={styles.badge}>
                              {domain.threat_level === 'safe' ? 'Clean' : 
                               domain.threat_level === 'suspicious' ? 'Suspicious' : 
                               domain.threat_level === 'malicious' ? 'Malicious' : 'Unknown'}
                            </Badge>
                            <Button
                              size="sm"
                              variant="ghost"
                              className="h-6 w-6 p-0 text-medium hover:text-dark"
                              onClick={() => copyToClipboard(domain.domain!)}
                            >
                              <Copy className="w-3 h-3" />
                            </Button>
                          </div>
                        </div>
                        <div className="border-t pt-2 mt-2">
                          <div className="grid grid-cols-2 gap-2 text-xs">
                            <div className="flex justify-between">
                              <span className="text-medium">VirusTotal:</span>
                              <span className="font-medium">{domain.detections}/{domain.total_engines} engines</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-medium">Registrar:</span>
                              <span className="font-medium">{domain.registrar || 'Unknown'}</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-medium">Created:</span>
                              <span className="font-medium">{domain.creation_date || 'Unknown'}</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-medium">Reputation:</span>
                              <span className="font-medium">{domain.reputation || 'Unknown'}</span>
                            </div>
                          </div>
                          {domain.categories && domain.categories.length > 0 && (
                            <div className="mt-2">
                              <div className="text-xs text-medium mb-1">Threat Categories:</div>
                              <div className="flex flex-wrap gap-1">
                                {domain.categories.map((cat, catIndex) => (
                                  <Badge key={catIndex} variant="outline" className="text-xs px-2 py-0 text-red-600 border-red-200">
                                    {cat}
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      </CardContent>
                    </Card>
                  );
                })
              )}
            </div>
          </TabsContent>

          {/* AI Analysis Tab */}
          <TabsContent value="analysis" className="p-4 space-y-4 m-0">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-dark">AI Threat Analysis</h3>
              <span className="text-xs text-medium">
                Analyzed: {scanData ? getTimeAgo(scanData.scanTime) : 'Never'}
              </span>
            </div>

            {!scanData?.analysis?.aiAnalysis ? (
              <div className="flex flex-col items-center justify-center py-8 text-center text-medium">
                <Brain className="w-12 h-12 mb-4 opacity-50" />
                <p>No analysis available yet. Scan the page to get AI-powered threat insights.</p>
              </div>
            ) : scanData.analysis.aiAnalysis.error ? (
              <Alert className="border-red-200 bg-red-50">
                <TriangleAlert className="h-4 w-4 text-red-600" />
                <AlertDescription className="text-red-800">
                  AI analysis failed: {scanData.analysis.aiAnalysis.error}
                </AlertDescription>
              </Alert>
            ) : (
              <>
                {/* Risk Assessment */}
                <Card className="bg-gradient-to-r from-red-50 to-yellow-50 border-yellow-200">
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center space-x-2">
                        <TriangleAlert className="w-5 h-5 text-yellow-600" />
                        <h4 className="font-semibold text-dark">Risk Assessment</h4>
                      </div>
                      <Badge className={getRiskBadgeStyles(scanData.analysis.aiAnalysis.risk_level)}>
                        {scanData.analysis.aiAnalysis.risk_level?.toUpperCase() || 'UNKNOWN'} RISK
                      </Badge>
                    </div>
                    <p className="text-sm text-dark leading-relaxed">
                      {scanData.analysis.aiAnalysis.summary}
                    </p>
                  </CardContent>
                </Card>

                {/* Key Findings */}
                {scanData.analysis.aiAnalysis.findings && scanData.analysis.aiAnalysis.findings.length > 0 && (
                  <Card>
                    <CardContent className="p-4">
                      <h4 className="font-semibold text-dark mb-3 flex items-center">
                        <Search className="w-4 h-4 mr-2 text-primary-orange" />
                        Key Findings
                      </h4>
                      <div className="space-y-3">
                        {scanData.analysis.aiAnalysis.findings.map((finding, index) => (
                          <div key={index} className="flex items-start space-x-3">
                            <div className={`w-1.5 h-1.5 rounded-full mt-2 flex-shrink-0 ${
                              finding.severity === 'high' ? 'bg-red-500' :
                              finding.severity === 'medium' ? 'bg-yellow-500' : 'bg-primary-orange'
                            }`} />
                            <div>
                              <div className="text-sm font-medium text-dark">{finding.title}</div>
                              <div className="text-xs text-medium mt-1">{finding.description}</div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}

                {/* Recommendations */}
                {scanData.analysis.aiAnalysis.recommendations && scanData.analysis.aiAnalysis.recommendations.length > 0 && (
                  <Card>
                    <CardContent className="p-4">
                      <h4 className="font-semibold text-dark mb-3 flex items-center">
                        <Lightbulb className="w-4 h-4 mr-2 text-primary-orange" />
                        Recommendations
                      </h4>
                      <div className="space-y-2">
                        {scanData.analysis.aiAnalysis.recommendations.map((rec, index) => (
                          <div key={index} className="flex items-start space-x-3">
                            <CheckCircle className="w-4 h-4 text-green-600 mt-0.5 flex-shrink-0" />
                            <div className="text-sm text-dark">{rec}</div>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}

                {/* Analysis Metadata */}
                <Card className="bg-light/50">
                  <CardContent className="p-3">
                    <div className="grid grid-cols-2 gap-2 text-xs text-medium">
                      <div className="flex justify-between">
                        <span>Analysis Date:</span>
                        <span>{new Date().toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Model:</span>
                        <span>GPT-4o</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Confidence:</span>
                        <span className="text-green-600 font-medium">{scanData.analysis.aiAnalysis.confidence}%</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Processing Time:</span>
                        <span>{scanData.analysis.aiAnalysis.processing_time}</span>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </>
            )}
          </TabsContent>
        </div>
      </Tabs>

      {/* Footer */}
      <div className="bg-light border-t border-gray-200 p-3 flex items-center justify-between text-xs text-medium">
        <div className="flex items-center space-x-2">
          <Clock className="w-3 h-3" />
          <span>Last scan: {scanData ? getTimeAgo(scanData.scanTime) : 'Never'}</span>
        </div>
        <div className="flex items-center space-x-2">
          <div className={`w-2 h-2 rounded-full ${
            allApiOnline ? 'bg-green-500' : someApiOnline ? 'bg-yellow-500' : 'bg-red-500'
          }`} />
          <span>APIs: {allApiOnline ? 'Online' : someApiOnline ? 'Partial' : 'Offline'}</span>
        </div>
      </div>
    </div>
  );
}
