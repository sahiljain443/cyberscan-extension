import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { 
  Shield, 
  Download, 
  Globe, 
  Server, 
  Brain, 
  CheckCircle, 
  AlertTriangle,
  Chrome,
  Settings,
  Eye,
  Zap
} from 'lucide-react';

export default function Home() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-orange-50 to-white">
      {/* Header */}
      <div className="bg-gradient-to-r from-primary-orange to-secondary-orange text-white">
        <div className="container mx-auto px-6 py-12">
          <div className="text-center">
            <div className="flex items-center justify-center mb-4">
              <Shield className="w-16 h-16 mr-4" />
              <div>
                <h1 className="text-4xl font-bold">CyberGuard</h1>
                <p className="text-xl opacity-90">Advanced Security Analysis Extension</p>
              </div>
            </div>
            <p className="text-lg max-w-2xl mx-auto opacity-95">
              A powerful Chrome extension for cybersecurity professionals that analyzes webpage network data, 
              performs threat intelligence lookups, and provides AI-powered security insights.
            </p>
          </div>
        </div>
      </div>

      <div className="container mx-auto px-6 py-12">
        {/* Installation Guide */}
        <Card className="mb-12 border-2 border-orange-200">
          <CardHeader className="bg-orange-50">
            <CardTitle className="flex items-center text-2xl text-orange-800">
              <Chrome className="w-8 h-8 mr-3" />
              How to Install the Extension
            </CardTitle>
          </CardHeader>
          <CardContent className="p-6">
            <div className="grid md:grid-cols-2 gap-8">
              <div className="space-y-4">
                <div className="flex items-start space-x-3">
                  <Badge className="bg-orange-500 text-white">1</Badge>
                  <div>
                    <h3 className="font-semibold">Open Chrome Extensions</h3>
                    <p className="text-gray-600">Go to <code className="bg-gray-100 px-2 py-1 rounded">chrome://extensions/</code> in Chrome</p>
                  </div>
                </div>
                <div className="flex items-start space-x-3">
                  <Badge className="bg-orange-500 text-white">2</Badge>
                  <div>
                    <h3 className="font-semibold">Enable Developer Mode</h3>
                    <p className="text-gray-600">Toggle "Developer mode" in the top right corner</p>
                  </div>
                </div>
                <div className="flex items-start space-x-3">
                  <Badge className="bg-orange-500 text-white">3</Badge>
                  <div>
                    <h3 className="font-semibold">Load Extension</h3>
                    <p className="text-gray-600">Click "Load unpacked" and select the <code className="bg-gray-100 px-2 py-1 rounded">chrome-extension</code> folder</p>
                  </div>
                </div>
                <div className="flex items-start space-x-3">
                  <Badge className="bg-orange-500 text-white">4</Badge>
                  <div>
                    <h3 className="font-semibold">Start Analyzing</h3>
                    <p className="text-gray-600">Click the CyberGuard icon in your browser toolbar on any webpage</p>
                  </div>
                </div>
              </div>
              <div className="bg-gray-50 rounded-lg p-6">
                <h3 className="font-semibold mb-4 flex items-center">
                  <Settings className="w-5 h-5 mr-2" />
                  Extension Folder Location
                </h3>
                <div className="bg-white p-4 rounded border font-mono text-sm">
                  📁 your-project/<br/>
                  &nbsp;&nbsp;📁 chrome-extension/<br/>
                  &nbsp;&nbsp;&nbsp;&nbsp;📄 manifest.json<br/>
                  &nbsp;&nbsp;&nbsp;&nbsp;📄 popup.html<br/>
                  &nbsp;&nbsp;&nbsp;&nbsp;📄 background.js<br/>
                  &nbsp;&nbsp;&nbsp;&nbsp;📄 content.js
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Features */}
        <div className="grid md:grid-cols-3 gap-8 mb-12">
          <Card className="border-orange-200 hover:shadow-lg transition-shadow">
            <CardHeader>
              <CardTitle className="flex items-center text-orange-800">
                <Server className="w-6 h-6 mr-2" />
                IP Analysis
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-gray-600 mb-4">
                Automatically detects and analyzes all IP addresses found on webpages using multiple threat intelligence sources.
              </p>
              <div className="space-y-2">
                <div className="flex items-center text-sm">
                  <CheckCircle className="w-4 h-4 mr-2 text-green-500" />
                  VirusTotal integration
                </div>
                <div className="flex items-center text-sm">
                  <CheckCircle className="w-4 h-4 mr-2 text-green-500" />
                  AbuseIPDB lookup
                </div>
                <div className="flex items-center text-sm">
                  <CheckCircle className="w-4 h-4 mr-2 text-green-500" />
                  Geolocation data
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="border-orange-200 hover:shadow-lg transition-shadow">
            <CardHeader>
              <CardTitle className="flex items-center text-orange-800">
                <Globe className="w-6 h-6 mr-2" />
                Domain Intelligence
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-gray-600 mb-4">
                Scans and evaluates all external domains with comprehensive threat intelligence and reputation scoring.
              </p>
              <div className="space-y-2">
                <div className="flex items-center text-sm">
                  <CheckCircle className="w-4 h-4 mr-2 text-green-500" />
                  Domain reputation
                </div>
                <div className="flex items-center text-sm">
                  <CheckCircle className="w-4 h-4 mr-2 text-green-500" />
                  WHOIS information
                </div>
                <div className="flex items-center text-sm">
                  <CheckCircle className="w-4 h-4 mr-2 text-green-500" />
                  Category analysis
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="border-orange-200 hover:shadow-lg transition-shadow">
            <CardHeader>
              <CardTitle className="flex items-center text-orange-800">
                <Brain className="w-6 h-6 mr-2" />
                AI Security Analysis
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-gray-600 mb-4">
                Advanced AI-powered analysis that provides intelligent security insights and actionable recommendations.
              </p>
              <div className="space-y-2">
                <div className="flex items-center text-sm">
                  <CheckCircle className="w-4 h-4 mr-2 text-green-500" />
                  Risk assessment
                </div>
                <div className="flex items-center text-sm">
                  <CheckCircle className="w-4 h-4 mr-2 text-green-500" />
                  Threat correlation
                </div>
                <div className="flex items-center text-sm">
                  <CheckCircle className="w-4 h-4 mr-2 text-green-500" />
                  Security recommendations
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* How It Works */}
        <Card className="mb-12">
          <CardHeader>
            <CardTitle className="text-2xl text-center">How CyberGuard Works</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid md:grid-cols-4 gap-6">
              <div className="text-center">
                <div className="w-16 h-16 bg-orange-100 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Eye className="w-8 h-8 text-orange-600" />
                </div>
                <h3 className="font-semibold mb-2">1. Scan</h3>
                <p className="text-sm text-gray-600">Automatically extracts IPs and domains from webpage content, scripts, and resources</p>
              </div>
              <div className="text-center">
                <div className="w-16 h-16 bg-orange-100 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Shield className="w-8 h-8 text-orange-600" />
                </div>
                <h3 className="font-semibold mb-2">2. Analyze</h3>
                <p className="text-sm text-gray-600">Queries threat intelligence databases for security information and reputation data</p>
              </div>
              <div className="text-center">
                <div className="w-16 h-16 bg-orange-100 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Brain className="w-8 h-8 text-orange-600" />
                </div>
                <h3 className="font-semibold mb-2">3. AI Process</h3>
                <p className="text-sm text-gray-600">Uses advanced AI to correlate findings and generate intelligent security insights</p>
              </div>
              <div className="text-center">
                <div className="w-16 h-16 bg-orange-100 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Zap className="w-8 h-8 text-orange-600" />
                </div>
                <h3 className="font-semibold mb-2">4. Report</h3>
                <p className="text-sm text-gray-600">Presents clear, actionable security analysis with risk levels and recommendations</p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Status */}
        <Card className="bg-green-50 border-green-200">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <CheckCircle className="w-8 h-8 text-green-600 mr-3" />
                <div>
                  <h3 className="text-lg font-semibold text-green-800">Server Running</h3>
                  <p className="text-green-600">Backend API is active and ready for extension requests</p>
                </div>
              </div>
              <Badge className="bg-green-500 text-white">Ready</Badge>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}