// Popup script for extension interface
class CyberGuardPopup {
    constructor() {
        this.currentTab = 'ips';
        this.scanData = null;
        this.isScanning = false;
        
        this.init();
    }

    async init() {
        this.setupEventListeners();
        this.updateCurrentUrl();
        await this.checkApiStatus();
        await this.loadLastScanData();
    }

    setupEventListeners() {
        // Tab switching
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const tab = e.currentTarget.dataset.tab;
                this.switchTab(tab);
            });
        });

        // Refresh and rescan buttons
        document.getElementById('refresh-btn').addEventListener('click', () => {
            this.rescanPage();
        });

        document.getElementById('rescan-btn').addEventListener('click', () => {
            this.rescanPage();
        });

        // Copy buttons (delegated event listener)
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('copy-btn') || e.target.closest('.copy-btn')) {
                this.copyToClipboard(e);
            }
        });

        // Listen for scan completion
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            if (request.action === 'scanComplete') {
                this.handleScanComplete(request.data);
            }
        });
    }

    async updateCurrentUrl() {
        try {
            const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tabs[0]) {
                const url = new URL(tabs[0].url);
                document.getElementById('current-url').textContent = url.hostname;
            }
        } catch (error) {
            console.error('Error getting current URL:', error);
            document.getElementById('current-url').textContent = 'Unknown';
        }
    }

    switchTab(tabName) {
        // Update tab buttons
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

        // Update tab panels
        document.querySelectorAll('.tab-panel').forEach(panel => {
            panel.classList.remove('active');
        });
        document.getElementById(`${tabName}-tab`).classList.add('active');

        this.currentTab = tabName;
    }

    async rescanPage() {
        if (this.isScanning) return;

        this.isScanning = true;
        this.showScanningState();

        try {
            // Get current tab
            const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
            if (!tabs[0]) {
                throw new Error('No active tab found');
            }

            // Extract network data from content script
            const response = await chrome.tabs.sendMessage(tabs[0].id, {
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

            this.scanData = {
                ...response.data,
                analysis: analysisResponse.data,
                scanTime: Date.now()
            };

            this.updateInterface();
        } catch (error) {
            console.error('Error during rescan:', error);
            this.showError(error.message);
        } finally {
            this.isScanning = false;
            this.hideScanningState();
        }
    }

    async loadLastScanData() {
        try {
            const response = await chrome.runtime.sendMessage({
                action: 'getLastScanData'
            });

            if (response.success && response.data) {
                this.scanData = response.data;
                this.updateInterface();
            }
        } catch (error) {
            console.error('Error loading last scan data:', error);
        }
    }

    handleScanComplete(data) {
        this.scanData = data;
        this.updateInterface();
        this.hideScanningState();
    }

    updateInterface() {
        if (!this.scanData || !this.scanData.analysis) return;

        const { analysis } = this.scanData;
        
        this.updateCounts();
        this.updateIPsList();
        this.updateDomainsList();
        this.updateAIAnalysis();
        this.updateFooter();
    }

    updateCounts() {
        const { analysis } = this.scanData;
        
        // Update IP counts
        document.getElementById('ip-count').textContent = analysis.summary.ips.total;
        document.getElementById('safe-ips').textContent = `${analysis.summary.ips.safe} Safe`;
        document.getElementById('suspicious-ips').textContent = `${analysis.summary.ips.suspicious} Suspicious`;
        document.getElementById('malicious-ips').textContent = `${analysis.summary.ips.malicious} Malicious`;

        // Update domain counts
        document.getElementById('domain-count').textContent = analysis.summary.domains.total;
        document.getElementById('safe-domains').textContent = `${analysis.summary.domains.safe} Safe`;
        document.getElementById('suspicious-domains').textContent = `${analysis.summary.domains.suspicious} Suspicious`;
        document.getElementById('malicious-domains').textContent = `${analysis.summary.domains.malicious} Malicious`;
    }

    updateIPsList() {
        const container = document.getElementById('ip-list');
        const { ips } = this.scanData.analysis;

        if (ips.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-search"></i>
                    <p>No IP addresses detected on this page.</p>
                </div>
            `;
            return;
        }

        container.innerHTML = ips.map(ip => this.createIPCard(ip)).join('');
    }

    updateDomainsList() {
        const container = document.getElementById('domain-list');
        const { domains } = this.scanData.analysis;

        if (domains.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-search"></i>
                    <p>No external domains detected on this page.</p>
                </div>
            `;
            return;
        }

        container.innerHTML = domains.map(domain => this.createDomainCard(domain)).join('');
    }

    updateAIAnalysis() {
        const container = document.getElementById('ai-analysis-content');
        const { aiAnalysis } = this.scanData.analysis;

        if (!aiAnalysis || aiAnalysis.error) {
            container.innerHTML = `
                <div class="error-message">
                    <i class="fas fa-exclamation-triangle"></i>
                    AI analysis failed: ${aiAnalysis?.error || 'Unknown error'}
                </div>
            `;
            return;
        }

        container.innerHTML = this.createAIAnalysisContent(aiAnalysis);
    }

    createIPCard(ip) {
        const statusClass = this.getThreatStatusClass(ip.threat_level);
        const indicatorClass = this.getThreatIndicatorClass(ip.threat_level);
        
        return `
            <div class="item-card">
                <div class="item-header">
                    <div class="item-info">
                        <div class="threat-indicator ${indicatorClass}"></div>
                        <div>
                            <div class="item-address">${ip.ip}</div>
                            <div class="item-location">${ip.location || 'Unknown Location'}</div>
                        </div>
                    </div>
                    <div class="item-actions">
                        <span class="status-badge ${statusClass}">${this.formatThreatLevel(ip.threat_level)}</span>
                        <button class="copy-btn" data-copy="${ip.ip}" title="Copy IP">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                </div>
                <div class="item-details">
                    <div class="details-grid">
                        <div class="detail-item">
                            <span class="detail-label">VirusTotal:</span>
                            <span class="detail-value">${ip.detections}/${ip.total_engines} engines</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">AbuseIPDB:</span>
                            <span class="detail-value">${ip.abuse_confidence || 0}% confidence</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">ASN:</span>
                            <span class="detail-value">${ip.asn || 'Unknown'}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">ISP:</span>
                            <span class="detail-value">${ip.isp || 'Unknown'}</span>
                        </div>
                    </div>
                    ${ip.categories && ip.categories.length > 0 ? `
                        <div class="threat-categories">
                            <div class="category-label">Threat Categories:</div>
                            <div class="category-tags">
                                ${ip.categories.map(cat => `
                                    <span class="category-tag ${this.getCategoryClass(cat)}">${cat}</span>
                                `).join('')}
                            </div>
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
    }

    createDomainCard(domain) {
        const statusClass = this.getThreatStatusClass(domain.threat_level);
        const indicatorClass = this.getThreatIndicatorClass(domain.threat_level);
        
        return `
            <div class="item-card">
                <div class="item-header">
                    <div class="item-info">
                        <div class="threat-indicator ${indicatorClass}"></div>
                        <div>
                            <div class="item-address">${domain.domain}</div>
                            <div class="item-location">${domain.category || 'Unknown Category'}</div>
                        </div>
                    </div>
                    <div class="item-actions">
                        <span class="status-badge ${statusClass}">${this.formatThreatLevel(domain.threat_level)}</span>
                        <button class="copy-btn" data-copy="${domain.domain}" title="Copy Domain">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                </div>
                <div class="item-details">
                    <div class="details-grid">
                        <div class="detail-item">
                            <span class="detail-label">VirusTotal:</span>
                            <span class="detail-value">${domain.detections}/${domain.total_engines} engines</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Registrar:</span>
                            <span class="detail-value">${domain.registrar || 'Unknown'}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Created:</span>
                            <span class="detail-value">${domain.creation_date || 'Unknown'}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Reputation:</span>
                            <span class="detail-value">${domain.reputation || 'Unknown'}</span>
                        </div>
                    </div>
                    ${domain.categories && domain.categories.length > 0 ? `
                        <div class="threat-categories">
                            <div class="category-label">Threat Categories:</div>
                            <div class="category-tags">
                                ${domain.categories.map(cat => `
                                    <span class="category-tag ${this.getCategoryClass(cat)}">${cat}</span>
                                `).join('')}
                            </div>
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
    }

    createAIAnalysisContent(aiAnalysis) {
        const riskClass = this.getRiskBadgeClass(aiAnalysis.risk_level);
        
        return `
            <div class="risk-assessment">
                <div class="risk-header">
                    <div class="risk-title">
                        <i class="fas fa-exclamation-triangle"></i>
                        Risk Assessment
                    </div>
                    <span class="risk-badge ${riskClass}">${aiAnalysis.risk_level?.toUpperCase() || 'UNKNOWN'}</span>
                </div>
                <p class="risk-description">${aiAnalysis.summary || 'No risk assessment available.'}</p>
            </div>

            ${aiAnalysis.findings && aiAnalysis.findings.length > 0 ? `
                <div class="analysis-section">
                    <div class="section-title">
                        <i class="fas fa-search"></i>
                        Key Findings
                    </div>
                    <div class="findings-list">
                        ${aiAnalysis.findings.map(finding => `
                            <div class="finding-item">
                                <div class="finding-indicator ${this.getFindingIndicatorClass(finding.severity)}"></div>
                                <div class="finding-content">
                                    <div class="finding-title">${finding.title}</div>
                                    <div class="finding-description">${finding.description}</div>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            ` : ''}

            ${aiAnalysis.recommendations && aiAnalysis.recommendations.length > 0 ? `
                <div class="analysis-section">
                    <div class="section-title">
                        <i class="fas fa-lightbulb"></i>
                        Recommendations
                    </div>
                    <div class="recommendations-list">
                        ${aiAnalysis.recommendations.map(rec => `
                            <div class="recommendation-item">
                                <i class="fas fa-check-circle"></i>
                                <div class="recommendation-text">${rec}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            ` : ''}

            <div class="analysis-metadata">
                <div class="metadata-grid">
                    <div class="metadata-item">
                        <span>Analysis Date:</span>
                        <span class="metadata-value">${new Date().toLocaleString()}</span>
                    </div>
                    <div class="metadata-item">
                        <span>Model:</span>
                        <span class="metadata-value">GPT-4o</span>
                    </div>
                    <div class="metadata-item">
                        <span>Confidence:</span>
                        <span class="metadata-value success">${aiAnalysis.confidence || 0}%</span>
                    </div>
                    <div class="metadata-item">
                        <span>Processing Time:</span>
                        <span class="metadata-value">${aiAnalysis.processing_time || 'N/A'}</span>
                    </div>
                </div>
            </div>
        `;
    }

    async checkApiStatus() {
        try {
            const response = await chrome.runtime.sendMessage({
                action: 'checkApiStatus'
            });

            if (response.success) {
                this.updateApiStatus(response.status);
            } else {
                this.updateApiStatus({ virustotal: false, abuseipdb: false, openai: false });
            }
        } catch (error) {
            console.error('Error checking API status:', error);
            this.updateApiStatus({ virustotal: false, abuseipdb: false, openai: false });
        }
    }

    updateApiStatus(status) {
        const statusDot = document.getElementById('api-status-dot');
        const statusText = document.getElementById('api-status-text');
        
        const allOnline = status.virustotal && status.abuseipdb && status.openai;
        const someOnline = status.virustotal || status.abuseipdb || status.openai;
        
        if (allOnline) {
            statusDot.className = 'status-dot online';
            statusText.textContent = 'Online';
        } else if (someOnline) {
            statusDot.className = 'status-dot checking';
            statusText.textContent = 'Partial';
        } else {
            statusDot.className = 'status-dot offline';
            statusText.textContent = 'Offline';
        }
    }

    updateFooter() {
        if (this.scanData && this.scanData.scanTime) {
            const timeAgo = this.getTimeAgo(this.scanData.scanTime);
            document.getElementById('last-scan-time').textContent = timeAgo;
            document.getElementById('ip-last-scan').textContent = `Last scan: ${timeAgo}`;
            document.getElementById('domain-last-scan').textContent = `Last scan: ${timeAgo}`;
            document.getElementById('analysis-last-scan').textContent = `Analyzed: ${timeAgo}`;
        }
    }

    showScanningState() {
        document.getElementById('loading-spinner').classList.remove('hidden');
        document.getElementById('scan-status-text').textContent = 'Scanning page...';
        
        const rescanBtn = document.getElementById('rescan-btn');
        rescanBtn.disabled = true;
        rescanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
    }

    hideScanningState() {
        document.getElementById('loading-spinner').classList.add('hidden');
        document.getElementById('scan-status-text').textContent = 'Scan complete';
        
        const rescanBtn = document.getElementById('rescan-btn');
        rescanBtn.disabled = false;
        rescanBtn.innerHTML = '<i class="fas fa-redo-alt"></i> Rescan';
    }

    showError(message) {
        // You could add a toast or modal here
        console.error('Extension error:', message);
        alert(`Error: ${message}`);
    }

    async copyToClipboard(event) {
        const button = event.target.closest('.copy-btn');
        const text = button.dataset.copy;
        
        try {
            await navigator.clipboard.writeText(text);
            
            // Show visual feedback
            const icon = button.querySelector('i');
            const originalClass = icon.className;
            icon.className = 'fas fa-check';
            
            setTimeout(() => {
                icon.className = originalClass;
            }, 1000);
        } catch (error) {
            console.error('Failed to copy to clipboard:', error);
        }
    }

    // Helper methods
    getThreatStatusClass(threatLevel) {
        switch (threatLevel) {
            case 'safe': return 'safe';
            case 'suspicious': return 'warning';
            case 'malicious': return 'danger';
            default: return 'warning';
        }
    }

    getThreatIndicatorClass(threatLevel) {
        switch (threatLevel) {
            case 'safe': return 'safe';
            case 'suspicious': return 'warning';
            case 'malicious': return 'danger';
            default: return 'warning';
        }
    }

    formatThreatLevel(threatLevel) {
        switch (threatLevel) {
            case 'safe': return 'Clean';
            case 'suspicious': return 'Suspicious';
            case 'malicious': return 'Malicious';
            default: return 'Unknown';
        }
    }

    getCategoryClass(category) {
        if (category.toLowerCase().includes('malware') || 
            category.toLowerCase().includes('phishing') ||
            category.toLowerCase().includes('trojan')) {
            return 'danger';
        }
        return 'warning';
    }

    getRiskBadgeClass(riskLevel) {
        switch (riskLevel?.toLowerCase()) {
            case 'high': return 'high';
            case 'medium': return 'medium';
            case 'low': return 'low';
            default: return 'medium';
        }
    }

    getFindingIndicatorClass(severity) {
        switch (severity?.toLowerCase()) {
            case 'high': return 'danger';
            case 'medium': return 'warning';
            case 'low': return 'info';
            default: return 'info';
        }
    }

    getTimeAgo(timestamp) {
        const now = Date.now();
        const diff = now - timestamp;
        const minutes = Math.floor(diff / 60000);
        const hours = Math.floor(diff / 3600000);
        
        if (minutes < 1) return 'Just now';
        if (minutes < 60) return `${minutes} min ago`;
        if (hours < 24) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
        return new Date(timestamp).toLocaleDateString();
    }
}

// Initialize popup when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new CyberGuardPopup();
});
