// Popup script for extension interface
class CyberScanAIPopup {
    constructor() {
        this.currentTab = 'ips';
        this.scanData = null;
        this.isScanning = false;
        
        this.init();
    }

    async init() {
        this.setupEventListeners();
        // this.updateCurrentUrl();  // Commented out as not needed
        await this.checkApiStatus();
        await this.loadLastScanData();
        
        // Automatically start scanning when popup opens
        console.log('Scanning page for threats...');
        await this.rescanPage();
    }

    setupEventListeners() {
        // Tab navigation
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const tabName = e.currentTarget.dataset.tab;
                this.switchTab(tabName);
            });
        });

        // Refresh button
        const refreshBtn = document.getElementById('refresh-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                this.rescanPage();
            });
        }

        // Settings button
        const settingsBtn = document.getElementById('settings-btn');
        if (settingsBtn) {
            settingsBtn.addEventListener('click', () => {
                this.openSettings();
            });
        }

        // Start AI Analysis button
        const startAIAnalysisBtn = document.getElementById('start-ai-analysis');
        if (startAIAnalysisBtn) {
            startAIAnalysisBtn.addEventListener('click', () => {
                this.startAIAnalysis();
            });
        }

        // Settings modal event listeners
        this.setupSettingsListeners();

        // Copy button handlers
        document.addEventListener('click', (e) => {
            if (e.target.closest('.copy-btn')) {
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

    setupSettingsListeners() {
        // Close modal buttons
        document.getElementById('close-settings')?.addEventListener('click', () => {
            this.closeSettings();
        });
        
        document.getElementById('cancel-settings')?.addEventListener('click', () => {
            this.closeSettings();
        });

        // Save settings button
        document.getElementById('save-settings')?.addEventListener('click', () => {
            this.saveSettings();
        });

        // Toggle password visibility buttons
        document.querySelectorAll('.toggle-visibility').forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.togglePasswordVisibility(e.target.closest('.toggle-visibility').dataset.target);
            });
        });

        // Close modal when clicking outside
        document.getElementById('settings-modal')?.addEventListener('click', (e) => {
            if (e.target.id === 'settings-modal') {
                this.closeSettings();
            }
        });

        // Escape key to close modal
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && document.getElementById('settings-modal').classList.contains('show')) {
                this.closeSettings();
            }
        });
    }

    // Commented out as not needed
    /*
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
    */

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
        const ipCount = document.getElementById('ip-count');
        if (ipCount) {
            ipCount.textContent = analysis.summary.ips.total;
        }
        
        const safeIPs = document.getElementById('safe-ips');
        if (safeIPs) {
            safeIPs.textContent = `${analysis.summary.ips.safe} Safe`;
        }
        
        const suspiciousIPs = document.getElementById('suspicious-ips');
        if (suspiciousIPs) {
            suspiciousIPs.textContent = `${analysis.summary.ips.suspicious} Suspicious`;
        }
        
        const maliciousIPs = document.getElementById('malicious-ips');
        if (maliciousIPs) {
            maliciousIPs.textContent = `${analysis.summary.ips.malicious} Malicious`;
        }

        // Update domain counts
        const domainCount = document.getElementById('domain-count');
        if (domainCount) {
            domainCount.textContent = analysis.summary.domains.total;
        }
        
        const safeDomains = document.getElementById('safe-domains');
        if (safeDomains) {
            safeDomains.textContent = `${analysis.summary.domains.safe} Safe`;
        }
        
        const suspiciousDomains = document.getElementById('suspicious-domains');
        if (suspiciousDomains) {
            suspiciousDomains.textContent = `${analysis.summary.domains.suspicious} Suspicious`;
        }
        
        const maliciousDomains = document.getElementById('malicious-domains');
        if (maliciousDomains) {
            maliciousDomains.textContent = `${analysis.summary.domains.malicious} Malicious`;
        }
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

        // Sort IPs by threat level: Malicious → Suspicious → Clean
        const sortedIPs = ips.sort((a, b) => {
            const threatOrder = { 'malicious': 0, 'suspicious': 1, 'safe': 2, 'unknown': 3 };
            return threatOrder[a.threat_level] - threatOrder[b.threat_level];
        });

        container.innerHTML = sortedIPs.map(ip => this.createIPCard(ip)).join('');
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

        // Sort domains by threat level: Malicious → Suspicious → Clean
        const sortedDomains = domains.sort((a, b) => {
            const threatOrder = { 'malicious': 0, 'suspicious': 1, 'safe': 2, 'unknown': 3 };
            return threatOrder[a.threat_level] - threatOrder[b.threat_level];
        });

        container.innerHTML = sortedDomains.map(domain => this.createDomainCard(domain)).join('');
    }

    updateAIAnalysis() {
        const { analysis } = this.scanData;
        const content = document.getElementById('ai-analysis-content');
        const startButton = document.getElementById('start-ai-analysis');
        const loading = document.getElementById('ai-analysis-loading');
        
        if (!content) return;
        
        if (analysis.aiAnalysis) {
            // Show AI analysis results
            if (analysis.aiAnalysis.error) {
                const errorMessage = analysis.aiAnalysis.error;
                const isApiKeyError = errorMessage.includes('API key') || errorMessage.includes('401') || errorMessage.includes('Invalid');
                
                content.innerHTML = `
                    <div class="error-message">
                        <i class="fas fa-exclamation-triangle"></i>
                        <div class="error-content">
                            <div class="error-title">AI analysis failed</div>
                            <div class="error-description">${errorMessage}</div>
                            ${isApiKeyError ? `
                                <button class="settings-button" onclick="cyberScanAIPopup.openSettings()">
                                    <i class="fas fa-cog"></i>
                                    Configure Anthropic API Key
                                </button>
                            ` : ''}
                        </div>
                    </div>
                `;
            } else {
                content.innerHTML = this.createAIAnalysisContent(analysis.aiAnalysis);
            }
            
            // Hide button and loading, show results
            if (startButton) startButton.style.display = 'none';
            if (loading) loading.style.display = 'none';
            
            // Update last scan time
            const lastScan = document.getElementById('analysis-last-scan');
            if (lastScan) {
                lastScan.textContent = `Analyzed: ${this.getTimeAgo(this.scanData.scanTime)}`;
            }
        } else if (analysis && (analysis.ips?.length > 0 || analysis.domains?.length > 0)) {
            // Show button to start AI analysis
            content.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-brain"></i>
                    <p>Threat intelligence data is ready. Click "Start AI Analysis" to get AI-powered security insights.</p>
                </div>
            `;
            if (startButton) startButton.style.display = 'block';
            if (loading) loading.style.display = 'none';
        } else {
            // No scan data yet
            content.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-brain"></i>
                    <p>No analysis available yet. First scan the page for IPs and domains, then click "Start AI Analysis" for AI-powered threat insights.</p>
                </div>
            `;
            if (startButton) startButton.style.display = 'none';
            if (loading) loading.style.display = 'none';
        }
    }

    async startAIAnalysis() {
        if (!this.scanData || !this.scanData.analysis) {
            this.showError('No scan data available. Please scan the page first.');
            return;
        }

        const startButton = document.getElementById('start-ai-analysis');
        const loading = document.getElementById('ai-analysis-loading');
        const content = document.getElementById('ai-analysis-content');

        try {
            // Show loading state
            if (startButton) startButton.style.display = 'none';
            if (loading) loading.style.display = 'flex';

            // Send request to background script
            const response = await chrome.runtime.sendMessage({
                action: 'startAIAnalysis',
                data: this.scanData
            });

            if (!response.success) {
                throw new Error(response.error || 'AI analysis failed');
            }

            // Update scan data with AI analysis
            this.scanData.analysis.aiAnalysis = response.data;

            // Update the interface
            this.updateAIAnalysis();

        } catch (error) {
            console.error('Error during AI analysis:', error);
            
            // Hide loading and show button again
            if (loading) loading.style.display = 'none';
            if (startButton) startButton.style.display = 'block';
            
            // Show error in the content area
            if (content) {
                content.innerHTML = `
                    <div class="error-message">
                        <i class="fas fa-exclamation-triangle"></i>
                        <div class="error-content">
                            <div class="error-title">AI Analysis Failed</div>
                            <div class="error-description">${error.message}</div>
                        </div>
                    </div>
                `;
            }
        }
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
                            <span class="detail-label">Country:</span>
                            <span class="detail-value">${ip.whois_country || ip.location || 'Unknown'}</span>
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
                            <span class="detail-label">Country:</span>
                            <span class="detail-value">${domain.whois_country || 'Unknown'}</span>
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

            <div class="ai-disclaimer">
                <div class="disclaimer-grid">
                    <div class="disclaimer-item">
                        <i class="fas fa-exclamation-triangle"></i>
                        Disclaimer: AI-generated results may be limited in scope and could contain inaccuracies or misleading information. Use with discretion.
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
                this.updateApiStatus({ virustotal: false, abuseipdb: false, anthropic: false });
            }
        } catch (error) {
            console.error('Error checking API status:', error);
            this.updateApiStatus({ virustotal: false, abuseipdb: false, anthropic: false });
        }
    }

    updateApiStatus(status) {
        const statusDot = document.getElementById('api-status-dot');
        const statusText = document.getElementById('api-status-text');
        
        if (!statusDot || !statusText) return;
        
        const allOnline = status.virustotal && status.abuseipdb && status.anthropic;
        const someOnline = status.virustotal || status.abuseipdb || status.anthropic;
        
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
            
            const lastScanTime = document.getElementById('last-scan-time');
            if (lastScanTime) {
                lastScanTime.textContent = timeAgo;
            }
            
            const ipLastScan = document.getElementById('ip-last-scan');
            if (ipLastScan) {
                ipLastScan.textContent = `Last scan: ${timeAgo}`;
            }
            
            const domainLastScan = document.getElementById('domain-last-scan');
            if (domainLastScan) {
                domainLastScan.textContent = `Last scan: ${timeAgo}`;
            }
            
            const analysisLastScan = document.getElementById('analysis-last-scan');
            if (analysisLastScan) {
                analysisLastScan.textContent = `Analyzed: ${timeAgo}`;
            }
        }
    }

    showScanningState() {
        const loadingSpinner = document.getElementById('loading-spinner');
        if (loadingSpinner) {
            loadingSpinner.classList.remove('hidden');
        }
        
        const scanStatusText = document.getElementById('scan-status-text');
        if (scanStatusText) {
            scanStatusText.textContent = 'Scanning page...';
        }
        
        const rescanBtn = document.getElementById('rescan-btn');
        if (rescanBtn) {
            rescanBtn.disabled = true;
            rescanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
        }
    }

    hideScanningState() {
        const loadingSpinner = document.getElementById('loading-spinner');
        if (loadingSpinner) {
            loadingSpinner.classList.add('hidden');
        }
        
        const scanStatusText = document.getElementById('scan-status-text');
        if (scanStatusText) {
            scanStatusText.textContent = 'Scan complete';
        }
        
        const rescanBtn = document.getElementById('rescan-btn');
        if (rescanBtn) {
            rescanBtn.disabled = false;
            rescanBtn.innerHTML = '<i class="fas fa-redo-alt"></i> Rescan';
        }
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
        if (!timestamp) return 'Never';
        
        const now = Date.now();
        const diff = now - timestamp;
        const minutes = Math.floor(diff / (1000 * 60));
        const hours = Math.floor(diff / (1000 * 60 * 60));
        const days = Math.floor(diff / (1000 * 60 * 60 * 24));
        
        if (minutes < 1) return 'Just now';
        if (minutes < 60) return `${minutes}m ago`;
        if (hours < 24) return `${hours}h ago`;
        return `${days}d ago`;
    }

    // Settings Modal Methods
    async openSettings() {
        const modal = document.getElementById('settings-modal');
        if (!modal) return;

        // Load current API keys
        await this.loadApiKeys();
        
        // Show modal with animation
        modal.classList.add('show');
        
        // Focus first input
        const firstInput = document.getElementById('virustotal-key');
        if (firstInput) {
            setTimeout(() => firstInput.focus(), 100);
        }
    }

    closeSettings() {
        const modal = document.getElementById('settings-modal');
        if (!modal) return;

        modal.classList.remove('show');
        
        // Clear all inputs for security
        document.getElementById('virustotal-key').value = '';
        document.getElementById('abuseipdb-key').value = '';
        document.getElementById('anthropic-key').value = '';
        
        // Reset all password fields to hidden
        this.resetPasswordVisibility();
    }

    async loadApiKeys() {
        try {
            const result = await chrome.storage.local.get(['apiKeys']);
            const apiKeys = result.apiKeys || {};
            
            document.getElementById('virustotal-key').value = apiKeys.virustotal || '';
            document.getElementById('abuseipdb-key').value = apiKeys.abuseipdb || '';
            document.getElementById('anthropic-key').value = apiKeys.anthropic || '';
        } catch (error) {
            console.error('Error loading API keys:', error);
        }
    }

    async saveSettings() {
        const virustotalKey = document.getElementById('virustotal-key').value.trim();
        const abuseipdbKey = document.getElementById('abuseipdb-key').value.trim();
        const anthropicKey = document.getElementById('anthropic-key').value.trim();

        // Validate at least one API key is provided
        if (!virustotalKey && !abuseipdbKey && !anthropicKey) {
            this.showSettingsError('Please provide at least one API key.');
            return;
        }

        try {
            // Save to Chrome storage
            await chrome.storage.local.set({
                apiKeys: {
                    virustotal: virustotalKey,
                    abuseipdb: abuseipdbKey,
                    anthropic: anthropicKey
                }
            });

            // Notify background script of new keys
            chrome.runtime.sendMessage({
                action: 'updateApiKeys',
                keys: {
                    virustotal: virustotalKey,
                    abuseipdb: abuseipdbKey,
                    anthropic: anthropicKey
                }
            });

            this.showSettingsSuccess('API keys saved successfully!');
            
            // Close modal after brief delay
            setTimeout(() => {
                this.closeSettings();
                // Refresh API status
                this.checkApiStatus();
            }, 1500);

        } catch (error) {
            console.error('Error saving API keys:', error);
            this.showSettingsError('Failed to save API keys. Please try again.');
        }
    }

    togglePasswordVisibility(targetId) {
        const input = document.getElementById(targetId);
        const button = document.querySelector(`[data-target="${targetId}"]`);
        const icon = button.querySelector('i');
        
        if (input.type === 'password') {
            input.type = 'text';
            icon.className = 'fas fa-eye-slash';
        } else {
            input.type = 'password';
            icon.className = 'fas fa-eye';
        }
    }

    resetPasswordVisibility() {
        const inputs = ['virustotal-key', 'abuseipdb-key', 'anthropic-key'];
        inputs.forEach(id => {
            const input = document.getElementById(id);
            const button = document.querySelector(`[data-target="${id}"]`);
            const icon = button?.querySelector('i');
            
            if (input) input.type = 'password';
            if (icon) icon.className = 'fas fa-eye';
        });
    }

    showSettingsSuccess(message) {
        this.showSettingsMessage(message, 'success');
    }

    showSettingsError(message) {
        this.showSettingsMessage(message, 'error');
    }

    showSettingsMessage(message, type) {
        // Remove any existing messages
        const existingMessage = document.querySelector('.settings-message');
        if (existingMessage) {
            existingMessage.remove();
        }

        // Create new message element
        const messageDiv = document.createElement('div');
        messageDiv.className = `settings-message ${type}`;
        messageDiv.innerHTML = `
            <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-triangle'}"></i>
            ${message}
        `;

        // Insert before modal footer
        const modalFooter = document.querySelector('.modal-footer');
        modalFooter.parentNode.insertBefore(messageDiv, modalFooter);

        // Auto-remove after 3 seconds
        setTimeout(() => {
            if (messageDiv.parentNode) {
                messageDiv.remove();
            }
        }, 3000);
    }
}

// Initialize popup when DOM is loaded
let cyberScanAIPopup;
document.addEventListener('DOMContentLoaded', () => {
    cyberScanAIPopup = new CyberScanAIPopup();
});
