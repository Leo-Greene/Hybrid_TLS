// TLS握手演示前端逻辑

class TLSHandshakeDemo {
    constructor() {
        this.currentMode = 'hybrid';
        this.currentCertMode = 'by_val';
        this.currentAlgorithm = 'mldsa65';
        this.apiBase = '/api';
        
        this.init();
    }
    
    init() {
        try {
            // 绑定事件
            const btnExecute = document.getElementById('btn-execute');
            if (btnExecute) {
                btnExecute.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    this.executeHandshake();
                });
                console.log('[初始化] 绑定btn-execute成功');
            } else {
                console.warn('[初始化] btn-execute元素不存在');
            }
            
            const btnCompare = document.getElementById('btn-compare');
            if (btnCompare) {
                btnCompare.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    this.compareModes();
                });
                console.log('[初始化] 绑定btn-compare成功');
            } else {
                console.warn('[初始化] btn-compare元素不存在');
            }
            
            const btnBandwidth = document.getElementById('btn-generate-bandwidth-chart');
            if (btnBandwidth) {
                btnBandwidth.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    this.generateBandwidthChart();
                });
                console.log('[初始化] 绑定btn-generate-bandwidth-chart成功');
            } else {
                console.warn('[初始化] btn-generate-bandwidth-chart元素不存在');
            }
            
            const btnCompareAlgorithms = document.getElementById('btn-compare-algorithms');
            if (btnCompareAlgorithms) {
                btnCompareAlgorithms.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    this.compareAlgorithms();
                });
                console.log('[初始化] 绑定btn-compare-algorithms成功');
            } else {
                console.warn('[初始化] btn-compare-algorithms元素不存在');
            }
            
            // 页面标签页切换
            const pageTabs = document.querySelectorAll('.page-tab');
            console.log(`[初始化] 找到${pageTabs.length}个页面标签`);
            pageTabs.forEach((tab, index) => {
                tab.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    const pageName = e.target.dataset.page || (e.target.closest && e.target.closest('.page-tab') ? e.target.closest('.page-tab').dataset.page : null);
                    console.log(`[标签点击] 标签${index}, pageName: ${pageName}`);
                    if (pageName) {
                        this.switchPage(pageName);
                    }
                });
                // 确保标签可以点击
                tab.style.cursor = 'pointer';
                tab.style.pointerEvents = 'auto';
            });
        } catch (error) {
            console.error('[初始化] 初始化错误:', error);
        }
        
        // 基准测试页面不再需要标签页切换，已移除
    }
    
    async executeHandshake() {
        const mode = document.getElementById('tls-mode').value;
        const certMode = document.getElementById('cert-mode').value;
        const algorithm = document.getElementById('algorithm').value;
        
        this.showLoading(true);
        this.updateStatus('执行中', 'warning');
        
        try {
            const response = await fetch(`${this.apiBase}/handshake/execute`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    mode: mode,
                    cert_mode: certMode,
                    algorithm: algorithm,
                })
            });
            
            if (!response.ok) {
                let errorMessage = '握手失败';
                try {
                    const error = await response.json();
                    errorMessage = error.detail || error.message || JSON.stringify(error);
                } catch (e) {
                    errorMessage = `HTTP ${response.status}: ${response.statusText}`;
                }
                throw new Error(errorMessage);
            }
            
            const data = await response.json();
            
            if (data.success) {
                this.displayResult(data);
                this.showToast('握手执行成功！', 'success');
                this.updateStatus('成功', 'success');
            } else {
                throw new Error(data.error || '握手失败');
            }
        } catch (error) {
            console.error('握手执行错误:', error);
            const errorMsg = error.message || String(error);
            this.showToast('握手执行失败: ' + errorMsg, 'error');
            this.updateStatus('失败', 'error');
        } finally {
            this.showLoading(false);
        }
    }
    
    async compareModes() {
        const compareTlsModeEl = document.getElementById('compare-tls-mode');
        const tlsModeEl = document.getElementById('tls-mode');
        const mode = (compareTlsModeEl && compareTlsModeEl.value) || (tlsModeEl && tlsModeEl.value);
        const compareAlgoEl = document.getElementById('compare-algorithm');
        const algoEl = document.getElementById('algorithm');
        const algorithm = (compareAlgoEl && compareAlgoEl.value) || (algoEl && algoEl.value);
        const runCountEl = document.getElementById('run-count');
        const runs = parseInt((runCountEl && runCountEl.value) || '3');
        const networkConditionEl = document.getElementById('network-condition');
        const networkCondition = (networkConditionEl && networkConditionEl.value) || 'loopback';
        const networkBandwidthEl = document.getElementById('network-bandwidth');
        const networkBandwidth = parseFloat((networkBandwidthEl && networkBandwidthEl.value) || '10');
        
        this.showLoading(true);
        this.updateStatus('对比中', 'warning');
        
        try {
            // 执行by_val和by_ref对比
            const response = await fetch(`${this.apiBase}/compare-modes`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    mode: mode,
                    algorithm: algorithm,
                    runs: runs,
                    network_condition: networkCondition,
                    network_bandwidth_mbps: networkBandwidth
                })
            });
            
            if (!response.ok) {
                let errorMessage = '对比失败';
                try {
                    const error = await response.json();
                    errorMessage = error.detail || error.message || JSON.stringify(error);
                } catch (e) {
                    errorMessage = `HTTP ${response.status}: ${response.statusText}`;
                }
                throw new Error(errorMessage);
            }
            
            const data = await response.json();
            
            if (data.success) {
                this.displayComparison(data);
                const runMsg = data.runs && data.runs > 1 ? `（${data.runs}次平均值）` : '';
                this.showToast(`模式对比完成${runMsg}！`, 'success');
                this.updateStatus('成功', 'success');
            } else {
                throw new Error('对比失败');
            }
        } catch (error) {
            console.error('对比错误:', error);
            const errorMsg = error.message || String(error);
            this.showToast('模式对比失败: ' + errorMsg, 'error');
            this.updateStatus('失败', 'error');
        } finally {
            this.showLoading(false);
        }
    }
    
    async loadBenchmarkData() {
        const benchmarkContent = document.getElementById('benchmark-content');
        if (!benchmarkContent) {
            console.error('基准测试内容容器不存在');
            return;
        }
        
        // 显示加载状态
        benchmarkContent.innerHTML = '<div class="loading-placeholder">正在加载基准测试图片...</div>';
        
        // 直接加载所有图片，不区分模式
        try {
            const response = await fetch(`${this.apiBase}/images/list`);
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const imageData = await response.json();
            
            if (imageData.success && imageData.images && imageData.images.length > 0) {
                // 显示图片画廊，一行至少两个图片
                let html = '<div class="image-grid">';
                imageData.images.forEach(img => {
                    html += 
                        '<div class="image-card" onclick="window.open(\'' + img.path + '\', \'_blank\')">' +
                        '<img src="' + img.path + '" alt="' + (img.title || '') + '" loading="lazy">' +
                        '<div class="image-card-title">' + (img.title || '') + '</div>' +
                        '</div>';
                });
                html += '</div>';
                benchmarkContent.innerHTML = html;
            } else {
                benchmarkContent.innerHTML = 
                    '<div class="loading-placeholder">暂无基准测试图片<br>请将PNG图片放置在 frontend/static/plots/ 目录中</div>';
            }
        } catch (error) {
            console.error('加载图片失败:', error);
            benchmarkContent.innerHTML = 
                '<div class="loading-placeholder">加载图片失败: ' + (error.message || '未知错误') + '</div>';
        }
    }
    
    displayResult(data) {
        document.getElementById('result-section').style.display = 'block';
        
        // 计算实际的TLS握手时间（包含所有握手步骤）
        let handshakeTime = data.total_time;
        if (data.timing && data.timing.steps) {
            const excludedSteps = [
                '证书服务器检查', '服务器线程启动', '等待服务器就绪', 
                '客户端初始化', '建立TCP连接', '清理连接', '等待服务器完成',
                '服务器Socket初始化', 'TLS服务器初始化', '等待客户端连接'
            ];
            let calculatedTime = 0;
            data.timing.steps.forEach(step => {
                if (!excludedSteps.includes(step.step_name)) {
                    calculatedTime += step.duration_ms || 0;
                }
            });
            // 如果找到了total_handshake_time_ms，使用它
            const handshakeStep = data.timing.steps.find(step => step.step_name === 'TLS握手执行');
            if (handshakeStep && handshakeStep.details && handshakeStep.details.total_handshake_time_ms) {
                handshakeTime = handshakeStep.details.total_handshake_time_ms;
            } else {
                handshakeTime = calculatedTime;
            }
        }
        
        document.getElementById('result-time').textContent = handshakeTime.toFixed(2);
        document.getElementById('result-messages').textContent = data.total_messages;
        document.getElementById('result-size').textContent = data.total_size.toLocaleString();
        
        // 计算证书大小
        const certSize = data.server_to_client_size - 250 - 500 - 36; // 减去ServerHello、CertificateVerify、Finished的估算大小
        document.getElementById('result-cert-size').textContent = certSize > 0 ? certSize.toLocaleString() : '-';
        
        // 显示资源消耗监控
        if (data.resources) {
            this.displayResourceMonitoring(data.resources);
        } else {
            const resourceSection = document.getElementById('resource-monitoring');
            if (resourceSection) {
                resourceSection.style.display = 'none';
            }
        }
        
        // 显示时间分析（by_val和by_ref都显示）
        if (data.timing) {
            this.displayTimingAnalysis(data.timing, data.cert_mode);
        }
    }
    
    displayResourceMonitoring(resources) {
        const resourceSection = document.getElementById('resource-monitoring');
        if (!resourceSection) {
            return;
        }
        
        resourceSection.style.display = 'block';
        
        // 显示CPU使用率
        if (resources.cpu) {
            const cpuAvgEl = document.getElementById('resource-cpu-avg');
            const cpuMaxEl = document.getElementById('resource-cpu-max');
            
            if (cpuAvgEl) {
                cpuAvgEl.textContent = resources.cpu.avg_percent !== undefined ? 
                    resources.cpu.avg_percent.toFixed(2) : '-';
            }
            if (cpuMaxEl) {
                cpuMaxEl.textContent = resources.cpu.max_percent !== undefined ? 
                    resources.cpu.max_percent.toFixed(2) : '-';
            }
        }
        
        // 显示内存使用
        if (resources.memory) {
            const memoryAvgEl = document.getElementById('resource-memory-avg');
            const memoryMaxEl = document.getElementById('resource-memory-max');
            
            if (memoryAvgEl) {
                memoryAvgEl.textContent = resources.memory.avg_mb !== undefined ? 
                    resources.memory.avg_mb.toFixed(2) : '-';
            }
            if (memoryMaxEl) {
                memoryMaxEl.textContent = resources.memory.max_mb !== undefined ? 
                    resources.memory.max_mb.toFixed(2) : '-';
            }
        }
    }
    
    displayComparisonResources(resources, prefix) {
        const resourceSection = document.getElementById(prefix + '-resources');
        if (!resourceSection) {
            return;
        }
        
        resourceSection.style.display = 'block';
        
        // 显示CPU使用率
        if (resources.cpu) {
            const cpuAvgEl = document.getElementById(prefix + '-cpu-avg');
            const cpuMaxEl = document.getElementById(prefix + '-cpu-max');
            
            if (cpuAvgEl) {
                cpuAvgEl.textContent = resources.cpu.avg_percent !== undefined ? 
                    resources.cpu.avg_percent.toFixed(2) : '-';
            }
            if (cpuMaxEl) {
                cpuMaxEl.textContent = resources.cpu.max_percent !== undefined ? 
                    resources.cpu.max_percent.toFixed(2) : '-';
            }
        }
        
        // 显示内存使用
        if (resources.memory) {
            const memoryAvgEl = document.getElementById(prefix + '-memory-avg');
            const memoryMaxEl = document.getElementById(prefix + '-memory-max');
            
            if (memoryAvgEl) {
                memoryAvgEl.textContent = resources.memory.avg_mb !== undefined ? 
                    resources.memory.avg_mb.toFixed(2) : '-';
            }
            if (memoryMaxEl) {
                memoryMaxEl.textContent = resources.memory.max_mb !== undefined ? 
                    resources.memory.max_mb.toFixed(2) : '-';
            }
        }
    }
    
    alignComparisonSections() {
        // 对齐整个section-item容器（这是最可靠的方法）
        const byvalSections = document.querySelectorAll('.comparison-card-item:first-child .comparison-section-item');
        const byrefSections = document.querySelectorAll('.comparison-card-item:last-child .comparison-section-item');
        
        if (byvalSections.length === byrefSections.length && byvalSections.length > 0) {
            // 重置之前设置的高度
            byvalSections.forEach(section => {
                section.style.minHeight = '';
            });
            byrefSections.forEach(section => {
                section.style.minHeight = '';
            });
            
            // 等待一帧，确保DOM已更新
            requestAnimationFrame(() => {
                // 对齐每个对应的section
                for (let i = 0; i < byvalSections.length; i++) {
                    const byvalSection = byvalSections[i];
                    const byrefSection = byrefSections[i];
                    
                    // 获取实际高度
                    const byvalHeight = byvalSection.offsetHeight;
                    const byrefHeight = byrefSection.offsetHeight;
                    const maxHeight = Math.max(byvalHeight, byrefHeight);
                    
                    // 设置相同的最小高度
                    if (maxHeight > 0) {
                        byvalSection.style.minHeight = maxHeight + 'px';
                        byrefSection.style.minHeight = maxHeight + 'px';
                    }
                }
            });
        }
        
        // 单独对齐内容区域（作为补充）
        // 对齐时间分析部分
        const byvalTiming = document.getElementById('byval-timing-breakdown');
        const byrefTiming = document.getElementById('byref-timing-breakdown');
        if (byvalTiming && byrefTiming) {
            requestAnimationFrame(() => {
                const maxHeight = Math.max(byvalTiming.offsetHeight, byrefTiming.offsetHeight);
                if (maxHeight > 0) {
                    byvalTiming.style.minHeight = maxHeight + 'px';
                    byrefTiming.style.minHeight = maxHeight + 'px';
                }
            });
        }
        
        // 对齐消息大小分析部分
        const byvalSize = document.getElementById('byval-size-breakdown');
        const byrefSize = document.getElementById('byref-size-breakdown');
        if (byvalSize && byrefSize) {
            requestAnimationFrame(() => {
                const maxHeight = Math.max(byvalSize.offsetHeight, byrefSize.offsetHeight);
                if (maxHeight > 0) {
                    byvalSize.style.minHeight = maxHeight + 'px';
                    byrefSize.style.minHeight = maxHeight + 'px';
                }
            });
        }
        
        // 对齐资源消耗部分
        const byvalResources = document.getElementById('byval-resources');
        const byrefResources = document.getElementById('byref-resources');
        if (byvalResources && byrefResources) {
            const byvalDisplay = byvalResources.style.display !== 'none';
            const byrefDisplay = byrefResources.style.display !== 'none';
            
            if (byvalDisplay || byrefDisplay) {
                requestAnimationFrame(() => {
                    // 如果只有一个显示，确保另一个也显示（但内容为空）
                    if (byvalDisplay && !byrefDisplay) {
                        byrefResources.style.display = 'block';
                    } else if (!byvalDisplay && byrefDisplay) {
                        byvalResources.style.display = 'block';
                    }
                    
                    const maxHeight = Math.max(byvalResources.offsetHeight, byrefResources.offsetHeight);
                    if (maxHeight > 0) {
                        byvalResources.style.minHeight = maxHeight + 'px';
                        byrefResources.style.minHeight = maxHeight + 'px';
                    }
                });
            }
        }
    }
    
    displayTimingAnalysis(timing, certMode) {
        // 查找或创建时间分析容器
        let timingContainer = document.getElementById('timing-analysis');
        if (!timingContainer) {
            timingContainer = document.createElement('div');
            timingContainer.id = 'timing-analysis';
            timingContainer.className = 'timing-analysis';
            timingContainer.innerHTML = '<h3>时间分析</h3><div id="timing-steps"></div>';
            document.getElementById('result-section').appendChild(timingContainer);
        }
        
        const stepsContainer = document.getElementById('timing-steps');
        stepsContainer.innerHTML = '';
        
        // 显示客户端步骤
        if (timing.steps && timing.steps.length > 0) {
            const clientSteps = document.createElement('div');
            clientSteps.className = 'timing-section';
            clientSteps.innerHTML = '<h4>客户端步骤</h4>';
            
            const stepsList = document.createElement('div');
            stepsList.className = 'timing-steps-list';
            
            timing.steps.forEach((step, index) => {
                const stepItem = document.createElement('div');
                stepItem.className = 'timing-step-item';
                stepItem.innerHTML = `
                    <div class="timing-step-header">
                        <span class="timing-step-name">${step.step_name}</span>
                        <span class="timing-step-duration">${step.duration_ms.toFixed(2)} ms</span>
                    </div>
                    ${step.details && Object.keys(step.details).length > 0 ? 
                        `<div class="timing-step-details">${JSON.stringify(step.details, null, 2)}</div>` : ''}
                `;
                stepsList.appendChild(stepItem);
            });
            
            clientSteps.appendChild(stepsList);
            stepsContainer.appendChild(clientSteps);
        }
        
        // 显示服务器步骤
        if (timing.server_timing && timing.server_timing.steps && timing.server_timing.steps.length > 0) {
            const serverSteps = document.createElement('div');
            serverSteps.className = 'timing-section';
            serverSteps.innerHTML = '<h4>服务器步骤</h4>';
            
            const stepsList = document.createElement('div');
            stepsList.className = 'timing-steps-list';
            
            timing.server_timing.steps.forEach((step, index) => {
                const stepItem = document.createElement('div');
                stepItem.className = 'timing-step-item';
                stepItem.innerHTML = `
                    <div class="timing-step-header">
                        <span class="timing-step-name">${step.step_name}</span>
                        <span class="timing-step-duration">${step.duration_ms.toFixed(2)} ms</span>
                    </div>
                    ${step.details && Object.keys(step.details).length > 0 ? 
                        `<div class="timing-step-details">${JSON.stringify(step.details, null, 2)}</div>` : ''}
                `;
                stepsList.appendChild(stepItem);
            });
            
            serverSteps.appendChild(stepsList);
            stepsContainer.appendChild(serverSteps);
        }
        
        // 显示时间摘要
        const timeSummary = document.createElement('div');
        timeSummary.className = 'timing-summary';
        
        // 计算TLS握手时间：包含所有握手相关的步骤
        // 排除：证书服务器检查、服务器线程启动、等待服务器就绪、客户端初始化、建立TCP连接、清理连接、等待服务器完成
        const excludedSteps = [
            '证书服务器检查', '服务器线程启动', '等待服务器就绪', 
            '客户端初始化', '建立TCP连接', '清理连接', '等待服务器完成',
            '服务器Socket初始化', 'TLS服务器初始化', '等待客户端连接'
        ];
        
        let handshakeTime = 0;
        if (timing.steps) {
            // 累加所有握手相关的步骤时间
            timing.steps.forEach(step => {
                if (!excludedSteps.includes(step.step_name)) {
                    handshakeTime += step.duration_ms || 0;
                }
            });
        }
        
        // 如果找到了total_handshake_time_ms，使用它（更准确）
        if (timing.steps) {
            const handshakeStep = timing.steps.find(step => step.step_name === 'TLS握手执行');
            if (handshakeStep && handshakeStep.details && handshakeStep.details.total_handshake_time_ms) {
                // 使用实际的握手时间，但需要加上握手内部的步骤时间
                const actualHandshakeTime = handshakeStep.details.total_handshake_time_ms;
                // 计算握手内部步骤的时间（接收Certificate、解析证书链、HTTP请求、证书验证等）
                let internalStepsTime = 0;
                timing.steps.forEach(step => {
                    const stepName = step.step_name;
                    if (stepName !== 'TLS握手执行' && 
                        !excludedSteps.includes(stepName) &&
                        (stepName.includes('接收') || stepName.includes('解析') || 
                         stepName.includes('HTTP') || stepName.includes('证书') ||
                         stepName.includes('验证'))) {
                        internalStepsTime += step.duration_ms || 0;
                    }
                });
                // 使用较大的值（实际握手时间或累加时间）
                handshakeTime = Math.max(actualHandshakeTime, internalStepsTime);
            }
        }
        
        timeSummary.innerHTML = `
            <div class="timing-summary-item">
                <div class="timing-summary-label">TLS握手时间:</div>
                <div class="timing-summary-value">${handshakeTime.toFixed(2)} ms</div>
            </div>
            <div class="timing-summary-item">
                <div class="timing-summary-label">总执行时间:</div>
                <div class="timing-summary-value">${timing.total_time_ms.toFixed(2)} ms</div>
            </div>
            <div class="timing-summary-note">
                <small>注：TLS握手时间包含所有握手协议步骤（接收消息、解析证书、HTTP请求、证书验证等），总执行时间包含所有初始化、连接等步骤</small>
            </div>
        `;
        stepsContainer.appendChild(timeSummary);
    }
    
    displayComparison(data) {
        // 切换到对比页面
        this.switchPage('comparison');
        
        // 移除提示信息
        const placeholder = document.getElementById('comparison-placeholder');
        if (placeholder) {
            placeholder.remove();
        }
        
        // 显示对比结果
        const comparisonResults = document.getElementById('comparison-results');
        if (comparisonResults) {
            comparisonResults.style.display = 'block';
        }
        
        // by_val数据 - 使用包含网络传输的时间
        const byvalTimeEl = document.getElementById('byval-time');
        const byvalCertSizeEl = document.getElementById('byval-cert-size');
        const byvalTotalSizeEl = document.getElementById('byval-total-size');
        const byvalTimeWithNetwork = data.by_val.handshake_time_with_network_ms || data.by_val.handshake_time_ms;
        if (byvalTimeEl) byvalTimeEl.textContent = byvalTimeWithNetwork.toFixed(2);
        if (byvalCertSizeEl) byvalCertSizeEl.textContent = data.by_val.certificate_size_bytes.toLocaleString();
        if (byvalTotalSizeEl) byvalTotalSizeEl.textContent = data.by_val.total_size_bytes.toLocaleString();
        
        // by_ref数据 - 使用包含网络传输的时间
        const byrefTimeEl = document.getElementById('byref-time');
        const byrefCertSizeEl = document.getElementById('byref-cert-size');
        const byrefTotalSizeEl = document.getElementById('byref-total-size');
        const byrefHttpRequestsEl = document.getElementById('byref-http-requests');
        const byrefTimeWithNetwork = data.by_ref.handshake_time_with_network_ms || data.by_ref.handshake_time_ms;
        if (byrefTimeEl) byrefTimeEl.textContent = byrefTimeWithNetwork.toFixed(2);
        if (byrefCertSizeEl) byrefCertSizeEl.textContent = data.by_ref.certificate_size_bytes.toLocaleString();
        if (byrefTotalSizeEl) byrefTotalSizeEl.textContent = data.by_ref.total_size_bytes.toLocaleString();
        if (byrefHttpRequestsEl) byrefHttpRequestsEl.textContent = data.by_ref.http_requests || 2;
        
        // 更新网络环境指示器
        const networkIndicator = document.getElementById('current-network-latency');
        if (networkIndicator && data.comparison && data.comparison.network_simulation) {
            const netSim = data.comparison.network_simulation;
            const bandwidthText = netSim.bandwidth_mbps >= 1 
                ? `${netSim.bandwidth_mbps} Mbps` 
                : `${netSim.bandwidth_mbps * 1000} Kbps`;
            networkIndicator.textContent = `${data.network_condition} | ${bandwidthText} | ${netSim.base_latency_ms}ms延迟`;
        }
        
        // 显示时间分析（by_val和by_ref都显示）
        if (data.by_val.timing) {
            this.displayTimingBreakdown(data.by_val.timing, 'byval-timing-breakdown');
        }
        if (data.by_ref.timing) {
            this.displayTimingBreakdown(data.by_ref.timing, 'byref-timing-breakdown');
        }
        
        // 显示消息大小分析（by_val和by_ref都显示）
        if (data.by_val.message_sizes) {
            this.displaySizeBreakdown(data.by_val.message_sizes, 'byval-size-breakdown', data.by_val.total_size_bytes);
        }
        if (data.by_ref.message_sizes) {
            this.displaySizeBreakdown(data.by_ref.message_sizes, 'byref-size-breakdown', data.by_ref.total_size_bytes);
        }
        
        // 显示资源消耗（by_val和by_ref都显示）
        if (data.by_val.resources) {
            this.displayComparisonResources(data.by_val.resources, 'byval');
        }
        if (data.by_ref.resources) {
            this.displayComparisonResources(data.by_ref.resources, 'byref');
        }
        
        // 对齐各个部分的高度（延迟执行，确保图表和内容都已渲染）
        // 图表渲染需要约10ms，所以延迟更长时间确保完成
        setTimeout(() => {
            this.alignComparisonSections();
            // 再次延迟对齐，确保图表完全渲染
            setTimeout(() => {
                this.alignComparisonSections();
            }, 200);
        }, 150);
        
        // 对比数据
        const comparison = data.comparison;
        const certReductionEl = document.getElementById('cert-reduction');
        const certReductionPercentEl = document.getElementById('cert-reduction-percent');
        const transmissionSavingEl = document.getElementById('transmission-saving');
        const httpOverheadEl = document.getElementById('http-overhead');
        if (certReductionEl) certReductionEl.textContent = comparison.cert_size_reduction_bytes.toLocaleString();
        if (certReductionPercentEl) certReductionPercentEl.textContent = comparison.cert_size_reduction_percent.toFixed(2);
        // 使用网络模拟中的传输时间节省
        const transmissionSaving = (comparison.server_side_benefit && comparison.server_side_benefit.transmission_time_saving_ms) || 
                                   (comparison.network_simulation && comparison.network_simulation.transmission_time_saving_ms) || 0;
        if (transmissionSavingEl) transmissionSavingEl.textContent = transmissionSaving.toFixed(3);
        if (httpOverheadEl) httpOverheadEl.textContent = 
            comparison.client_side_overhead.estimated_latency_ms.toFixed(2);
    }
    
    displayTimingBreakdown(timing, containerId) {
        const container = document.getElementById(containerId);
        if (!container || !timing || !timing.steps) {
            return;
        }
        
        const excludedSteps = [
            '证书服务器检查', '服务器线程启动', '等待服务器就绪',
            '客户端初始化', '建立TCP连接', '清理连接', '等待服务器完成',
            '服务器Socket初始化', 'TLS服务器初始化', '等待客户端连接',
            'TLS握手执行'  // 排除总步骤，只显示详细步骤
        ];

        // 调试：输出所有步骤信息
        console.log('所有步骤数据:', timing.steps);
        console.log('排除步骤:', excludedSteps);
        
        // 定义标准步骤列表（按逻辑顺序）
        const standardSteps = [
            '生成ClientHello',
            '接收ServerHello',
            '处理ServerHello',
            '接收Certificate消息',
            '解析证书链',
            '解析证书扩展信息',
            '接收PQ签名扩展',  // by_val特有
            'HTTP获取server公钥',  // by_ref特有
            'HTTP获取server签名',  // by_ref特有
            'HTTP获取intermediate公钥',  // by_ref特有
            'HTTP获取intermediate签名',  // by_ref特有
            '证书链验证',
            '接收CertificateVerify消息',
            '接收Finished消息'
        ];
        
        // 收集所有步骤数据（包括时间为0的）
        const stepMap = new Map();
        timing.steps.forEach(step => {
            if (!excludedSteps.includes(step.step_name)) {
                stepMap.set(step.step_name, step.duration_ms || 0);
            }
        });
        
        // 收集所有步骤（包括标准步骤和其他步骤）
        const allSteps = [];
        
        // 先添加标准步骤（如果存在且时间>0）
        standardSteps.forEach(stepName => {
            if (stepMap.has(stepName)) {
                const duration = stepMap.get(stepName) || 0;
                if (duration > 0) {  // 只添加时间>0的步骤
                    allSteps.push({
                        name: stepName,
                        duration: duration
                    });
                }
            }
        });
        
        // 添加其他未在标准列表中的步骤（时间>0）
        stepMap.forEach((duration, stepName) => {
            if (!standardSteps.includes(stepName) && duration > 0) {
                allSteps.push({
                    name: stepName,
                    duration: duration
                });
            }
        });
        
        if (allSteps.length === 0) {
            container.innerHTML = '<p style="color: #6b7280; font-size: 0.9rem;">暂无详细数据</p>';
            return;
        }
        
        // 按时间降序排序
        allSteps.sort((a, b) => b.duration - a.duration);
        
        // 计算总时间
        const finalTotalTime = allSteps.reduce((sum, step) => sum + step.duration, 0);

        // 为HTTP资源获取步骤添加更详细的显示
        allSteps.forEach(step => {
            if (step.name.includes('HTTP获取') && step.name.includes('资源')) {
                const details = step.details || {};
                if (details.pk_uri && details.sig_uri) {
                    step.name += ' (公钥+签名)';
                } else if (details.pk_uri) {
                    step.name += ' (仅公钥)';
                } else if (details.sig_uri) {
                    step.name += ' (仅签名)';
                }
            } else if (step.name.includes('HTTP获取') && step.name.includes('签名')) {
                // 为单独的签名获取步骤添加算法信息
                const details = step.details || {};
                if (details.algorithm) {
                    step.name += ` (${details.algorithm})`;
                }
            }
        });

        // 创建饼图容器
        container.innerHTML = `
            <div class="timing-chart-container">
                <div class="timing-pie-chart">
                    <canvas id="${containerId}-pie"></canvas>
                </div>
                <div class="timing-legend" id="${containerId}-legend"></div>
            </div>
        `;

        // 等待DOM更新后生成饼图
        setTimeout(() => {
            this.createPieChart(`${containerId}-pie`, `${containerId}-legend`, allSteps, finalTotalTime);
        }, 10);
    }
    
    createPieChart(canvasId, legendId, steps, totalTime) {
        const canvas = document.getElementById(canvasId);
        const legend = document.getElementById(legendId);
        
        if (!canvas || !legend) {
            return;
        }
        
        // 设置画布大小
        const size = 200;
        canvas.width = size;
        canvas.height = size;
        const ctx = canvas.getContext('2d');
        const centerX = size / 2;
        const centerY = size / 2;
        const radius = size / 2 - 10;
        
        // 颜色方案
        const colors = [
            '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6',
            '#06b6d4', '#ec4899', '#14b8a6', '#f97316', '#6366f1'
        ];
        
        // 绘制饼图
        let currentAngle = -Math.PI / 2; // 从顶部开始
        
        steps.forEach((step, index) => {
            const sliceAngle = (step.duration / totalTime) * 2 * Math.PI;
            const color = colors[index % colors.length];
            
            // 绘制扇形
            ctx.beginPath();
            ctx.moveTo(centerX, centerY);
            ctx.arc(centerX, centerY, radius, currentAngle, currentAngle + sliceAngle);
            ctx.closePath();
            ctx.fillStyle = color;
            ctx.fill();
            
            // 添加边框
            ctx.strokeStyle = '#ffffff';
            ctx.lineWidth = 2;
            ctx.stroke();
            
            // 创建图例项
            const legendItem = document.createElement('div');
            legendItem.className = 'timing-legend-item';
            const percentage = ((step.duration / totalTime) * 100).toFixed(1);
            legendItem.innerHTML = `
                <span class="legend-color" style="background-color: ${color}"></span>
                <span class="legend-label">${step.name}</span>
                <span class="legend-value">${step.duration.toFixed(2)} ms (${percentage}%)</span>
            `;
            legend.appendChild(legendItem);
            
            currentAngle += sliceAngle;
        });
        
        // 在中心显示总时间
        ctx.fillStyle = '#ffffff';
        ctx.font = 'bold 14px sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(`${totalTime.toFixed(1)} ms`, centerX, centerY);
    }
    
    displaySizeBreakdown(messageSizes, containerId, totalSize) {
        const container = document.getElementById(containerId);
        if (!container || !messageSizes || Object.keys(messageSizes).length === 0) {
            return;
        }
        
        // 将消息大小转换为数组，按大小排序
        const sizeItems = Object.entries(messageSizes)
            .map(([name, size]) => ({ name, size: Number(size) }))
            .filter(item => item.size > 0)
            .sort((a, b) => b.size - a.size);
        
        if (sizeItems.length === 0) {
            container.innerHTML = '<p style="color: #6b7280; font-size: 0.9rem;">暂无消息大小数据</p>';
            return;
        }
        
        // 计算总大小（如果提供了）
        const calculatedTotal = sizeItems.reduce((sum, item) => sum + item.size, 0);
        const displayTotal = totalSize || calculatedTotal;
        
        // 创建饼图容器
        container.innerHTML = `
            <div class="size-chart-container" style="display: flex; gap: 1.5rem; align-items: flex-start;">
                <div class="size-pie-chart">
                    <canvas id="${containerId}-pie"></canvas>
                </div>
                <div class="size-legend" id="${containerId}-legend"></div>
            </div>
            <div style="margin-top: 0.5rem; text-align: center; color: #6b7280; font-size: 0.85rem;">
                总大小: ${displayTotal.toLocaleString()} 字节
            </div>
        `;
        
        // 等待DOM更新后生成饼图
        setTimeout(() => {
            this.createSizePieChart(`${containerId}-pie`, `${containerId}-legend`, sizeItems, displayTotal);
        }, 10);
    }
    
    createSizePieChart(canvasId, legendId, items, totalSize) {
        const canvas = document.getElementById(canvasId);
        const legend = document.getElementById(legendId);
        
        if (!canvas || !legend) {
            return;
        }
        
        // 设置画布大小
        const size = 200;
        canvas.width = size;
        canvas.height = size;
        const ctx = canvas.getContext('2d');
        const centerX = size / 2;
        const centerY = size / 2;
        const radius = size / 2 - 10;
        
        // 颜色方案（与时间分析不同，使用不同的颜色）
        const colors = [
            '#8b5cf6', '#ec4899', '#14b8a6', '#f97316', '#6366f1',
            '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#06b6d4'
        ];
        
        // 绘制饼图
        let currentAngle = -Math.PI / 2; // 从顶部开始
        
        items.forEach((item, index) => {
            const sliceAngle = (item.size / totalSize) * 2 * Math.PI;
            const color = colors[index % colors.length];
            
            // 绘制扇形
            ctx.beginPath();
            ctx.moveTo(centerX, centerY);
            ctx.arc(centerX, centerY, radius, currentAngle, currentAngle + sliceAngle);
            ctx.closePath();
            ctx.fillStyle = color;
            ctx.fill();
            
            // 添加边框
            ctx.strokeStyle = '#ffffff';
            ctx.lineWidth = 2;
            ctx.stroke();
            
            // 创建图例项
            const legendItem = document.createElement('div');
            legendItem.className = 'size-legend-item';
            legendItem.style.cssText = 'display: flex; align-items: center; margin-bottom: 0.5rem; font-size: 0.9rem;';
            const percentage = ((item.size / totalSize) * 100).toFixed(1);
            const sizeText = item.size >= 1024 
                ? `${(item.size / 1024).toFixed(2)} KB` 
                : `${item.size} B`;
            legendItem.innerHTML = `
                <span class="legend-color" style="display: inline-block; width: 12px; height: 12px; background-color: ${color}; border-radius: 2px; margin-right: 0.5rem;"></span>
                <span class="legend-label" style="flex: 1; color: #374151;">${item.name}</span>
                <span class="legend-value" style="color: #6b7280; margin-left: 0.5rem;">${sizeText} (${percentage}%)</span>
            `;
            legend.appendChild(legendItem);
            
            currentAngle += sliceAngle;
        });
        
        // 在中心显示总大小（简化显示）
        ctx.fillStyle = '#ffffff';
        ctx.font = 'bold 12px sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        const totalText = totalSize >= 1024 
            ? `${(totalSize / 1024).toFixed(1)} KB` 
            : `${totalSize} B`;
        ctx.fillText(totalText, centerX, centerY);
    }
    
    switchPage(pageName) {
        console.log('切换到页面:', pageName);
        
        // 隐藏所有页面
        document.querySelectorAll('.page-content').forEach(page => {
            page.classList.remove('active');
            page.style.display = 'none'; // 确保隐藏
            page.style.pointerEvents = 'none'; // 禁用交互
        });
        
        // 显示目标页面
        const targetPage = document.getElementById(`page-${pageName}`);
        if (targetPage) {
            targetPage.classList.add('active');
            targetPage.style.display = 'block'; // 确保显示
            targetPage.style.pointerEvents = 'auto'; // 启用交互
            console.log('显示页面:', pageName, targetPage);
        } else {
            console.error('页面不存在:', `page-${pageName}`);
        }
        
        // 更新标签页状态
        document.querySelectorAll('.page-tab').forEach(tab => {
            tab.classList.remove('active');
            if (tab.dataset.page === pageName) {
                tab.classList.add('active');
                console.log('激活标签页:', pageName);
            }
        });
        
        // 根据页面类型执行相应操作
        if (pageName === 'benchmark') {
            // 切换到基准测试页面时，自动加载所有图片
            console.log('加载基准测试数据');
            this.loadBenchmarkData();
        } else if (pageName === 'comparison') {
            // 切换到对比页面时，如果没有数据，显示提示
            const comparisonResults = document.getElementById('comparison-results');
            if (!comparisonResults || comparisonResults.style.display === 'none') {
                // 显示提示信息
                let placeholder = document.getElementById('comparison-placeholder');
                if (!placeholder) {
                    placeholder = document.createElement('div');
                    placeholder.className = 'loading-placeholder';
                    placeholder.style.marginTop = '2rem';
                    placeholder.style.padding = '2rem';
                    placeholder.style.textAlign = 'center';
                    placeholder.id = 'comparison-placeholder';
                    placeholder.textContent = '请点击"执行对比"按钮开始对比';
                    const comparisonPage = document.getElementById('page-comparison');
                    if (comparisonPage) {
                        // 插入到控制面板后面
                        const controlPanel = comparisonPage.querySelector('.control-panel');
                        if (controlPanel && controlPanel.nextSibling) {
                            comparisonPage.insertBefore(placeholder, controlPanel.nextSibling);
                        } else {
                            comparisonPage.appendChild(placeholder);
                        }
                    }
                }
                placeholder.style.display = 'block';
            }
        }
    }
    
    async displayBenchmark(data) {
        // 基准测试页面只显示图片，不显示实际数据
        // 直接调用loadBenchmarkData加载所有图片
        this.loadBenchmarkData();
    }
    
    showLoading(show) {
        const overlay = document.getElementById('loading-overlay');
        if (overlay) {
            overlay.style.display = show ? 'flex' : 'none';
            // 确保覆盖层不会阻止点击（当隐藏时）
            overlay.style.pointerEvents = show ? 'auto' : 'none';
        }
    }
    
    showToast(message, type = 'success') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        
        const icons = {
            success: '[OK]',
            error: '❌',
            warning: '⚠️',
            info: 'ℹ️'
        };
        
        toast.innerHTML = `
            <span>${icons[type] || icons.info}</span>
            <span>${message}</span>
        `;
        
        container.appendChild(toast);
        
        setTimeout(() => {
            toast.style.animation = 'slideIn 0.3s ease-out reverse';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }
    
    updateStatus(text, type = 'success') {
        const indicator = document.getElementById('status-indicator');
        const statusText = indicator.querySelector('.status-text');
        const statusDot = indicator.querySelector('.status-dot');
        
        statusText.textContent = text;
        
        const colors = {
            success: '#10b981',
            warning: '#f59e0b',
            error: '#ef4444',
            info: '#06b6d4'
        };
        
        statusDot.style.background = colors[type] || colors.success;
    }
    
    async generateBandwidthChart() {
        const bandwidthTlsModeEl = document.getElementById('bandwidth-tls-mode');
        const mode = (bandwidthTlsModeEl && bandwidthTlsModeEl.value) || 'hybrid';
        const bandwidthAlgoEl = document.getElementById('bandwidth-algorithm');
        const algorithm = (bandwidthAlgoEl && bandwidthAlgoEl.value) || 'mldsa65';
        const bandwidthLatencyEl = document.getElementById('bandwidth-network-latency');
        const networkLatency = (bandwidthLatencyEl && bandwidthLatencyEl.value) || 'loopback';
        
        this.showLoading(true);
        this.updateStatus('生成中', 'warning');
        
        try {
            const response = await fetch(`${this.apiBase}/bandwidth-comparison`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    mode: mode,
                    algorithm: algorithm,
                    network_latency: networkLatency
                })
            });
            
            if (!response.ok) {
                let errorMessage = '生成图表失败';
                try {
                    const error = await response.json();
                    errorMessage = error.detail || error.message || JSON.stringify(error);
                } catch (e) {
                    errorMessage = `HTTP ${response.status}: ${response.statusText}`;
                }
                throw new Error(errorMessage);
            }
            
            const data = await response.json();
            
            if (data.success) {
                this.displayBandwidthChart(data);
                this.showToast('带宽对比图生成成功！', 'success');
                this.updateStatus('成功', 'success');
            } else {
                throw new Error(data.error || '生成图表失败');
            }
        } catch (error) {
            console.error('生成图表错误:', error);
            const errorMsg = error.message || String(error);
            this.showToast('生成图表失败: ' + errorMsg, 'error');
            this.updateStatus('失败', 'error');
        } finally {
            this.showLoading(false);
        }
    }
    
    displayBandwidthChart(data) {
        // 切换到带宽对比页面
        this.switchPage('bandwidth');
        
        // 显示图表容器
        const chartContainer = document.getElementById('bandwidth-chart-container');
        if (chartContainer) {
            chartContainer.style.display = 'block';
        }
        
        // 准备数据
        const bandwidths = data.bandwidths || [];
        const byvalDelays = data.by_val_delays || [];
        const byrefDelays = data.by_ref_delays || [];
        
        // 销毁旧图表（如果存在）
        const chartCanvas = document.getElementById('bandwidth-chart');
        if (!chartCanvas) {
            console.error('图表canvas元素不存在');
            return;
        }
        
        if (window.bandwidthChart) {
            window.bandwidthChart.destroy();
        }
        
        // 检查Chart.js是否加载
        if (typeof Chart === 'undefined') {
            console.error('Chart.js未加载');
            this.showToast('图表库未加载，请刷新页面', 'error');
            return;
        }
        
        // 创建新图表
        const ctx = chartCanvas.getContext('2d');
        window.bandwidthChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: bandwidths.map(bw => {
                    if (bw >= 1) {
                        return `${bw} Mbps`;
                    } else {
                        return `${bw * 1000} Kbps`;
                    }
                }),
                datasets: [
                    {
                        label: 'by_val (值模式)',
                        data: byvalDelays,
                        borderColor: '#3b82f6',
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        tension: 0.4,
                        fill: false,
                        pointRadius: 5,
                        pointHoverRadius: 7
                    },
                    {
                        label: 'by_ref (引用模式)',
                        data: byrefDelays,
                        borderColor: '#10b981',
                        backgroundColor: 'rgba(16, 185, 129, 0.1)',
                        tension: 0.4,
                        fill: false,
                        pointRadius: 5,
                        pointHoverRadius: 7
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    title: {
                        display: true,
                        text: '握手延迟 vs 网络带宽',
                        font: {
                            size: 16,
                            weight: 'bold'
                        }
                    },
                    legend: {
                        display: true,
                        position: 'top'
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                        callbacks: {
                            label: function(context) {
                                return `${context.dataset.label}: ${context.parsed.y.toFixed(2)} ms`;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        title: {
                            display: true,
                            text: '网络带宽',
                            font: {
                                size: 14,
                                weight: 'bold'
                            }
                        },
                        grid: {
                            display: true,
                            color: 'rgba(0, 0, 0, 0.05)'
                        }
                    },
                    y: {
                        title: {
                            display: true,
                            text: '握手延迟 (ms)',
                            font: {
                                size: 14,
                                weight: 'bold'
                            }
                        },
                        beginAtZero: false,
                        grid: {
                            display: true,
                            color: 'rgba(0, 0, 0, 0.05)'
                        }
                    }
                },
                interaction: {
                    mode: 'nearest',
                    axis: 'x',
                    intersect: false
                }
            }
        });
        
        // 显示数据来源说明
        const dataSourceEl = document.getElementById('bandwidth-data-source');
        if (dataSourceEl && data && data.data_source) {
            const dataSource = data.data_source;
            const testConfig = dataSource.test_config || '';
            const calcMethod = dataSource.calculation_method || '';
            const netLatency = dataSource.network_latency || '';
            const description = dataSource.description || '';
            
            dataSourceEl.innerHTML = 
                '<p><strong>测试配置：</strong>' + testConfig + '</p>' +
                '<p><strong>数据计算方式：</strong>' + calcMethod + '</p>' +
                '<p><strong>网络延迟：</strong>' + netLatency + '</p>' +
                '<p><strong>说明：</strong>' + description + '</p>';
        }
    }
    
    async compareAlgorithms() {
        const certModeEl = document.getElementById('algorithm-cert-mode');
        const certMode = (certModeEl && certModeEl.value) || 'by_val';
        const runsEl = document.getElementById('algorithm-runs');
        const runs = parseInt((runsEl && runsEl.value) || '3', 10);
        
        // 获取三个模式的KEM和签名算法配置
        const classicKemEl = document.getElementById('classic-kem');
        const classicSigEl = document.getElementById('classic-signature');
        const pqcKemEl = document.getElementById('pqc-kem');
        const pqcSigEl = document.getElementById('pqc-signature');
        const hybridKemEl = document.getElementById('hybrid-kem');
        const hybridSigEl = document.getElementById('hybrid-signature');
        
        const classicKem = (classicKemEl && classicKemEl.value) || 'x25519';
        const classicSig = (classicSigEl && classicSigEl.value) || 'ecdsa_p256';
        const pqcKem = (pqcKemEl && pqcKemEl.value) || 'kyber768';
        const pqcSig = (pqcSigEl && pqcSigEl.value) || 'mldsa65';
        const hybridKem = (hybridKemEl && hybridKemEl.value) || 'p256_kyber768';
        const hybridSig = (hybridSigEl && hybridSigEl.value) || 'mldsa65';
        
        this.showLoading(true);
        this.updateStatus('执行中', 'warning');
        
        try {
            const response = await fetch(`${this.apiBase}/algorithm-comparison`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    cert_mode: certMode,
                    runs: runs,
                    classic: {
                        kem: classicKem,
                        signature: classicSig
                    },
                    pqc: {
                        kem: pqcKem,
                        signature: pqcSig
                    },
                    hybrid: {
                        kem: hybridKem,
                        signature: hybridSig
                    }
                })
            });
            
            if (!response.ok) {
                let errorMessage = '算法对比失败';
                try {
                    const error = await response.json();
                    errorMessage = error.detail || error.message || JSON.stringify(error);
                } catch (e) {
                    errorMessage = `HTTP ${response.status}: ${response.statusText}`;
                }
                throw new Error(errorMessage);
            }
            
            const data = await response.json();
            
            if (data.success) {
                this.displayAlgorithmComparison(data);
                this.showToast('算法对比完成！', 'success');
                this.updateStatus('成功', 'success');
            } else {
                throw new Error(data.error || '算法对比失败');
            }
        } catch (error) {
            console.error('算法对比错误:', error);
            const errorMsg = error.message || String(error);
            this.showToast('算法对比失败: ' + errorMsg, 'error');
            this.updateStatus('失败', 'error');
        } finally {
            this.showLoading(false);
        }
    }
    
    displayAlgorithmComparison(data) {
        // 切换到算法对比页面
        this.switchPage('algorithm');
        
        // 等待页面切换完成后再操作DOM
        setTimeout(() => {
            // 显示结果容器
            const resultsContainer = document.getElementById('algorithm-comparison-results');
            if (resultsContainer) {
                resultsContainer.style.display = 'block';
            }
            
            // 显示算法信息
            const algorithmInfoSection = document.getElementById('algorithm-info-section');
            if (algorithmInfoSection && data.comparison) {
                const comparison = data.comparison;
                
                // 填充KEM和签名算法信息（使用结果展示区域的ID）
                const classicKemEl = document.getElementById('result-classic-kem');
                const classicSigEl = document.getElementById('result-classic-signature');
                const pqcKemEl = document.getElementById('result-pqc-kem');
                const pqcSigEl = document.getElementById('result-pqc-signature');
                const hybridKemEl = document.getElementById('result-hybrid-kem');
                const hybridSigEl = document.getElementById('result-hybrid-signature');
                
                if (classicKemEl && comparison.classic) {
                    classicKemEl.textContent = comparison.classic.kem || '-';
                }
                if (classicSigEl && comparison.classic) {
                    classicSigEl.textContent = comparison.classic.signature || '-';
                }
                if (pqcKemEl && comparison.pqc) {
                    pqcKemEl.textContent = comparison.pqc.kem || '-';
                }
                if (pqcSigEl && comparison.pqc) {
                    pqcSigEl.textContent = comparison.pqc.signature || '-';
                }
                if (hybridKemEl && comparison.hybrid) {
                    hybridKemEl.textContent = comparison.hybrid.kem || '-';
                }
                if (hybridSigEl && comparison.hybrid) {
                    hybridSigEl.textContent = comparison.hybrid.signature || '-';
                }
                
                algorithmInfoSection.style.display = 'block';
            }
            
            // 填充对比表格
            this.fillAlgorithmComparisonTable(data);
            
            // 创建图表
            if (typeof Chart !== 'undefined' && data.comparison) {
                this.createAlgorithmCharts(data.comparison);
            }
        }, 100);
    }
    
    fillAlgorithmComparisonTable(data) {
        const tbody = document.getElementById('algorithm-comparison-tbody');
        if (tbody && data.comparison) {
            const comparison = data.comparison;
            tbody.innerHTML = `
                <tr>
                    <td style="padding: 0.75rem; border-bottom: 1px solid #e5e7eb; font-weight: 500;">握手时间 (ms)</td>
                    <td style="padding: 0.75rem; text-align: right; border-bottom: 1px solid #e5e7eb;">${comparison.classic && comparison.classic.handshake_time_ms ? comparison.classic.handshake_time_ms.toFixed(2) : '-'}</td>
                    <td style="padding: 0.75rem; text-align: right; border-bottom: 1px solid #e5e7eb;">${comparison.pqc && comparison.pqc.handshake_time_ms ? comparison.pqc.handshake_time_ms.toFixed(2) : '-'}</td>
                    <td style="padding: 0.75rem; text-align: right; border-bottom: 1px solid #e5e7eb;">${comparison.hybrid && comparison.hybrid.handshake_time_ms ? comparison.hybrid.handshake_time_ms.toFixed(2) : '-'}</td>
                </tr>
                <tr>
                    <td style="padding: 0.75rem; border-bottom: 1px solid #e5e7eb; font-weight: 500;">证书大小 (字节)</td>
                    <td style="padding: 0.75rem; text-align: right; border-bottom: 1px solid #e5e7eb;">${comparison.classic && comparison.classic.certificate_size_bytes ? comparison.classic.certificate_size_bytes.toLocaleString() : '-'}</td>
                    <td style="padding: 0.75rem; text-align: right; border-bottom: 1px solid #e5e7eb;">${comparison.pqc && comparison.pqc.certificate_size_bytes ? comparison.pqc.certificate_size_bytes.toLocaleString() : '-'}</td>
                    <td style="padding: 0.75rem; text-align: right; border-bottom: 1px solid #e5e7eb;">${comparison.hybrid && comparison.hybrid.certificate_size_bytes ? comparison.hybrid.certificate_size_bytes.toLocaleString() : '-'}</td>
                </tr>
                <tr>
                    <td style="padding: 0.75rem; border-bottom: 1px solid #e5e7eb; font-weight: 500;">总数据量 (字节)</td>
                    <td style="padding: 0.75rem; text-align: right; border-bottom: 1px solid #e5e7eb;">${comparison.classic && comparison.classic.total_size_bytes ? Math.round(comparison.classic.total_size_bytes).toLocaleString() : '-'}</td>
                    <td style="padding: 0.75rem; text-align: right; border-bottom: 1px solid #e5e7eb;">${comparison.pqc && comparison.pqc.total_size_bytes ? Math.round(comparison.pqc.total_size_bytes).toLocaleString() : '-'}</td>
                    <td style="padding: 0.75rem; text-align: right; border-bottom: 1px solid #e5e7eb;">${comparison.hybrid && comparison.hybrid.total_size_bytes ? Math.round(comparison.hybrid.total_size_bytes).toLocaleString() : '-'}</td>
                </tr>
                <tr>
                    <td style="padding: 0.75rem; border-bottom: 1px solid #e5e7eb; font-weight: 500;">消息数量</td>
                    <td style="padding: 0.75rem; text-align: right; border-bottom: 1px solid #e5e7eb;">${comparison.classic && comparison.classic.total_messages ? Math.round(comparison.classic.total_messages) : '-'}</td>
                    <td style="padding: 0.75rem; text-align: right; border-bottom: 1px solid #e5e7eb;">${comparison.pqc && comparison.pqc.total_messages ? Math.round(comparison.pqc.total_messages) : '-'}</td>
                    <td style="padding: 0.75rem; text-align: right; border-bottom: 1px solid #e5e7eb;">${comparison.hybrid && comparison.hybrid.total_messages ? Math.round(comparison.hybrid.total_messages) : '-'}</td>
                </tr>
            `;
        }
    }
    
    createAlgorithmCharts(comparison) {
        const modes = ['经典TLS', '纯PQC-TLS', '混合TLS'];
        const classicData = comparison.classic || {};
        const pqcData = comparison.pqc || {};
        const hybridData = comparison.hybrid || {};
        
        // 握手时间对比图表
        const timeCtx = document.getElementById('algorithm-time-chart');
        if (timeCtx) {
            if (window.algorithmTimeChart) {
                window.algorithmTimeChart.destroy();
            }
            window.algorithmTimeChart = new Chart(timeCtx.getContext('2d'), {
                type: 'bar',
                data: {
                    labels: modes,
                    datasets: [{
                        label: '握手时间 (ms)',
                        data: [
                            classicData.handshake_time_ms || 0,
                            pqcData.handshake_time_ms || 0,
                            hybridData.handshake_time_ms || 0
                        ],
                        backgroundColor: ['#3b82f6', '#10b981', '#f59e0b'],
                        borderColor: ['#2563eb', '#059669', '#d97706'],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        legend: {
                            display: false
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    return '握手时间: ' + context.parsed.y.toFixed(2) + ' ms';
                                }
                            }
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: '时间 (ms)'
                            }
                        }
                    }
                }
            });
        }
        
        // 证书大小对比图表
        const certSizeCtx = document.getElementById('algorithm-cert-size-chart');
        if (certSizeCtx) {
            if (window.algorithmCertSizeChart) {
                window.algorithmCertSizeChart.destroy();
            }
            window.algorithmCertSizeChart = new Chart(certSizeCtx.getContext('2d'), {
                type: 'bar',
                data: {
                    labels: modes,
                    datasets: [{
                        label: '证书大小 (字节)',
                        data: [
                            classicData.certificate_size_bytes || 0,
                            pqcData.certificate_size_bytes || 0,
                            hybridData.certificate_size_bytes || 0
                        ],
                        backgroundColor: ['#3b82f6', '#10b981', '#f59e0b'],
                        borderColor: ['#2563eb', '#059669', '#d97706'],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        legend: {
                            display: false
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    return '证书大小: ' + context.parsed.y.toLocaleString() + ' 字节';
                                }
                            }
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: '大小 (字节)'
                            }
                        }
                    }
                }
            });
        }
    }
}

// 初始化应用
document.addEventListener('DOMContentLoaded', function() {
    try {
        console.log('[DOMContentLoaded] 开始初始化应用');
        window.app = new TLSHandshakeDemo();
        console.log('[DOMContentLoaded] 应用初始化完成');
        
        // 默认加载基准测试数据
        if (window.app && window.app.loadBenchmarkData) {
            window.app.loadBenchmarkData();
        }
    } catch (error) {
        console.error('[DOMContentLoaded] 初始化失败:', error);
        console.error('错误堆栈:', error.stack);
        alert('应用初始化失败: ' + (error.message || '未知错误') + '\n请查看控制台获取详细信息');
    }
});
