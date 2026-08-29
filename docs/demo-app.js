// ============================================================
// 🤖 AI SECURITY SCANNER - Demo Interactivo
// ============================================================

let scannerUses = 0;

function initScannerDemo() {
    const container = document.getElementById('scanner-demo');
    if (!container) return;

    container.innerHTML = `
        <style>
            .scanner-demo { background: #0d0d1a; border-radius: 20px; padding: 2rem; margin: 2rem auto; max-width: 800px; border: 1px solid #1a1a3e; }
            .scanner-demo h3 { color: #ff4757; margin-bottom: 1rem; font-size: 1.3rem; }
            .scan-input-wrap { display: flex; gap: 10px; margin-bottom: 1.5rem; }
            .scan-input { flex: 1; padding: 14px 18px; background: #111122; border: 2px solid #222244; border-radius: 12px; color: #fff; font-size: 1rem; font-family: 'Courier New', monospace; transition: border-color 0.3s; }
            .scan-input:focus { border-color: #ff4757; outline: none; }
            .scan-btn { padding: 14px 28px; background: linear-gradient(135deg, #ff4757, #ff6b81); color: #fff; border: none; border-radius: 12px; font-weight: 700; font-size: 1rem; cursor: pointer; transition: all 0.3s; }
            .scan-btn:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(255,71,87,0.3); }
            .scan-progress { display: none; margin: 1rem 0; }
            .scan-progress-bar { height: 6px; background: #222; border-radius: 3px; overflow: hidden; }
            .scan-progress-fill { height: 100%; background: linear-gradient(90deg, #ff4757, #ff6b81); width: 0%; transition: width 0.3s; border-radius: 3px; }
            .scan-progress-text { color: #888; font-size: 0.85rem; margin-top: 6px; }
            .scan-result { border-radius: 12px; padding: 1.5rem; margin-top: 1rem; display: none; background: #111122; border: 1px solid #222244; }
            .scan-summary { display: flex; gap: 20px; margin-bottom: 1.5rem; flex-wrap: wrap; }
            .scan-stat { text-align: center; padding: 15px 20px; background: #0a0a15; border-radius: 10px; min-width: 100px; }
            .scan-stat .num { font-size: 1.8rem; font-weight: 800; }
            .scan-stat .label { color: #666; font-size: 0.8rem; margin-top: 4px; }
            .scan-findings { display: flex; flex-direction: column; gap: 10px; }
            .scan-finding { padding: 12px 16px; background: #0a0a15; border-radius: 8px; border-left: 4px solid; }
            .scan-finding.critical { border-color: #ff4444; }
            .scan-finding.high { border-color: #ff8c00; }
            .scan-finding.medium { border-color: #ffbd2e; }
            .scan-finding.low { border-color: #00ff88; }
            .scan-finding .title { font-weight: 600; font-size: 0.95rem; }
            .scan-finding .desc { color: #888; font-size: 0.85rem; margin-top: 4px; }
            .scan-samples { margin-top: 1.5rem; }
            .scan-samples h4 { color: #888; font-size: 0.9rem; margin-bottom: 0.8rem; }
            .scan-sample-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
            .scan-sample-btn { padding: 10px 14px; background: #111122; border: 1px solid #222244; border-radius: 8px; color: #aaa; font-size: 0.85rem; cursor: pointer; transition: all 0.2s; text-align: left; font-family: 'Courier New', monospace; }
            .scan-sample-btn:hover { border-color: #ff4757; color: #ff4757; }
            .scan-uses { text-align: center; color: #666; font-size: 0.8rem; margin-top: 1rem; }
        </style>
        <div class="scanner-demo">
            <h3>🤖 Escaneo de Seguridad AI</h3>
            <p style="color:#666; margin-bottom:1rem;">Ingresa una URL para detectar vulnerabilidades en sistemas AI</p>
            
            <div class="scan-input-wrap">
                <input type="text" class="scan-input" id="scan-input" placeholder="https://chat.ejemplo.com">
                <button class="scan-btn" onclick="runScan()">🔍 Escanear</button>
            </div>
            
            <div class="scan-progress" id="scan-progress">
                <div class="scan-progress-bar"><div class="scan-progress-fill" id="scan-fill"></div></div>
                <div class="scan-progress-text" id="scan-text">Iniciando escaneo...</div>
            </div>
            
            <div class="scan-result" id="scan-result"></div>
            
            <div class="scan-samples">
                <h4>📋 Prueba con estos targets:</h4>
                <div class="scan-sample-grid">
                    <button class="scan-sample-btn" onclick="testScan('https://chatgpt-clone.com')">https://chatgpt-clone.com</button>
                    <button class="scan-sample-btn" onclick="testScan('https://ai-api.empresa.com')">https://ai-api.empresa.com</button>
                    <button class="scan-sample-btn" onclick="testScan('https://bot-atencion.clientes.com')">https://bot-atencion.clientes.com</button>
                    <button class="scan-sample-btn" onclick="testScan('https://generador-contenido.ai')">https://generador-contenido.ai</button>
                </div>
            </div>
            <div class="scan-uses" id="scan-uses">Usos: ${scannerUses}/3</div>
        </div>
    `;
}

function runScan() {
    if (!DemoSystem.use()) return;
    scannerUses++;
    
    const url = document.getElementById('scan-input').value.trim();
    if (!url) { alert('Ingresa una URL'); return; }
    
    const progress = document.getElementById('scan-progress');
    const fill = document.getElementById('scan-fill');
    const text = document.getElementById('scan-text');
    const result = document.getElementById('scan-result');
    
    progress.style.display = 'block';
    result.style.display = 'none';
    
    const steps = [
        { pct: 15, msg: '🔍 Analizando estructura...' },
        { pct: 35, msg: '🛡️ Verificando endpoints AI...' },
        { pct: 55, msg: '🤖 Probando prompt injection...' },
        { pct: 75, msg: '📊 Revisando data leakage...' },
        { pct: 90, msg: '🔒 Evaluando autenticación...' },
        { pct: 100, msg: '✅ Escaneo completado' },
    ];
    
    let i = 0;
    const interval = setInterval(() => {
        if (i < steps.length) {
            fill.style.width = steps[i].pct + '%';
            text.textContent = steps[i].msg;
            i++;
        } else {
            clearInterval(interval);
            showScanResults(url);
        }
    }, 400);
}

function showScanResults(url) {
    const result = document.getElementById('scan-result');
    const findings = [
        { severity: 'critical', title: '🔴 Prompt Injection vulnerable', desc: 'El endpoint /chat acepta instrucciones sin sanitización. Un atacante puede manipular el comportamiento del AI.' },
        { severity: 'high', title: '🟠 Sin rate limiting en API', desc: 'No hay límite de requests. Posible abuso para scraping o denegación de servicio.' },
        { severity: 'medium', title: '🟡 Data leakage en respuestas', desc: 'El modelo puede revelar información interna del sistema con prompts específicos.' },
        { severity: 'medium', title: '🟡 CORS abierto', desc: 'El endpoint AI acepta requests desde cualquier origen.' },
        { severity: 'low', title: '🟢 Headers de seguridad ausentes', desc: 'Faltan X-Content-Type-Options, X-Frame-Options en endpoints AI.' },
    ];
    
    const critical = findings.filter(f => f.severity === 'critical').length;
    const high = findings.filter(f => f.severity === 'high').length;
    const medium = findings.filter(f => f.severity === 'medium').length;
    
    result.style.display = 'block';
    result.innerHTML = `
        <div class="scan-summary">
            <div class="scan-stat"><div class="num" style="color:#ff4444">${critical}</div><div class="label">Críticos</div></div>
            <div class="scan-stat"><div class="num" style="color:#ff8c00">${high}</div><div class="label">Altos</div></div>
            <div class="scan-stat"><div class="num" style="color:#ffbd2e">${medium}</div><div class="label">Medios</div></div>
            <div class="scan-stat"><div class="num" style="color:#00ff88">${findings.length}</div><div class="label">Total</div></div>
        </div>
        <div class="scan-findings">
            ${findings.map(f => `
                <div class="scan-finding ${f.severity}">
                    <div class="title">${f.title}</div>
                    <div class="desc">${f.desc}</div>
                </div>
            `).join('')}
        </div>
    `;
    document.getElementById('scan-uses').textContent = `Usos: ${scannerUses}/3`;
}

function testScan(url) {
    document.getElementById('scan-input').value = url;
    runScan();
}

document.addEventListener('DOMContentLoaded', () => { setTimeout(initScannerDemo, 100); });
