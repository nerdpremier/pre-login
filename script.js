function updateStatus(type, msg) {
    const box = document.getElementById('status-box');
    box.style.display = 'block';
    box.innerText = msg;
    box.style.background = type === 'danger' ? 'rgba(239,68,68,0.2)' : 'rgba(34,197,94,0.2)';
    box.style.color = type === 'danger' ? '#f87171' : '#4ade80';
}

function getSecureFp() {
    return btoa([screen.width + "x" + screen.height, navigator.hardwareConcurrency, navigator.platform].join("|"));
}

async function preLoginCheck() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    const remember = document.getElementById('remember-device').checked;
    if (!username || !password) return updateStatus('danger', "⚠️ กรุณากรอกให้ครบ");

    updateStatus('loading', "⏳ กำลังตรวจสอบ...");
    try {
        const fingerprint = getSecureFp();
        // 1. เช็คความเสี่ยง
        const riskRes = await fetch('/api/assess', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, fingerprint, device: navigator.userAgent })
        });
        const riskData = await riskRes.json();
        if (riskData.risk_level === "HIGH") return updateStatus('danger', "🚨 ความเสี่ยงสูง ถูกระงับ");

        // 2. เช็ครหัสผ่าน
        const authRes = await fetch('/api/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'login', username, password, fingerprint, logId: riskData.logId, risk_level: riskData.risk_level, remember })
        });
        const authData = await authRes.json();

        if (authRes.ok) {
            if (authData.mfa_required) {
                window.location.href = `mfa.html?logId=${riskData.logId}&remember=${remember}`;
            } else {
                window.location.href = 'welcome.html';
            }
        } else {
            updateStatus('danger', "❌ ชื่อผู้ใช้หรือรหัสผ่านผิด");
        }
    } catch (e) { updateStatus('danger', "❌ ระบบขัดข้อง"); }
}