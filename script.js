function updateStatus(type, msg) {
    const box = document.getElementById('status-box');
    box.style.display = 'block';
    box.innerText = msg;
    box.style.background = type === 'danger' ? 'rgba(239,68,68,0.2)' : (type === 'success' ? 'rgba(34,197,94,0.2)' : '#334155');
    box.style.color = type === 'danger' ? '#f87171' : (type === 'success' ? '#4ade80' : 'white');
}

async function preLoginCheck() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    if (!username || !password) return updateStatus('danger', "⚠️ กรุณากรอกให้ครบ");

    updateStatus('loading', "🔍 กำลังวิเคราะห์ความปลอดภัย...");

    try {
        const device = `${navigator.platform} | ${navigator.userAgent}`;
        const currentFp = btoa(device).substring(0, 16);
        const isMismatch = localStorage.getItem('last_fp') && localStorage.getItem('last_fp') !== currentFp;
        localStorage.setItem('last_fp', currentFp);

        // ส่งเฉพาะ Username และ Device ข้อมูล IP หลังบ้านจะจัดการเอง
        const riskRes = await fetch('/api/assess', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, device, fp_mismatch: isMismatch })
        });
        const riskData = await riskRes.json();

        if (riskData.risk_level === "HIGH") {
            return updateStatus('danger', "🚨 พยายามเข้าสู่ระบบมากเกินไป กรุณารอ 15 นาที");
        }

        const authRes = await fetch('/api/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'login', username, password })
        });
        
        const authData = await authRes.json();
        if (authRes.ok) {
            updateStatus('success', "✅ สำเร็จ! กำลังนำเข้า...");
            localStorage.setItem('logged_in_user', authData.user);
            setTimeout(() => window.location.href = 'welcome.html', 1000);
        } else {
            updateStatus('danger', "❌ " + authData.error);
        }
    } catch (e) {
        updateStatus('danger', "❌ ระบบขัดข้อง กรุณาลองใหม่");
    }
}

async function handleRegister() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    if (!username || !password) return updateStatus('danger', "⚠️ กรอกข้อมูลไม่ครบ");

    const res = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'register', username, password })
    });
    if (res.ok) { alert("สมัครสมาชิกสำเร็จ!"); window.location.href = 'index.html'; }
    else { const data = await res.json(); updateStatus('danger', data.error); }
}