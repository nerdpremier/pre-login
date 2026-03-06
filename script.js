function updateStatus(type, msg) {
    const box = document.getElementById('status-box');
    box.style.display = 'block';
    box.innerText = msg;
    box.className = `status-${type}`; // ใช้ Class เพื่อเปลี่ยนสีตาม CSS
}

async function preLoginCheck() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    if (!username || !password) return updateStatus('danger', "⚠️ กรุณากรอกให้ครบ");

    updateStatus('loading', "🔍 กำลังสแกนความปลอดภัย...");

    try {
        const ipRes = await fetch('https://ipapi.co/json/').then(r => r.json());
        const device = `${navigator.platform} | ${navigator.userAgent}`;
        const currentFp = btoa(device).substring(0, 16);
        const isMismatch = localStorage.getItem('last_fp') && localStorage.getItem('last_fp') !== currentFp;
        localStorage.setItem('last_fp', currentFp);

        const riskRes = await fetch('/api/assess', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, ip: ipRes.ip, location: ipRes.city, device, fp_mismatch: isMismatch })
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

        if (authRes.ok) {
            const authData = await authRes.json();
            updateStatus('success', "✅ ยินดีต้อนรับ! กำลังพานำหน้า...");
            localStorage.setItem('logged_in_user', authData.user);
            setTimeout(() => window.location.href = 'welcome.html', 1000);
        } else {
            const authData = await authRes.json();
            updateStatus('danger', "❌ " + authData.error);
        }
    } catch (e) {
        updateStatus('danger', "❌ ไม่สามารถเชื่อมต่อกับเซิร์ฟเวอร์ได้");
    }
}

// ฟังก์ชันสมัครสมาชิก
async function handleRegister() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    if (!username || !password) return updateStatus('danger', "⚠️ กรุณากรอกให้ครบ");

    const res = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'register', username, password })
    });
    if (res.ok) { alert("สมัครสมาชิกสำเร็จ!"); window.location.href = 'index.html'; }
    else { const data = await res.json(); updateStatus('danger', data.error); }
}