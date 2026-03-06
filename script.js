function updateStatus(type, msg) {
    const box = document.getElementById('status-box');
    box.style.display = 'block';
    box.innerText = msg;
    box.style.background = type === 'danger' ? 'rgba(239,68,68,0.2)' : 'rgba(34,197,94,0.2)';
    box.style.color = type === 'danger' ? '#f87171' : '#4ade80';
}

async function handleRegister() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const res = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'register', username, password })
    });
    if (res.ok) { alert("สมัครสมาชิกสำเร็จ!"); window.location.href = 'index.html'; }
    else updateStatus('danger', "สมัครไม่สำเร็จ");
}

async function preLoginCheck() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    updateStatus('loading', "🔍 กำลังประเมินความเสี่ยง...");

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

    if (riskData.risk_level === "HIGH") return updateStatus('danger', "🚨 ความเสี่ยงสูง ระบบถูกบล็อก");

    const authRes = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'login', username, password })
    });
    if (authRes.ok) updateStatus('success', "✅ เข้าสู่ระบบสำเร็จ!");
    else updateStatus('danger', "❌ รหัสผ่านไม่ถูกต้อง");
}