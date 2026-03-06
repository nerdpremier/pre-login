function updateStatus(type, msg) {
    const box = document.getElementById('status-box');
    box.style.display = 'block'; box.innerText = msg;
    box.style.background = type === 'danger' ? 'rgba(239,68,68,0.2)' : (type === 'success' ? 'rgba(34,197,94,0.2)' : '#334155');
    box.style.color = type === 'danger' ? '#f87171' : (type === 'success' ? '#4ade80' : 'white');
}

async function preLoginCheck() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    if (!username || !password) return updateStatus('danger', "⚠️ กรุณากรอกให้ครบ");

    updateStatus('loading', "🔍 ตรวจสอบความปลอดภัย...");
    try {
        const device = `${navigator.platform} | ${navigator.userAgent}`;
        const currentFp = btoa(device).substring(0, 16);
        const isMismatch = localStorage.getItem('last_fp') && localStorage.getItem('last_fp') !== currentFp;

        // 1. ประเมินความเสี่ยง
        const riskRes = await fetch('/api/assess', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, device, fp_mismatch: isMismatch })
        });
        const { risk_level, logId } = await riskRes.json();

        if (risk_level === "HIGH") return updateStatus('danger', "🚨 พยายามล็อกอินเกินขีดจำกัด กรุณารอ 15 นาที");

        // 2. ตรวจสอบรหัสผ่าน
        const authRes = await fetch('/api/auth', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'login', username, password })
        });
        const isOk = authRes.ok;

        // 3. อัปเดต Log (Success/Fail) กลับไปที่ ID เดิม
        await fetch('/api/update-risk', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ logId, success: isOk })
        });

        if (isOk) {
            const authData = await authRes.json();
            localStorage.setItem('logged_in_user', authData.user);
            localStorage.setItem('last_fp', currentFp);
            updateStatus('success', "✅ ยินดีต้อนรับ! กำลังเข้าสู่ระบบ...");
            setTimeout(() => window.location.href = 'welcome.html', 1000);
        } else {
            updateStatus('danger', "❌ Username หรือ Password ผิด");
        }
    } catch (e) { updateStatus('danger', "❌ ระบบขัดข้อง"); }
}

async function handleRegister() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    if (!username || !password) return updateStatus('danger', "⚠️ ข้อมูลไม่ครบ");

    const res = await fetch('/api/auth', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'register', username, password })
    });
    if (res.ok) { alert("สมัครสำเร็จ!"); window.location.href = 'index.html'; }
    else updateStatus('danger', "❌ ไม่สามารถสมัครได้ (ชื่ออาจซ้ำ)");
}