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

    updateStatus('loading', "🔍 กำลังวิเคราะห์ความปลอดภัย...");
    try {
        const device = `${navigator.platform} | ${navigator.userAgent}`;
        const currentFp = btoa(device).substring(0, 16);
        const isMismatch = localStorage.getItem('last_fp') && localStorage.getItem('last_fp') !== currentFp;

        // 1. เช็คความเสี่ยง
        const riskRes = await fetch('/api/assess', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, device, fp_mismatch: isMismatch })
        });
        const { risk_level, logId } = await riskRes.json();

        if (risk_level === "HIGH") return updateStatus('danger', "🚨 ระงับการเข้าถึงชั่วคราว (15 นาที)");

        // 2. เช็ครหัสผ่าน
        const authRes = await fetch('/api/auth', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'login', username, password })
        });
        const isOk = authRes.ok;

        // 3. ส่งผลกลับไปอัปเดต ID เดิม
        await fetch('/api/update-risk', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ logId, success: isOk })
        });

        if (isOk) {
            const authData = await authRes.json();
            localStorage.setItem('logged_in_user', authData.user);
            localStorage.setItem('last_fp', currentFp);
            updateStatus('success', "✅ สำเร็จ! กำลังนำเข้า...");
            setTimeout(() => window.location.href = 'welcome.html', 1000);
        } else {
            updateStatus('danger', "❌ ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง");
        }
    } catch (e) { updateStatus('danger', "❌ ระบบขัดข้อง"); }
}