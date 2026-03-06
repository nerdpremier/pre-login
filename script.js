function updateStatus(type, msg) {
    const box = document.getElementById('status-box');
    if (!box) return;
    box.style.display = 'block'; box.innerText = msg;
    box.style.background = type === 'danger' ? 'rgba(239,68,68,0.2)' : (type === 'success' ? 'rgba(34,197,94,0.2)' : '#334155');
    box.style.color = type === 'danger' ? '#f87171' : (type === 'success' ? '#4ade80' : 'white');
}

async function preLoginCheck() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    if (!username || !password) return updateStatus('danger', "⚠️ กรุณากรอกให้ครบ");

    updateStatus('loading', "🔍 วิเคราะห์ความปลอดภัย...");

    try {
        // สร้าง Fingerprint จากสเปคเครื่อง
        const device = `${navigator.platform} | ${navigator.userAgent}`;
        const currentFp = btoa(device).substring(0, 16);
        
        // แก้ไข Logic: ถ้าเครื่องใหม่ (null) หรือไม่ตรงกัน ให้ถือเป็น Mismatch (true)
        const lastFp = localStorage.getItem('last_fp');
        const isMismatch = (lastFp === null || lastFp !== currentFp);

        // 1. ส่งข้อมูลไปประเมินความเสี่ยง
        const riskRes = await fetch('/api/assess', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, device, fp_mismatch: isMismatch })
        });
        const { risk_level, logId } = await riskRes.json();

        if (risk_level === "HIGH") return updateStatus('danger', "🚨 พยายามล็อกอินเกินขีดจำกัด (ระงับ 15 นาที)");

        // 2. ตรวจสอบรหัสผ่าน
        const authRes = await fetch('/api/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'login', username, password })
        });
        const isOk = authRes.ok;

        // 3. แจ้งผลสำเร็จกลับไปที่ ID เดิม
        await fetch('/api/update-risk', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ logId, success: isOk })
        });

        if (isOk) {
            const authData = await authRes.json();
            // เมื่อ Login สำเร็จ ให้จำ Fingerprint เครื่องนี้ไว้ว่าเป็นเครื่องที่ "ไว้ใจได้"
            localStorage.setItem('last_fp', currentFp);
            localStorage.setItem('logged_in_user', authData.user);
            
            updateStatus('success', "✅ ยินดีต้อนรับ! กำลังเข้าสู่ระบบ...");
            setTimeout(() => window.location.href = 'welcome.html', 1000);
        } else {
            updateStatus('danger', "❌ ชื่อผู้ใช้หรือรหัสผ่านผิด");
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
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'register', username, password })
    });
    if (res.ok) { 
        alert("สมัครสมาชิกสำเร็จ!"); 
        window.location.href = 'index.html'; 
    } else {
        updateStatus('danger', "❌ ชื่อนี้อาจถูกใช้ไปแล้ว");
    }
}