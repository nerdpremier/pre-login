function updateStatus(type, msg) {
    const box = document.getElementById('status-box');
    if (!box) return;
    box.style.display = 'block'; box.innerText = msg;
    box.style.background = type === 'danger' ? 'rgba(239,68,68,0.2)' : (type === 'success' ? 'rgba(34,197,94,0.2)' : '#334155');
    box.style.color = type === 'danger' ? '#f87171' : (type === 'success' ? '#4ade80' : 'white');
}

// ฟังก์ชันสร้างลายนิ้วมือ (สลับเอา Hardware ขึ้นก่อนเพื่อแยกเครื่องให้ขาด)
function getSecureFp() {
    const hardware = [
        screen.width + "x" + screen.height,
        navigator.hardwareConcurrency || 0,
        new Date().getTimezoneOffset(),
        screen.colorDepth,
        navigator.platform,
        navigator.language
    ];
    // ต่อด้วย UserAgent ไว้ท้ายสุด
    const raw = hardware.join("|") + "|" + navigator.userAgent;
    return btoa(raw).substring(0, 128);
}

async function preLoginCheck() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    if (!username || !password) return updateStatus('danger', "⚠️ กรุณากรอกให้ครบ");

    updateStatus('loading', "🔍 ตรวจสอบความปลอดภัยอุปกรณ์...");
    try {
        const fingerprint = getSecureFp();
        const device = `Screen:${screen.width}x${screen.height} | CPU:${navigator.hardwareConcurrency} | ${navigator.platform}`;

        // 1. ประเมินความเสี่ยง
        const riskRes = await fetch('/api/assess', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, device, fingerprint })
        });
        const { risk_level, logId } = await riskRes.json();

        if (risk_level === "HIGH") return updateStatus('danger', "🚨 ระงับการเข้าถึงเนื่องจากความเสี่ยงสูง");

        // 2. ดำเนินการล็อกอิน
        const authRes = await fetch('/api/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'login', username, password, fingerprint })
        });
        const isOk = authRes.ok;

        // 3. บันทึกผลสำเร็จลงใน Log ID เดิม
        await fetch('/api/update-risk', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ logId, success: isOk })
        });

        if (isOk) {
            updateStatus('success', "✅ สำเร็จ! กำลังนำคุณเข้าสู่ระบบ");
            setTimeout(() => window.location.href = 'welcome.html', 1000);
        } else {
            updateStatus('danger', "❌ รหัสผ่านไม่ถูกต้อง");
        }
    } catch (e) { updateStatus('danger', "❌ ระบบขัดข้อง"); }
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
    if (res.ok) { alert("สมัครสำเร็จ!"); window.location.href = 'index.html'; }
    else updateStatus('danger', "❌ ชื่อนี้ถูกใช้ไปแล้ว");
}