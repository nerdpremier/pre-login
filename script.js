function updateStatus(type, msg) {
    const box = document.getElementById('status-box');
    if (!box) return;
    box.style.display = 'block'; box.innerText = msg;
    box.style.background = type === 'danger' ? 'rgba(239,68,68,0.2)' : (type === 'success' ? 'rgba(34,197,94,0.2)' : '#334155');
    box.style.color = type === 'danger' ? '#f87171' : (type === 'success' ? '#4ade80' : 'white');
}

// ฟังก์ชันสร้างลายนิ้วมือระดับ Hardware
function getDetailedFp() {
    const info = [
        navigator.platform,
        navigator.userAgent,
        screen.width + "x" + screen.height, // ความละเอียดหน้าจอ
        new Date().getTimezoneOffset(),     // เขตเวลา
        navigator.language,                 // ภาษาเครื่อง
        navigator.hardwareConcurrency || 0, // จำนวน CPU Core
        screen.colorDepth                   // ความลึกของสีหน้าจอ
    ];
    return btoa(info.join("|")).substring(0, 32); // เข้ารหัสยาว 32 ตัวเพื่อให้ค่าต่างกันชัดเจน
}

async function preLoginCheck() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    if (!username || !password) return updateStatus('danger', "⚠️ กรุณากรอกให้ครบ");

    updateStatus('loading', "🔍 ตรวจสอบความปลอดภัยเครื่อง...");
    try {
        const fingerprint = getDetailedFp();
        const device = `${navigator.platform} | ${screen.width}x${screen.height} | CPU:${navigator.hardwareConcurrency}`;

        // 1. ประเมินความเสี่ยง
        const riskRes = await fetch('/api/assess', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, device, fingerprint })
        });
        const { risk_level, logId } = await riskRes.json();

        if (risk_level === "HIGH") return updateStatus('danger', "🚨 บล็อกการเข้าถึงเนื่องจากความเสี่ยงสูง");

        // 2. ล็อกอิน
        const authRes = await fetch('/api/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'login', username, password, fingerprint })
        });
        const isOk = authRes.ok;

        // 3. บันทึกผล Success/Fail
        await fetch('/api/update-risk', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ logId, success: isOk })
        });

        if (isOk) {
            updateStatus('success', "✅ เข้าสู่ระบบสำเร็จ!");
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
    else updateStatus('danger', "❌ ชื่อนี้ถูกใช้แล้ว");
}