// ฟังก์ชันแสดงสถานะบนหน้าจอ
function updateStatus(type, msg) {
    const box = document.getElementById('status-box');
    if (!box) return;
    box.style.display = 'block'; box.innerText = msg;
    box.style.background = type === 'danger' ? 'rgba(239,68,68,0.2)' : (type === 'success' ? 'rgba(34,197,94,0.2)' : '#334155');
    box.style.color = type === 'danger' ? '#f87171' : (type === 'success' ? '#4ade80' : 'white');
}

// สร้างลายนิ้วมือโดยเอา Hardware ขึ้นก่อน (แก้ปัญหาค่าซ้ำจาก OS/Browser)
function getSecureFp() {
    const hardwareInfo = [
        screen.width + "x" + screen.height,    // ความละเอียดจอ (ต่างกันบ่อย)
        navigator.hardwareConcurrency || 0,    // จำนวน CPU Core (ต่างกันชัดเจน)
        new Date().getTimezoneOffset(),        // เขตเวลา
        screen.colorDepth,                     // ความลึกสี
        navigator.platform,                    // OS (Win32)
        navigator.language                     // ภาษาเครื่อง
    ];
    // นำค่า Hardware มาต่อกันแล้วเข้ารหัส Base64
    // ไม่เอา UserAgent ไว้ข้างหน้า เพราะมันยาวและทำให้ค่าต้นๆ เหมือนกัน
    const rawString = hardwareInfo.join("|") + "|" + navigator.userAgent;
    return btoa(rawString).substring(0, 128); // เก็บยาว 128 ตัวเพื่อความแม่นยำสูงสุด
}

async function preLoginCheck() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    if (!username || !password) return updateStatus('danger', "⚠️ กรุณากรอกให้ครบ");

    updateStatus('loading', "🔍 กำลังตรวจพิสูจน์เครื่องอุปกรณ์...");
    try {
        const fingerprint = getSecureFp();
        // สร้างข้อมูลอุปกรณ์เพื่อโชว์ใน DB (เห็นความต่างของ CPU/Screen ชัดเจน)
        const device = `Screen:${screen.width}x${screen.height} | CPU:${navigator.hardwareConcurrency} | ${navigator.platform}`;

        // 1. ประเมินความเสี่ยง
        const riskRes = await fetch('/api/assess', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, device, fingerprint })
        });
        const { risk_level, logId } = await riskRes.json();

        if (risk_level === "HIGH") return updateStatus('danger', "🚨 ระงับการเข้าถึง (ตรวจพบพฤติกรรมเสี่ยงสูง)");

        // 2. ล็อกอิน
        const authRes = await fetch('/api/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'login', username, password, fingerprint })
        });
        const isOk = authRes.ok;

        // 3. บันทึกผล Success/Fail ลง Log เดิม
        await fetch('/api/update-risk', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ logId, success: isOk })
        });

        if (isOk) {
            updateStatus('success', "✅ ยินดีต้อนรับ! กำลังเข้าสู่ระบบ...");
            setTimeout(() => window.location.href = 'welcome.html', 1000);
        } else {
            updateStatus('danger', "❌ ชื่อผู้ใช้หรือรหัสผ่านผิด");
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