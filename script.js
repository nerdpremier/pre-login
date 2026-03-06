// 1. ฟังก์ชันแสดงสถานะบนหน้าจอ
function updateStatus(type, msg) {
    const box = document.getElementById('status-box');
    if (!box) return;
    box.style.display = 'block'; 
    box.innerText = msg;
    box.style.background = type === 'danger' ? 'rgba(239,68,68,0.2)' : (type === 'success' ? 'rgba(34,197,94,0.2)' : '#334155');
    box.style.color = type === 'danger' ? '#f87171' : (type === 'success' ? '#4ade80' : 'white');
}

// 2. ฟังก์ชันตรวจสอบ Username (อังกฤษ) และ Password (ตามมาตรฐาน)
function validateInputs(username, password) {
    const userRegex = /^[a-zA-Z0-9]+$/;
    const passRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

    if (!userRegex.test(username)) return "Username ต้องเป็นภาษาอังกฤษและตัวเลขเท่านั้น";
    if (!passRegex.test(password)) return "Password ต้องมี 8 ตัวขึ้นไป, มีพิมพ์ใหญ่, พิมพ์เล็ก, ตัวเลข และสัญลักษณ์ (@$!%*?&)";
    return null;
}

// 3. สร้างลายนิ้วมือเครื่อง (Fingerprint)
function getSecureFp() {
    const hardware = [
        screen.width + "x" + screen.height,
        navigator.hardwareConcurrency || 0,
        navigator.platform
    ];
    return btoa(hardware.join("|")).substring(0, 128);
}

// 4. ฟังก์ชัน Login
async function preLoginCheck() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    if (!username || !password) return updateStatus('danger', "⚠️ กรุณากรอกให้ครบ");

    updateStatus('loading', "🔍 กำลังตรวจสอบความปลอดภัย...");
    try {
        const fingerprint = getSecureFp();
        const device = `Screen:${screen.width}x${screen.height} | CPU:${navigator.hardwareConcurrency}`;

        // เช็ค Risk
        const riskRes = await fetch('/api/assess', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, device, fingerprint })
        });
        const riskData = await riskRes.json();

        if (riskData.risk_level === "HIGH") return updateStatus('danger', "🚨 ความเสี่ยงสูงเกินไป ระงับการเข้าถึง");
        
        // ถ้าเป็น MEDIUM ให้ไปหน้า MFA
        if (riskData.risk_level === "MEDIUM") {
            updateStatus('success', "🛡️ อุปกรณ์ใหม่! กรุณายืนยันรหัส MFA ในอีเมล...");
            setTimeout(() => window.location.href = `mfa.html?logId=${riskData.logId}`, 1500);
            return;
        }

        // ถ้าผ่าน (LOW) ให้ Login
        const authRes = await fetch('/api/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'login', username, password, fingerprint })
        });

        const isOk = authRes.ok;
        await fetch('/api/update-risk', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ logId: riskData.logId, success: isOk })
        });

        if (isOk) {
            updateStatus('success', "✅ ล็อกอินสำเร็จ!");
            setTimeout(() => window.location.href = 'welcome.html', 1000);
        } else {
            updateStatus('danger', "❌ รหัสผ่านไม่ถูกต้อง");
        }
    } catch (e) { updateStatus('danger', "❌ ระบบขัดข้อง"); }
}

// 5. ฟังก์ชันสมัครสมาชิก
async function handleRegister() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    
    const error = validateInputs(username, password);
    if (error) return updateStatus('danger', `⚠️ ${error}`);

    updateStatus('loading', "⏳ กำลังสร้างบัญชี...");
    try {
        const res = await fetch('/api/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'register', username, password })
        });

        if (res.ok) {
            updateStatus('success', "✅ สมัครสำเร็จ! กำลังกลับไปหน้า Login...");
            setTimeout(() => window.location.href = 'index.html', 1500);
        } else {
            updateStatus('danger', "❌ ชื่อนี้ถูกใช้ไปแล้ว");
        }
    } catch (e) { updateStatus('danger', "❌ ไม่สามารถติดต่อเซิร์ฟเวอร์ได้"); }
}