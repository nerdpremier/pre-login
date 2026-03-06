// ฟังก์ชันแสดงสถานะ
function updateStatus(type, msg) {
    const box = document.getElementById('status-box');
    if (!box) return;
    box.style.display = 'block'; box.innerText = msg;
    box.style.background = type === 'danger' ? 'rgba(239,68,68,0.2)' : (type === 'success' ? 'rgba(34,197,94,0.2)' : '#334155');
    box.style.color = type === 'danger' ? '#f87171' : (type === 'success' ? '#4ade80' : 'white');
}

// ตรวจสอบความปลอดภัย (Username อังกฤษ / Password ตามมาตรฐาน)
function validateInputs(username, password) {
    const userRegex = /^[a-zA-Z0-9]+$/; // ภาษาอังกฤษและตัวเลขเท่านั้น
    const passRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

    if (!userRegex.test(username)) return "Username ต้องเป็นภาษาอังกฤษและตัวเลขเท่านั้น";
    if (!passRegex.test(password)) return "Password ต้องมี 8 ตัวขึ้นไป (พิมพ์ใหญ่, เล็ก, เลข, สัญลักษณ์)";
    return null;
}

function getSecureFp() {
    const hardware = [screen.width + "x" + screen.height, navigator.hardwareConcurrency || 0, navigator.platform];
    return btoa(hardware.join("|")).substring(0, 128);
}

// ฟังก์ชัน Login
async function preLoginCheck() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    if (!username || !password) return updateStatus('danger', "⚠️ กรุณากรอกให้ครบ");

    updateStatus('loading', "🔍 กำลังตรวจสอบความปลอดภัย...");
    try {
        const fingerprint = getSecureFp();
        const device = `Screen:${screen.width}x${screen.height} | CPU:${navigator.hardwareConcurrency}`;

        // 1. ประเมินความเสี่ยงและสร้าง Log (และรหัส MFA หากเป็น Medium)
        const riskRes = await fetch('/api/assess', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, device, fingerprint })
        });
        const riskData = await riskRes.json();

        if (riskData.risk_level === "HIGH") return updateStatus('danger', "🚨 ความเสี่ยงสูงเกินไป ระงับการเข้าถึง");
        
        // ถ้าเป็น MEDIUM ให้ไปหน้า MFA
        if (riskData.risk_level === "MEDIUM") {
            updateStatus('success', "🛡️ ตรวจพบอุปกรณ์ใหม่ กรุณายืนยันรหัสในอีเมล...");
            setTimeout(() => window.location.href = `mfa.html?logId=${riskData.logId}`, 1500);
            return;
        }

        // 2. ถ้าผ่าน (LOW) ให้ล็อกอินจริง
        const authRes = await fetch('/api/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'login', username, password, fingerprint })
        });
        const isOk = authRes.ok;

        // 3. อัปเดต Log ว่าสำเร็จหรือไม่ (เพื่อให้ Log เก็บข้อมูลครบ)
        await fetch('/api/update-risk', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ logId: riskData.logId, success: isOk })
        });

        if (isOk) {
            updateStatus('success', "✅ ยินดีต้อนรับ!");
            setTimeout(() => window.location.href = 'welcome.html', 1000);
        } else {
            updateStatus('danger', "❌ รหัสผ่านไม่ถูกต้อง");
        }
    } catch (e) { updateStatus('danger', "❌ ระบบขัดข้อง"); }
}

// ฟังก์ชันสมัครสมาชิก
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
    } catch (e) { updateStatus('danger', "❌ ไม่สามารถสมัครสมาชิกได้"); }
}