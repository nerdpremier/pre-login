// --- ส่วนที่ต้องใช้ใน script.js ---

async function handleRegister() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    
    // 1. เรียกใช้ตัวตรวจสอบ (ภาษาอังกฤษ + ความแข็งแรงรหัสผ่าน)
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
            updateStatus('success', "✅ สมัครสมาชิกสำเร็จ! กำลังกลับไปหน้า Login...");
            setTimeout(() => window.location.href = 'index.html', 1500);
        } else {
            updateStatus('danger', "❌ ชื่อนี้ถูกใช้ไปแล้ว หรือเซิร์ฟเวอร์ขัดข้อง");
        }
    } catch (e) { updateStatus('danger', "❌ ไม่สามารถสมัครสมาชิกได้"); }
}

async function preLoginCheck() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    if (!username || !password) return updateStatus('danger', "⚠️ กรุณากรอกให้ครบ");

    updateStatus('loading', "🔍 ตรวจสอบความปลอดภัยอุปกรณ์...");
    try {
        const fingerprint = getSecureFp();
        const device = `Screen:${screen.width}x${screen.height} | CPU:${navigator.hardwareConcurrency} | ${navigator.platform}`;

        const riskRes = await fetch('/api/assess', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, device, fingerprint })
        });
        const { risk_level, logId } = await riskRes.json();

        if (risk_level === "HIGH") {
            return updateStatus('danger', "🚨 ระงับการเข้าถึงเนื่องจากความเสี่ยงสูง");
        } 
        
        // 2. ถ้าเป็น MEDIUM ให้ไปหน้า MFA
        if (risk_level === "MEDIUM") {
            updateStatus('success', "🛡️ ตรวจพบอุปกรณ์ใหม่ กรุณายืนยันรหัสผ่านทางอีเมล...");
            setTimeout(() => {
                window.location.href = `mfa.html?logId=${logId}&username=${username}`;
            }, 1500);
            return;
        }

        // 3. ถ้าเป็น LOW (หรือปกติ) ให้ล็อกอินต่อ
        const authRes = await fetch('/api/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'login', username, password, fingerprint })
        });
        const isOk = authRes.ok;

        // อัปเดตผลลัพธ์ลง Log
        await fetch('/api/update-risk', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ logId, success: isOk })
        });

        if (isOk) {
            updateStatus('success', "✅ ยินดีต้อนรับ!");
            setTimeout(() => window.location.href = 'welcome.html', 1000);
        } else {
            updateStatus('danger', "❌ ชื่อผู้ใช้หรือรหัสผ่านผิด");
        }
    } catch (e) { updateStatus('danger', "❌ ระบบขัดข้อง"); }
}