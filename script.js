// ... (updateStatus, getSecureFp, validateInputs เหมือนเดิม) ...

// ----------------- ล็อกอิน และเช็ค Risk -----------------
async function preLoginCheck() {
    const username = document.getElementById('username')?.value.trim();
    const password = document.getElementById('password')?.value.trim();
    // ดึงค่า Checkbox ว่าผู้ใช้ต้องการให้จำเครื่องไหม
    const remember = document.getElementById('remember-device')?.checked;

    if (!username || !password) return updateStatus('danger', "⚠️ กรุณากรอกให้ครบ");

    updateStatus('loading', "🔍 กำลังตรวจสอบอุปกรณ์...");
    try {
        const fingerprint = getSecureFp();
        const device = `Screen:${screen.width}x${screen.height} | CPU:${navigator.hardwareConcurrency}`;

        // 1. ประเมินความเสี่ยงเบื้องต้น
        const riskRes = await fetch('/api/assess', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, device, fingerprint })
        });
        const riskData = await riskRes.json();

        if (riskData.risk_level === "HIGH") {
            return updateStatus('danger', "🚨 ความเสี่ยงสูงเกินไป ระงับการเข้าถึงชั่วคราว");
        }
        
        // 2. ส่งไปเช็ครหัสผ่าน
        const authRes = await fetch('/api/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                action: 'login', 
                username, 
                password, 
                fingerprint,
                logId: riskData.logId,
                risk_level: riskData.risk_level,
                remember: remember // ส่งสถานะการจดจำเครื่องไปให้หลังบ้าน
            })
        });

        const authData = await authRes.json();

        if (authRes.ok) {
            if (authData.mfa_required) {
                updateStatus('success', "🛡️ ตรวจพบอุปกรณ์ใหม่! ส่งรหัสยืนยันไปที่อีเมลแล้ว...");
                // ส่ง remember พ่วงไปใน URL เพื่อให้หน้า mfa.html ส่งต่อให้ api/verify-mfa ได้
                setTimeout(() => {
                    window.location.href = `mfa.html?logId=${riskData.logId}&remember=${remember}`;
                }, 1500);
            } else {
                updateStatus('success', "✅ ล็อกอินสำเร็จ!");
                setTimeout(() => window.location.href = 'welcome.html', 1000);
            }
        } else {
            updateStatus('danger', `❌ ${authData.error || "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"}`);
        }

    } catch (e) { 
        console.error(e);
        updateStatus('danger', "❌ ระบบขัดข้อง"); 
    }
}

// ----------------- ยืนยันรหัส MFA -----------------
async function verifyMFA() {
    const code = document.getElementById('mfa-code')?.value.trim();
    const urlParams = new URLSearchParams(window.location.search);
    const logId = urlParams.get('logId');
    const remember = urlParams.get('remember') === 'true'; // ดึงค่าการจดจำจาก URL

    if (!code || code.length !== 6) return updateStatus('danger', "⚠️ กรุณากรอกรหัส 6 หลัก");
    if (!logId) return updateStatus('danger', "⚠️ ข้อมูลเซสชันไม่ถูกต้อง");

    updateStatus('loading', "⏳ กำลังตรวจสอบรหัส...");
    try {
        const res = await fetch('/api/verify-mfa', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                logId, 
                code, 
                remember: remember // ส่งไปบอก API ว่าให้บันทึก fingerprint ลงตาราง users หรือไม่
            })
        });

        if (res.ok) {
            updateStatus('success', "✅ ยืนยันตัวตนสำเร็จ! กำลังเข้าสู่หน้าหลัก...");
            setTimeout(() => window.location.href = 'welcome.html', 1500);
        } else {
            const data = await res.json();
            updateStatus('danger', `❌ ${data.error || "รหัสไม่ถูกต้อง"}`);
        }
    } catch (e) {
        updateStatus('danger', "❌ ระบบขัดข้อง");
    }
}