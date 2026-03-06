function updateStatus(type, msg) {
    const box = document.getElementById('status-box');
    if (!box) return;
    box.style.display = 'block'; box.innerText = msg;
    box.style.background = type === 'danger' ? 'rgba(239,68,68,0.2)' : (type === 'success' ? 'rgba(34,197,94,0.2)' : '#334155');
    box.style.color = type === 'danger' ? '#f87171' : (type === 'success' ? '#4ade80' : 'white');
}

function getSecureFp() {
    const hardware = [screen.width + "x" + screen.height, navigator.hardwareConcurrency || 0, navigator.platform];
    return btoa(hardware.join("|")).substring(0, 128);
}

function validateInputs(username, password) {
    const userRegex = /^[a-zA-Z0-9]+$/;
    const passRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!userRegex.test(username)) return "Username ต้องเป็นภาษาอังกฤษและตัวเลขเท่านั้น";
    if (!passRegex.test(password)) return "Password ไม่ตรงตามมาตรฐานความปลอดภัย";
    return null;
}

// ----------------- สมัครสมาชิก -----------------
async function handleRegister() {
    const username = document.getElementById('username')?.value.trim();
    const email = document.getElementById('email')?.value.trim();
    const password = document.getElementById('password')?.value.trim();
    
    if (!username || !email || !password) return updateStatus('danger', "⚠️ กรุณากรอกให้ครบทุกช่อง");
    const error = validateInputs(username, password);
    if (error) return updateStatus('danger', `⚠️ ${error}`);

    updateStatus('loading', "⏳ กำลังสร้างบัญชี...");
    try {
        const res = await fetch('/api/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'register', username, email, password })
        });
        if (res.ok) {
            updateStatus('success', "✅ สมัครสำเร็จ! กำลังไปหน้า Login...");
            setTimeout(() => window.location.href = 'index.html', 1500);
        } else {
            const data = await res.json();
            updateStatus('danger', `❌ ${data.error || "มีข้อผิดพลาด"}`);
        }
    } catch (e) { updateStatus('danger', "❌ ระบบขัดข้อง"); }
}

// ----------------- ล็อกอิน และเช็ค Risk -----------------
async function preLoginCheck() {
    const username = document.getElementById('username')?.value.trim();
    const password = document.getElementById('password')?.value.trim();
    const remember = document.getElementById('remember-device')?.checked; // ดึงค่าจำเครื่อง

    if (!username || !password) return updateStatus('danger', "⚠️ กรุณากรอกให้ครบ");

    updateStatus('loading', "🔍 กำลังตรวจสอบความปลอดภัย...");
    try {
        const fingerprint = getSecureFp();
        const device = `Screen:${screen.width}x${screen.height} | CPU:${navigator.hardwareConcurrency}`;

        // 1. ประเมินความเสี่ยงเพื่อเอา logId และ risk_level
        const riskRes = await fetch('/api/assess', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, device, fingerprint })
        });
        const riskData = await riskRes.json();

        if (riskData.risk_level === "HIGH") {
            return updateStatus('danger', "🚨 ความเสี่ยงสูง ระงับการเข้าถึงชั่วคราว");
        }
        
        // 2. *** สำคัญมาก *** ต้องเรียก /api/auth เพื่อเช็ครหัสผ่านก่อน!
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
                remember: remember
            })
        });

        const authData = await authRes.json();

        if (authRes.ok) {
            // ถ้าหลังบ้านยืนยันว่ารหัสถูก และต้องทำ MFA (เพราะเป็นเครื่องใหม่)
            if (authData.mfa_required) {
                updateStatus('success', "🛡️ อุปกรณ์ใหม่! กรุณายืนยันรหัสในอีเมล...");
                setTimeout(() => {
                    window.location.href = `mfa.html?logId=${riskData.logId}&remember=${remember}`;
                }, 1500);
            } else {
                // ล็อกอินสำเร็จ (เครื่องเดิม/ความเสี่ยงต่ำ)
                updateStatus('success', "✅ ล็อกอินสำเร็จ!");
                setTimeout(() => window.location.href = 'welcome.html', 1000);
            }
        } else {
            // ถ้ารหัสผิดตั้งแต่ด่านนี้
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
    const remember = urlParams.get('remember'); // ดึงค่า remember ที่ส่งต่อมา

    if (!code || !logId) return updateStatus('danger', "⚠️ ข้อมูลไม่ครบถ้วน");

    updateStatus('loading', "⏳ กำลังตรวจสอบรหัส...");
    try {
        const res = await fetch('/api/verify-mfa', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                logId, 
                code, 
                remember: remember === 'true' // ส่งค่า boolean ไปให้หลังบ้าน
            })
        });
        
        if (res.ok) {
            updateStatus('success', "✅ ยืนยันตัวตนสำเร็จ!");
            setTimeout(() => window.location.href = 'welcome.html', 1000);
        } else {
            const data = await res.json();
            updateStatus('danger', `❌ ${data.error || "รหัสไม่ถูกต้อง"}`);
        }
    } catch (e) { 
        updateStatus('danger', "❌ ระบบขัดข้อง"); 
    }
}