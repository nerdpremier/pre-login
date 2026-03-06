function updateStatus(type, msg) {
    const box = document.getElementById('status-box');
    if (!box) return;
    box.style.display = 'block'; 
    box.innerText = msg;
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
    const remember = document.getElementById('remember-device')?.checked; // ดึงค่า Checkbox

    if (!username || !password) return updateStatus('danger', "⚠️ กรุณากรอกให้ครบ");

    updateStatus('loading', "🔍 กำลังตรวจสอบอุปกรณ์...");
    try {
        const fingerprint = getSecureFp();
        const device = `Screen:${screen.width}x${screen.height} | CPU:${navigator.hardwareConcurrency}`;

        // 1. ประเมินความเสี่ยงเบื้องต้น (เพื่อเอา logId)
        const riskRes = await fetch('/api/assess', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, device, fingerprint })
        });
        const riskData = await riskRes.json();

        if (riskData.risk_level === "HIGH") {
            return updateStatus('danger', "🚨 ความเสี่ยงสูงเกินไป ระงับการเข้าถึงชั่วคราว");
        }
        
        // 2. ส่งไปเช็ครหัสผ่านที่ /api/auth (ด่านสำคัญ)
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
            // ถ้าหลังบ้านบอกว่าต้องทำ MFA
            if (authData.mfa_required) {
                updateStatus('success', "🛡️ ตรวจพบอุปกรณ์ใหม่! กรุณายืนยันรหัสในอีเมล...");
                setTimeout(() => {
                    window.location.href = `mfa.html?logId=${riskData.logId}&remember=${remember}`;
                }, 1500);
            } else {
                // ล็อกอินสำเร็จ (เครื่องเดิม)
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

// ----------------- ยืนยันรหัส MFA (ใช้ในหน้า mfa.html) -----------------
async function verifyMFA() {
    const code = document.getElementById('mfa-code')?.value.trim();
    const urlParams = new URLSearchParams(window.location.search);
    const logId = urlParams.get('logId');
    const remember = urlParams.get('remember');

    if (!code || code.length !== 6) return updateStatus('danger', "⚠️ กรุณากรอกรหัส 6 หลัก");

    updateStatus('loading', "⏳ กำลังตรวจสอบรหัส...");
    try {
        const res = await fetch('/api/verify-mfa', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ logId, code, remember })
        });

        if (res.ok) {
            updateStatus('success', "✅ ยืนยันสำเร็จ! กำลังเข้าสู่หน้าหลัก...");
            setTimeout(() => window.location.href = 'welcome.html', 1500);
        } else {
            const data = await res.json();
            updateStatus('danger', `❌ ${data.error || "รหัสไม่ถูกต้อง"}`);
        }
    } catch (e) {
        updateStatus('danger', "❌ ระบบขัดข้อง");
    }
}

document.addEventListener('keypress', function (e) {
    if (e.key === 'Enter') {
        const mfaInput = document.getElementById('mfa-code');
        if (mfaInput) {
            verifyMFA();
        } else {
            preLoginCheck();
        }
    }
});