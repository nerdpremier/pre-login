let countdownTimer; // ประกาศไว้บนสุดเพื่อให้ใช้ได้ทุกฟังก์ชัน

// ----------------- Helper Functions -----------------

function updateStatus(type, msg) {
    const box = document.getElementById('status-box');
    if (!box) return;
    box.style.display = 'block';
    // ใช้ innerHTML เพื่อรองรับการแสดงผลกล่อง Countdown
    box.innerHTML = msg; 
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

function startCountdown(seconds) {
    const statusBox = document.getElementById('status-box');
    if (!statusBox) return;
    
    clearInterval(countdownTimer); // ล้าง Timer เก่าก่อนเริ่มใหม่
    let remaining = seconds;
    
    countdownTimer = setInterval(() => {
        if (remaining <= 0) {
            clearInterval(countdownTimer);
            updateStatus('success', "✅ หมดเวลาระงับแล้ว คุณสามารถลองใหม่ได้");
            return;
        }

        statusBox.innerHTML = `
            <div style="border: 2px solid #ef4444; padding: 15px; border-radius: 8px; background: rgba(239, 68, 68, 0.1); text-align: center;">
                <p style="color: #ef4444; font-weight: bold; margin: 0;">🚨 ความเสี่ยงสูง ระงับการเข้าถึงชั่วคราว</p>
                <div style="font-size: 32px; font-weight: bold; color: #ef4444; margin: 10px 0;">
                    ${remaining} วินาที
                </div>
                <p style="font-size: 12px; color: #94a3b8; margin: 0;">กรุณารอสักครู่เพื่อความปลอดภัยของบัญชี</p>
            </div>
        `;
        remaining--;
    }, 1000);
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
    const remember = document.getElementById('remember-device')?.checked;

    if (!username || !password) return updateStatus('danger', "⚠️ กรุณากรอกให้ครบ");

    updateStatus('loading', "🔍 กำลังตรวจสอบความปลอดภัย...");
    try {
        const fingerprint = getSecureFp();
        const device = `Screen:${screen.width}x${screen.height} | CPU:${navigator.hardwareConcurrency}`;

        const riskRes = await fetch('/api/assess', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, device, fingerprint })
        });
        const riskData = await riskRes.json();

        // กรณีติด HIGH RISK (โดนแบนชั่วคราว)
        if (riskData.risk_level === "HIGH") {
            startCountdown(60); 
            return;
        }
        
        const authRes = await fetch('/api/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                action: 'login', username, password, fingerprint,
                logId: riskData.logId,
                risk_level: riskData.risk_level,
                remember: remember
            })
        });

        const authData = await authRes.json();

        if (authRes.ok) {
            if (authData.mfa_required) {
                updateStatus('success', "🛡️ อุปกรณ์ใหม่! กรุณายืนยันรหัสในอีเมล...");
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
    const remember = urlParams.get('remember');

    if (!code || !logId) return updateStatus('danger', "⚠️ ข้อมูลไม่ครบถ้วน");

    updateStatus('loading', "⏳ กำลังตรวจสอบรหัส...");
    try {
        const res = await fetch('/api/verify-mfa', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                logId, 
                code, 
                remember: remember === 'true'
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

// ----------------- Keyboard Listeners -----------------
document.addEventListener('keypress', function (e) {
    if (e.key === 'Enter') {
        const mfaInput = document.getElementById('mfa-code');
        if (mfaInput && document.activeElement === mfaInput) {
            return verifyMFA();
        }

        const isRegisterPage = document.getElementById('email');
        if (isRegisterPage) {
            return handleRegister();
        }

        const isLoginPage = document.getElementById('password');
        if (isLoginPage) {
            return preLoginCheck();
        }
    }
});