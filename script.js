let isSubmitting = false;

function updateStatus(type, msg) {
    const box = document.getElementById('status-box');
    if (!box) return;

    box.style.display = 'block';
    box.innerText = msg;

    const styles = {
        danger: { bg: 'rgba(239,68,68,0.2)', color: '#f87171' },
        success: { bg: 'rgba(34,197,94,0.2)', color: '#4ade80' },
        loading: { bg: '#334155', color: '#ffffff' }
    };

    const s = styles[type] || styles.loading;
    box.style.background = s.bg;
    box.style.color = s.color;
}

function getSecureFp() {
    const hardware = [
        screen.width + "x" + screen.height,
        navigator.hardwareConcurrency || 0,
        navigator.platform,
        navigator.language,
        Intl.DateTimeFormat().resolvedOptions().timeZone
    ];

    return btoa(hardware.join("|")).substring(0, 128);
}

function validateInputs(username, password) {
    const userRegex = /^[a-zA-Z0-9]+$/;
    const passRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/;

    if (!userRegex.test(username))
        return "Username ต้องเป็นภาษาอังกฤษและตัวเลขเท่านั้น";

    if (!passRegex.test(password))
        return "Password ต้องมี a-z A-Z 0-9 และ special character";

    return null;
}

function validateEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ----------------- สมัครสมาชิก -----------------
async function handleRegister() {

    if (isSubmitting) return;
    isSubmitting = true;

    const username = document.getElementById('username')?.value.trim();
    const email = document.getElementById('email')?.value.trim();
    const password = document.getElementById('password')?.value.trim();

    if (!username || !email || !password) {
        updateStatus('danger', "⚠️ กรุณากรอกให้ครบทุกช่อง");
        isSubmitting = false;
        return;
    }

    if (!validateEmail(email)) {
        updateStatus('danger', "⚠️ Email ไม่ถูกต้อง");
        isSubmitting = false;
        return;
    }

    const error = validateInputs(username, password);
    if (error) {
        updateStatus('danger', `⚠️ ${error}`);
        isSubmitting = false;
        return;
    }

    updateStatus('loading', "⏳ กำลังสร้างบัญชี...");

    try {

        const res = await fetch('/api/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                action: 'register',
                username,
                email,
                password
            })
        });

        const data = await res.json().catch(() => ({}));

        if (res.ok) {
            updateStatus('success', "✅ สมัครสำเร็จ! กำลังไปหน้า Login...");
            setTimeout(() => window.location.href = 'index.html', 1500);
        } else {
            updateStatus('danger', `❌ ${data.error || "สมัครไม่สำเร็จ"}`);
        }

    } catch (e) {

        updateStatus('danger', "❌ ระบบขัดข้อง");

    }

    isSubmitting = false;
}

// ----------------- ล็อกอิน และเช็ค Risk -----------------
async function preLoginCheck() {

    if (isSubmitting) return;
    isSubmitting = true;

    const username = document.getElementById('username')?.value.trim();
    const password = document.getElementById('password')?.value.trim();

    if (!username || !password) {
        updateStatus('danger', "⚠️ กรุณากรอกให้ครบ");
        isSubmitting = false;
        return;
    }

    updateStatus('loading', "🔍 กำลังตรวจสอบอุปกรณ์...");

    try {

        const fingerprint = getSecureFp();

        const device =
            `Screen:${screen.width}x${screen.height} | CPU:${navigator.hardwareConcurrency}`;

        // -------- 1. Risk Assessment --------
        const riskRes = await fetch('/api/assess', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username,
                device,
                fingerprint
            })
        });

        const riskData = await riskRes.json();

        if (!riskRes.ok) {
            updateStatus('danger', riskData.error || "Risk service error");
            isSubmitting = false;
            return;
        }

        if (riskData.risk_level === "HIGH") {
            updateStatus('danger', "🚨 ความเสี่ยงสูง ระงับการเข้าถึง");
            isSubmitting = false;
            return;
        }

        // -------- 2. MFA Required --------
        if (riskData.risk_level === "MEDIUM") {

            updateStatus('success', "🛡️ อุปกรณ์ใหม่! กรุณายืนยันรหัสในอีเมล...");

            setTimeout(() => {
                window.location.href = `mfa.html?logId=${riskData.logId}`
            }, 1500);

            isSubmitting = false;
            return;
        }

        // -------- 3. Normal Login --------
        const authRes = await fetch('/api/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                action: 'login',
                username,
                password,
                fingerprint
            })
        });

        const authData = await authRes.json().catch(() => ({}));

        const isOk = authRes.ok;

        // update login risk log
        if (riskData.logId) {
            await fetch('/api/update-risk', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    logId: riskData.logId,
                    success: isOk
                })
            }).catch(() => {});
        }

        if (isOk) {

            updateStatus('success', "✅ ล็อกอินสำเร็จ!");

            setTimeout(() => {
                window.location.href = 'welcome.html'
            }, 1000);

        } else {

            updateStatus('danger', `❌ ${authData.error || "ชื่อผู้ใช้หรือรหัสผ่านผิด"}`);

        }

    } catch (e) {

        updateStatus('danger', "❌ ระบบขัดข้อง");

    }

    isSubmitting = false;
}

// ----------------- ยืนยัน MFA -----------------
async function verifyMFA() {

    if (isSubmitting) return;
    isSubmitting = true;

    const code = document.getElementById('mfa-code')?.value.trim();
    const logId = new URLSearchParams(window.location.search).get('logId');

    if (!code || !logId) {
        updateStatus('danger', "⚠️ ข้อมูลไม่ครบถ้วน");
        isSubmitting = false;
        return;
    }

    updateStatus('loading', "⏳ กำลังตรวจสอบรหัส...");

    try {

        const res = await fetch('/api/verify-mfa', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                logId,
                code
            })
        });

        const data = await res.json().catch(() => ({}));

        if (res.ok) {

            updateStatus('success', "✅ ยืนยันตัวตนสำเร็จ!");

            setTimeout(() => {
                window.location.href = 'welcome.html'
            }, 1000);

        } else {

            updateStatus('danger', `❌ ${data.error || "รหัสไม่ถูกต้อง"}`);

        }

    } catch (e) {

        updateStatus('danger', "❌ ระบบขัดข้อง");

    }

    isSubmitting = false;
}