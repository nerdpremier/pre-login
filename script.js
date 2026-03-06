// ฟังก์ชันแสดงสถานะบนหน้าจอ (UI Only)
function updateStatus(type, msg) {
    const box = document.getElementById('status-box');
    if (!box) return;
    box.style.display = 'block'; box.innerText = msg;
    box.style.background = type === 'danger' ? 'rgba(239,68,68,0.2)' : (type === 'success' ? 'rgba(34,197,94,0.2)' : '#334155');
    box.style.color = type === 'danger' ? '#f87171' : (type === 'success' ? '#4ade80' : 'white');
}

// สร้างลายนิ้วมือ Hardware-First
function getSecureFp() {
    const hardware = [
        screen.width + "x" + screen.height,
        navigator.hardwareConcurrency || 0,
        new Date().getTimezoneOffset(),
        screen.colorDepth,
        navigator.platform,
        navigator.language
    ];
    const raw = hardware.join("|") + "|" + navigator.userAgent;
    return btoa(raw).substring(0, 128);
}

// ระบบตรวจจับการกด Enter
document.addEventListener('DOMContentLoaded', () => {
    const inputs = document.querySelectorAll('input');
    inputs.forEach(input => {
        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                const btn = document.querySelector('button');
                if (btn.innerText.includes('Login') || btn.innerText.includes('เข้าสู่ระบบ')) {
                    preLoginCheck();
                } else {
                    handleRegister();
                }
            }
        });
    });
});

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

        if (risk_level === "HIGH") return updateStatus('danger', "🚨 ระงับการเข้าถึงเนื่องจากความเสี่ยงสูง");

        const authRes = await fetch('/api/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'login', username, password, fingerprint })
        });
        const isOk = authRes.ok;

        await fetch('/api/update-risk', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ logId, success: isOk })
        });

        if (isOk) {
            updateStatus('success', "✅ ยินดีต้อนรับ! กำลังพาคุณไป...");
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

    updateStatus('loading', "⏳ กำลังสร้างบัญชี...");
    try {
        const res = await fetch('/api/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'register', username, password })
        });

        if (res.ok) {
            // แก้ไขตรงนี้: ไม่ใช้ alert แต่แสดงบนหน้าจอแทน
            updateStatus('success', "✅ สมัครสมาชิกสำเร็จ! กำลังกลับไปหน้า Login...");
            setTimeout(() => window.location.href = 'index.html', 1500);
        } else {
            updateStatus('danger', "❌ ชื่อนี้ถูกใช้ไปแล้ว หรือเซิร์ฟเวอร์ขัดข้อง");
        }
    } catch (e) { updateStatus('danger', "❌ ไม่สามารถสมัครสมาชิกได้"); }
}

// ฟังก์ชันตรวจสอบความปลอดภัย (เพิ่มเข้าไปใน script.js)
function validateInputs(username, password) {
    // 1. ตรวจสอบ Username: ภาษาอังกฤษและตัวเลขเท่านั้น (A-Z, a-z, 0-9)
    const userRegex = /^[a-zA-Z0-9]+$/;
    if (!userRegex.test(username)) {
        return "Username ต้องเป็นภาษาอังกฤษและตัวเลขเท่านั้น";
    }

    // 2. ตรวจสอบ Password มาตรฐานความปลอดภัย:
    // อย่างน้อย 8 ตัว, มีพิมพ์ใหญ่, พิมพ์เล็ก, ตัวเลข และอักขระพิเศษ (@$!%*?&)
    const passRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!passRegex.test(password)) {
        return "รหัสผ่านต้องมี 8 ตัวขึ้นไป, มีพิมพ์ใหญ่, พิมพ์เล็ก, ตัวเลข และสัญลักษณ์ (@$!%*?&)";
    }
    return null; // ผ่านการตรวจสอบ
}

// แก้ไขฟังก์ชัน handleRegister
async function handleRegister() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    
    // เรียกใช้ตัวตรวจสอบ
    const error = validateInputs(username, password);
    if (error) return updateStatus('danger', `⚠️ ${error}`);

    updateStatus('loading', "⏳ กำลังสร้างบัญชี...");
    // ... โค้ด fetch /api/auth เดิมของคุณ ...
}

// แก้ไขฟังก์ชัน preLoginCheck
async function preLoginCheck() {
    // ... (ส่วนดึงค่า username, password, fingerprint เหมือนเดิม) ...
    
    try {
        const riskRes = await fetch('/api/assess', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, device, fingerprint })
        });
        const { risk_level, logId } = await riskRes.json();

        if (risk_level === "HIGH") {
            return updateStatus('danger', "🚨 ระงับการเข้าถึงเนื่องจากความเสี่ยงสูง");
        } 
        
        // เพิ่มส่วนนี้: ถ้าเป็น MEDIUM ให้ไปหน้า MFA
        if (risk_level === "MEDIUM") {
            updateStatus('success', "🛡️ ตรวจพบอุปกรณ์ใหม่ กรุณายืนยันรหัสผ่านทางอีเมล...");
            setTimeout(() => {
                window.location.href = `mfa.html?logId=${logId}&username=${username}`;
            }, 1500);
            return;
        }

        // ถ้าเป็น LOW ให้ล็อกอินปกติ
        // ... (โค้ด fetch /api/auth และ update-risk เดิมของคุณ) ...
    } catch (e) { updateStatus('danger', "❌ ระบบขัดข้อง"); }
}