// ฟังก์ชันแสดงสถานะ
function updateStatus(type, msg) {
    const box = document.getElementById('status-box');
    if (!box) return;
    box.style.display = 'block'; box.innerText = msg;
    box.style.background = type === 'danger' ? 'rgba(239,68,68,0.2)' : (type === 'success' ? 'rgba(34,197,94,0.2)' : '#334155');
    box.style.color = type === 'danger' ? '#f87171' : (type === 'success' ? '#4ade80' : 'white');
}

// สร้างลายนิ้วมือ (Hardware-First)
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

// --- ส่วนที่เพิ่มใหม่: ตรวจจับการกด Enter ---
document.addEventListener('DOMContentLoaded', () => {
    const inputs = document.querySelectorAll('input');
    inputs.forEach(input => {
        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                // ถ้าอยู่ในหน้า Login ให้เรียก preLoginCheck
                // ถ้าอยู่ในหน้า Register ให้เรียก handleRegister
                if (document.querySelector('button').innerText.includes('Login')) {
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

    updateStatus('loading', "🔍 กำลังตรวจพิสูจน์เครื่องอุปกรณ์...");
    try {
        const fingerprint = getSecureFp();
        const device = `Screen:${screen.width}x${screen.height} | CPU:${navigator.hardwareConcurrency} | ${navigator.platform}`;

        const riskRes = await fetch('/api/assess', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, device, fingerprint })
        });
        const { risk_level, logId } = await riskRes.json();

        if (risk_level === "HIGH") return updateStatus('danger', "🚨 บล็อกการเข้าถึงเนื่องจากความเสี่ยงสูง");

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
            updateStatus('success', "✅ ยินดีต้อนรับ!");
            setTimeout(() => window.location.href = 'welcome.html', 800);
        } else {
            updateStatus('danger', "❌ รหัสผ่านไม่ถูกต้อง");
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