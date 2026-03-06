// ฟังก์ชัน Register
async function handleRegister() {
    const user = document.getElementById('username').value;
    const pass = document.getElementById('password').value;
    
    const res = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'register', username: user, password: pass })
    });
    const data = await res.json();
    alert(data.message || data.error);
}

// ฟังก์ชัน Login (ที่มี Risk Assessment นำหน้า)
async function preLoginCheck() {
    const user = document.getElementById('username').value;
    const pass = document.getElementById('password').value;
    const msg = document.getElementById('status-msg');

    // --- STEP 1: ประเมินความเสี่ยง (ใช้โค้ดเดิมที่เราทำ) ---
    const riskRes = await fetch('/api/assess', { /* ... ข้อมูล Device/IP ... */ });
    const riskData = await riskRes.json();

    if (riskData.risk_level === "HIGH") {
        msg.innerText = "🚨 ความเสี่ยงสูงเกินไป ระบบปฏิเสธการเข้าถึง";
        return;
    }

    // --- STEP 2: ถ้าความเสี่ยงผ่าน (LOW/MEDIUM) ให้ลอง Login จริง ---
    const authRes = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'login', username: user, password: pass })
    });

    const authData = await authRes.json();
    if (authRes.ok) {
        msg.style.color = "green";
        msg.innerText = "✅ Login สำเร็จ! ยินดีต้อนรับ " + authData.user;
        // ย้ายหน้าไป Dashboard
    } else {
        msg.style.color = "red";
        msg.innerText = "❌ " + authData.error;
    }
}

// ฟังก์ชันช่วยแสดงข้อความสถานะ
function updateStatus(type, message) {
    const box = document.getElementById('status-box');
    const msg = document.getElementById('status-msg');
    box.className = 'status-visible';
    msg.innerText = message;

    if (type === 'loading') { box.style.background = '#334155'; box.style.color = 'white'; }
    if (type === 'success') { box.style.background = 'rgba(34, 197, 94, 0.2)'; box.style.color = '#4ade80'; }
    if (type === 'warning') { box.style.background = 'rgba(245, 158, 11, 0.2)'; box.style.color = '#fbbf24'; }
    if (type === 'danger') { box.style.background = 'rgba(239, 68, 68, 0.2)'; box.style.color = '#f87171'; }
}

async function handleRegister() {
    const user = document.getElementById('username').value;
    const pass = document.getElementById('password').value;
    if(!user || !pass) return alert("กรุณากรอกให้ครบ");

    updateStatus('loading', "⏳ กำลังสร้างบัญชี...");
    const res = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'register', username: user, password: pass })
    });
    const data = await res.json();
    if(res.ok) updateStatus('success', "✅ สมัครสมาชิกสำเร็จ! ลอง Login ได้เลย");
    else updateStatus('danger', "❌ " + data.error);
}

// ... ส่วนของ preLoginCheck ให้เพิ่มการเรียก updateStatus ตามความเหมาะสม ...