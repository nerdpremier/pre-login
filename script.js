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