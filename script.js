// ฟังก์ชันช่วยแสดงสถานะ
function updateStatus(type, msg) {
    const box = document.getElementById('status-box');
    box.style.display = 'block';
    box.innerText = msg;
    box.style.background = type === 'danger' ? 'rgba(239,68,68,0.2)' : 'rgba(34,197,94,0.2)';
    box.style.color = type === 'danger' ? '#f87171' : '#4ade80';
}

// สร้าง Fingerprint อย่างง่าย
function getFp() {
    return btoa(navigator.userAgent + screen.width).substring(0, 16);
}

// 1. ระบบสมัครสมาชิก
async function handleRegister() {
    const username = document.getElementById('username').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    const res = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'register', username, email, password })
    });
    const data = await res.json();
    if (res.ok) {
        updateStatus('success', "✅ Success! Going to login...");
        setTimeout(() => window.location.href = 'index.html', 1500);
    } else {
        updateStatus('danger', "❌ " + data.error);
    }
}

// 2. ระบบเช็คความเสี่ยงก่อน Login
async function preLoginCheck() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const fingerprint = getFp();

    const res = await fetch('/api/assess', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, fingerprint })
    });
    const data = await res.json();

    if (data.risk_level === "MEDIUM") {
        window.location.href = `mfa.html?logId=${data.logId}`;
    } else {
        // ถ้าความเสี่ยงต่ำ ให้ข้ามไป Login ทันที
        const authRes = await fetch('/api/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'login', username, password, fingerprint })
        });
        if (authRes.ok) window.location.href = 'welcome.html';
        else updateStatus('danger', "❌ Invalid credentials");
    }
}

// 3. ระบบยืนยัน OTP
async function verifyMFA() {
    const logId = new URLSearchParams(window.location.search).get('logId');
    const code = document.getElementById('mfa-input').value;

    const res = await fetch('/api/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ logId, code })
    });

    if (res.ok) {
        updateStatus('success', "✅ Identity Verified!");
        setTimeout(() => window.location.href = 'welcome.html', 1000);
    } else {
        updateStatus('danger', "❌ Invalid Code");
    }
}