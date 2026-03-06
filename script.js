function updateStatus(type, msg) {
    const box = document.getElementById('status-box');
    box.style.display = 'block'; box.innerText = msg;
    box.style.background = type === 'danger' ? 'rgba(239,68,68,0.2)' : 'rgba(34,197,94,0.2)';
    box.style.color = type === 'danger' ? '#f87171' : '#4ade80';
}

function getFp() {
    return btoa(navigator.userAgent + screen.width + navigator.language).substring(0, 32);
}

async function handleRegister() {
    const username = document.getElementById('username').value.trim();
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value.trim();

    if(!username || !email || !password) return updateStatus('danger', "Fields empty!");

    const res = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'register', username, email, password })
    });

    if (res.ok) {
        updateStatus('success', "✅ Success! Redirecting...");
        setTimeout(() => window.location.href = 'index.html', 1500);
    } else { updateStatus('danger', "❌ User exists."); }
}

async function preLoginCheck() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    const fingerprint = getFp();

    updateStatus('loading', "⏳ Checking security...");
    const res = await fetch('/api/assess', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, fingerprint })
    });
    const { risk_level, logId } = await res.json();

    if (risk_level === "MEDIUM") {
        updateStatus('success', "🛡️ New device! Code sent to email.");
        setTimeout(() => window.location.href = `mfa.html?logId=${logId}`, 1500);
        return;
    }

    const authRes = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'login', username, password, fingerprint })
    });

    if (authRes.ok) {
        updateStatus('success', "✅ Welcome!");
        setTimeout(() => window.location.href = 'welcome.html', 1000);
    } else { updateStatus('danger', "❌ Login failed."); }
}