// Validation
const isStrongPass = (p) => p.length >= 8 && /[A-Z]/.test(p) && /[a-z]/.test(p) && /[0-9]/.test(p) && /\W/.test(p);
const isEng = (t) => /^[A-Za-z0-9]+$/.test(t);

function updateStatus(type, msg) {
    const box = document.getElementById('status-box');
    box.style.display = 'block'; box.innerText = msg;
    box.style.background = type === 'danger' ? 'rgba(239,68,68,0.1)' : 'rgba(34,197,94,0.1)';
    box.style.color = type === 'danger' ? '#f87171' : '#4ade80';
}

function getSecureFp() {
    const hw = [screen.width+"x"+screen.height, navigator.hardwareConcurrency||0, new Date().getTimezoneOffset(), screen.colorDepth, navigator.platform];
    return btoa(hw.join("|") + "|" + navigator.userAgent).substring(0, 128);
}

// Global Enter Key Handler
document.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        const btn = document.querySelector('button');
        if (btn.innerText.includes('Login')) preLoginCheck();
        else if (btn.innerText.includes('Register')) handleRegister();
        else if (btn.innerText.includes('Verify')) verifyMFA();
    }
});

async function preLoginCheck() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    if (!username || !password) return updateStatus('danger', "Fields cannot be empty.");

    updateStatus('loading', "🔍 Probing device fingerprint...");
    const fingerprint = getSecureFp();
    const device = `Screen:${screen.width}x${screen.height} | CPU:${navigator.hardwareConcurrency}`;

    const riskRes = await fetch('/api/assess', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, device, fingerprint })
    });
    const { risk_level, logId } = await riskRes.json();

    if (risk_level === "HIGH") return updateStatus('danger', "🚨 Blocked: High risk detected.");
    
    if (risk_level === "MEDIUM") {
        updateStatus('success', "🛡️ New device detected. Check your email for MFA code.");
        setTimeout(() => window.location.href = `mfa.html?logId=${logId}`, 1500);
        return;
    }

    const authRes = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'login', username, password, fingerprint })
    });

    await fetch('/api/update-risk', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ logId, success: authRes.ok }) });

    if (authRes.ok) {
        updateStatus('success', "✅ Authorized. Welcome!");
        setTimeout(() => window.location.href = 'welcome.html', 1000);
    } else {
        updateStatus('danger', "❌ Invalid username or password.");
    }
}

async function handleRegister() {
    const username = document.getElementById('username').value.trim();
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value.trim();

    if (!isEng(username)) return updateStatus('danger', "Username: English only.");
    if (!email.includes('@')) return updateStatus('danger', "Invalid email address.");
    if (!isStrongPass(password)) return updateStatus('danger', "Password: Need A-z, 0-9, @, 8+ chars.");

    const res = await fetch('/api/auth', { 
        method: 'POST', 
        headers: { 'Content-Type': 'application/json' }, 
        body: JSON.stringify({ action: 'register', username, email, password }) 
    });

    if (res.ok) {
        updateStatus('success', "✅ Registered! Redirecting to login...");
        setTimeout(() => window.location.href = 'index.html', 1500);
    } else { updateStatus('danger', "❌ Registration failed."); }
}