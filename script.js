async function handleRegister() {
    const username = document.getElementById('username').value.trim();
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value.trim();

    if(!username || !email || !password) {
        return updateStatus('danger', "⚠️ Please fill all fields.");
    }

    updateStatus('loading', "⏳ Registering your account...");

    try {
        const res = await fetch('/api/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'register', username, email, password })
        });

        const data = await res.json();

        if (res.ok) {
            updateStatus('success', "✅ Registration Successful! Redirecting...");
            setTimeout(() => window.location.href = 'index.html', 1500);
        } else {
            // โชว์ Error จริงที่ส่งมาจาก API (เช่น "Username already taken")
            updateStatus('danger', `❌ ${data.error}`);
        }
    } catch (e) {
        updateStatus('danger', "❌ Connection error. Check your Vercel logs.");
    }
}