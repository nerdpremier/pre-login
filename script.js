let pendingMfaLogId = null;

function updateStatus(type, msg) {
    const box = document.getElementById('status-box');
    if (!box) return;
    box.style.display = 'block';
    box.innerText = msg;
    box.style.background = type === 'danger' ? 'rgba(239,68,68,0.2)' : (type === 'success' ? 'rgba(34,197,94,0.2)' : '#334155');
    box.style.color = type === 'danger' ? '#f87171' : (type === 'success' ? '#4ade80' : 'white');
}

function getSecureFp() {
    const hardware = [
        screen.width + 'x' + screen.height,
        navigator.hardwareConcurrency || 0,
        new Date().getTimezoneOffset(),
        screen.colorDepth,
        navigator.platform,
        navigator.language
    ];
    const raw = hardware.join('|') + '|' + navigator.userAgent;
    return btoa(raw).substring(0, 128);
}

function toggleMfaSection(show) {
    const section = document.getElementById('mfa-section');
    if (!section) return;
    section.style.display = show ? 'block' : 'none';
}

document.addEventListener('DOMContentLoaded', () => {
    const inputs = document.querySelectorAll('input');
    inputs.forEach(input => {
        input.addEventListener('keypress', (e) => {
            if (e.key !== 'Enter') return;

            if (document.getElementById('mfa-code') && document.activeElement?.id === 'mfa-code') {
                verifyMfa();
                return;
            }

            const btn = document.querySelector('button');
            if (btn && (btn.innerText.includes('Login') || btn.innerText.includes('เข้าสู่ระบบ'))) {
                preLoginCheck();
            } else {
                handleRegister();
            }
        });
    });
});

async function preLoginCheck() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    if (!username || !password) return updateStatus('danger', '⚠️ กรุณากรอกให้ครบ');

    updateStatus('loading', '🔍 ตรวจสอบความปลอดภัยอุปกรณ์...');
    toggleMfaSection(false);

    try {
        const fingerprint = getSecureFp();
        const device = `Screen:${screen.width}x${screen.height} | CPU:${navigator.hardwareConcurrency} | ${navigator.platform}`;

        const riskRes = await fetch('/api/assess', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, device, fingerprint })
        });
        const riskData = await riskRes.json();

        if (!riskRes.ok) {
            return updateStatus('danger', `❌ ${riskData.error || 'ประเมินความเสี่ยงไม่สำเร็จ'}`);
        }

        const { risk_level, logId } = riskData;

        if (risk_level === 'HIGH') {
            return updateStatus('danger', '🚨 ระงับการเข้าถึงเนื่องจากความเสี่ยงสูง');
        }

        const authRes = await fetch('/api/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'login', username, password, fingerprint, riskLevel: risk_level, logId })
        });
        const authData = await authRes.json();

        if (authData.requiresMfa) {
            pendingMfaLogId = authData.logId;
            toggleMfaSection(true);
            updateStatus('loading', `📧 ส่งรหัส MFA ไปที่ ${authData.maskedEmail || 'อีเมลของคุณ'} แล้ว`);
            return;
        }

        await fetch('/api/update-risk', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ logId, success: authRes.ok })
        });

        if (authRes.ok) {
            updateStatus('success', '✅ ยินดีต้อนรับ! กำลังพาคุณไป...');
            setTimeout(() => window.location.href = 'welcome.html', 1000);
        } else {
            updateStatus('danger', `❌ ${authData.error || 'ชื่อผู้ใช้หรือรหัสผ่านผิด'}`);
        }
    } catch (e) {
        updateStatus('danger', `❌ ${e.message || 'ระบบขัดข้อง'}`);
    }
}

async function verifyMfa() {
    const code = document.getElementById('mfa-code')?.value.trim();
    if (!pendingMfaLogId || !code) return updateStatus('danger', '⚠️ กรุณากรอกรหัส MFA');

    updateStatus('loading', '⏳ กำลังตรวจสอบรหัส MFA...');
    try {
        const res = await fetch('/api/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ logId: pendingMfaLogId, code })
        });
        const data = await res.json();

        if (res.ok) {
            updateStatus('success', '✅ ยืนยันตัวตนสำเร็จ กำลังเข้าสู่ระบบ...');
            setTimeout(() => window.location.href = 'welcome.html', 1000);
        } else {
            updateStatus('danger', `❌ ${data.error || 'รหัสไม่ถูกต้อง'}`);
        }
    } catch (e) {
        updateStatus('danger', `❌ ${e.message || 'ไม่สามารถยืนยัน MFA ได้'}`);
    }
}

async function handleRegister() {
    const username = document.getElementById('username').value.trim();
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value.trim();
    if (!username || !email || !password) return updateStatus('danger', '⚠️ กรอกข้อมูลไม่ครบ');

    updateStatus('loading', '⏳ กำลังสร้างบัญชี...');
    try {
        const res = await fetch('/api/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'register', username, email, password })
        });
        const data = await res.json();

        if (res.ok) {
            updateStatus('success', '✅ สมัครสมาชิกสำเร็จ! กำลังกลับไปหน้า Login...');
            setTimeout(() => window.location.href = 'index.html', 1500);
        } else {
            updateStatus('danger', `❌ ${data.error || 'สมัครสมาชิกไม่สำเร็จ'}`);
        }
    } catch (e) {
        updateStatus('danger', `❌ ${e.message || 'ไม่สามารถสมัครสมาชิกได้'}`);
    }
}
