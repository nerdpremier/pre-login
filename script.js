async function preLoginCheck() {
    const user = document.getElementById('username').value;
    const msg = document.getElementById('status-msg');
    if (!user) return alert("กรุณาระบุ Username");

    msg.innerText = "🔍 กำลังประเมินความปลอดภัย...";

    try {
        // 1. ดึง IP และ Location (ใช้ Public API)
        const ipRes = await fetch('https://ipapi.co/json/');
        const ipInfo = await ipRes.json();

        // 2. ดึงข้อมูล Device
        const device = `${navigator.platform} | ${navigator.userAgent}`;

        // 3. ตรวจสอบ Fingerprint (ใช้การ Hash เครื่องเบื้องต้น)
        const currentFp = btoa(device).substring(0, 16);
        const savedFp = localStorage.getItem('last_fp');
        const isMismatch = savedFp && savedFp !== currentFp;
        localStorage.setItem('last_fp', currentFp); // บันทึกไว้เทียบครั้งหน้า

        // 4. ส่งไปให้ Backend ประเมิน Risk
        const response = await fetch('/api/assess', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: user,
                ip: ipInfo.ip,
                location: `${ipInfo.city}, ${ipInfo.country_name}`,
                device: device,
                fp_mismatch: isMismatch
            })
        });

        const result = await response.json();
        handleResult(result);

    } catch (err) {
        msg.innerText = "❌ เกิดข้อผิดพลาดในการตรวจสอบ";
    }
}

function handleResult(res) {
    const msg = document.getElementById('status-msg');
    
    if (res.risk_level === "HIGH") {
        msg.style.color = "#ff4444";
        msg.innerText = "🚨 ความเสี่ยงสูง: ระบบถูกระงับชั่วคราว (กรุณาติดต่อ Admin)";
    } else if (res.risk_level === "MEDIUM") {
        msg.style.color = "#ffbb33";
        msg.innerText = "⚠️ ความเสี่ยงปานกลาง: กรุณายืนยันรหัสผ่านอีกครั้งผ่าน Email";
    } else {
        msg.style.color = "#00C851";
        msg.innerText = "✅ ปลอดภัย: กำลังเข้าสู่ระบบ...";
        // ทำขั้นตอน Login ปกติที่นี่
    }
}