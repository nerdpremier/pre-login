import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

    try {
        await client.connect();
        const { username, device, fingerprint } = req.body;
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        // 1. เช็คแค่ว่า User มีตัวตนไหม และดึง Fingerprint มาเทียบ
        const userRes = await client.query("SELECT authorized_fingerprint FROM users WHERE username = $1", [username]);
        
        // ถ้าไม่เจอ User ให้ตีเป็น LOW เพื่อไปให้ด่าน api/auth ตอบว่า "รหัสผิด" (ป้องกันการเดาชื่อ User)
        if (userRes.rows.length === 0) return res.status(200).json({ risk_level: "LOW", logId: null });

        const { authorized_fingerprint: savedFp } = userRes.rows[0];
        const fp_match = savedFp === fingerprint;

        // 2. คำนวณความเสี่ยง (MEDIUM ถ้าเครื่องไม่ตรง)
        let score = 0.1;
        if (!fp_match) score += 0.4; 
        const level = score >= 0.7 ? "HIGH" : (score >= 0.4 ? "MEDIUM" : "LOW");

        // 3. บันทึกลงตาราง login_risks (ยังไม่สร้าง mfaCode ที่นี่)
        const result = await client.query(
            `INSERT INTO login_risks (username, ip_address, device_info, current_fingerprint, risk_level, is_success) 
             VALUES ($1, $2, $3, $4, $5, FALSE) RETURNING id`,
            [username, ip, device, fingerprint, level]
        );

        res.status(200).json({ risk_level: level, logId: result.rows[0].id });
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    } finally { 
        await client.end(); 
    }
}