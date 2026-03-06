import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

    try {
        await client.connect();
        const { username, device, fingerprint } = req.body;
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        const userRes = await client.query("SELECT email, authorized_fingerprint FROM users WHERE username = $1", [username]);
        if (userRes.rows.length === 0) return res.status(200).json({ risk_level: "LOW", logId: null });

        const { email, authorized_fingerprint: savedFp } = userRes.rows[0];
        const fp_match = savedFp ? (savedFp === fingerprint) : true;

        let score = 0.1;
        if (!fp_match) score += 0.4; // เครื่องเปลี่ยน = เสี่ยง Medium

        const level = score >= 0.7 ? "HIGH" : (score >= 0.4 ? "MEDIUM" : "LOW");

        let mfaCode = null;
        if (level === "MEDIUM") {
            mfaCode = Math.floor(100000 + Math.random() * 900000).toString();
            // TODO: โค้ดส่งเมลด้วย Nodemailer นำมาใส่ตรงนี้
            console.log(`[EMAIL MOCK] ส่งรหัส ${mfaCode} ไปที่ ${email}`); 
        }

        const result = await client.query(
            `INSERT INTO login_risks (username, ip_address, device_info, current_fingerprint, fingerprint_match, risk_score, risk_level, mfa_code, is_success) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, FALSE) RETURNING id`,
            [username, ip, device, fingerprint, fp_match, score, level, mfaCode]
        );

        res.status(200).json({ risk_level: level, logId: result.rows[0].id });
    } catch (err) { res.status(500).json({ error: err.message }); } 
    finally { await client.end(); }
}