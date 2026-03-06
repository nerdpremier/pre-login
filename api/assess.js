import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
    try {
        await client.connect();
        const { username, device, fingerprint } = req.body;
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        // ดึง Email และลายนิ้วมือที่เคยบันทึก
        const userRes = await client.query("SELECT email, authorized_fingerprint FROM users WHERE username = $1", [username]);
        if (userRes.rows.length === 0) return res.status(200).json({ risk_level: "LOW" });

        const { email, authorized_fingerprint } = userRes.rows[0];
        const fp_match = (authorized_fingerprint === fingerprint); // เครื่องเดิม = true

        let score = 0.1;
        let mfa = null;

        if (fp_match === false) { 
            score = 0.5; // เปลี่ยนเครื่องปุ๊บ เป็น Medium ทันที
            mfa = Math.floor(100000 + Math.random() * 900000).toString();
            // จำลองการส่งเมล
            console.log(`[EMAIL SYSTEM] Sending MFA Code: ${mfa} to ${email}`);
        }

        const level = score >= 0.7 ? "HIGH" : (score >= 0.4 ? "MEDIUM" : "LOW");

        const result = await client.query(
            "INSERT INTO login_risks (username, ip_address, device_info, current_fingerprint, fingerprint_match, mfa_code, risk_score, risk_level) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id",
            [username, ip, device, fingerprint, fp_match, mfa, score, level]
        );

        res.status(200).json({ risk_level: level, logId: result.rows[0].id });
    } catch (e) { res.status(500).json({ error: e.message }); }
    finally { await client.end(); }
}