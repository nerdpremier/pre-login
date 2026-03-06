import pkg from 'pg';
import nodemailer from 'nodemailer';
import geoip from 'geoip-lite'; // ADD: GeoIP detection

const { Client } = pkg;

export default async function handler(req, res) {

    if (req.method !== 'POST') return res.status(405).send();

    const client = new Client({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false }
    });

    try {

        await client.connect();
        await client.query("BEGIN"); // ADD: transaction safety

        const { username, device, fingerprint } = req.body;

        // FIX: handle proxy ip
        let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        if (ip && ip.includes(",")) ip = ip.split(",")[0];

        // ADD: GeoIP country detection
        const geo = geoip.lookup(ip);
        const country = geo ? geo.country : "UNKNOWN";

        // 1. ดึงข้อมูล User
        const userRes = await client.query(
            "SELECT email, authorized_fingerprint FROM users WHERE username = $1",
            [username]
        );

        if (userRes.rows.length === 0) {
            await client.query("COMMIT"); // ADD
            return res.status(200).json({ risk_level: "LOW", logId: null });
        }

        const { email, authorized_fingerprint: savedFp } = userRes.rows[0];

        const fp_match = savedFp ? (savedFp === fingerprint) : true;

        // 2. คำนวณความเสี่ยง
        let score = 0.1;

        if (!fp_match) score += 0.4; // เครื่องเปลี่ยน

        // ADD: Impossible travel detection
        try {

            const lastLogin = await client.query(
                `SELECT country, updated_at
                 FROM login_risks
                 WHERE username=$1 AND is_success=true
                 ORDER BY updated_at DESC
                 LIMIT 1`,
                [username]
            );

            if (lastLogin.rows.length > 0) {

                const lastCountry = lastLogin.rows[0].country;
                const lastTime = new Date(lastLogin.rows[0].updated_at);

                const now = new Date();
                const minutes = (now - lastTime) / 60000;

                // คนละประเทศใน 30 นาที = เสี่ยง
                if (lastCountry && lastCountry !== country && minutes < 30) {
                    score += 0.5;
                    console.log("⚠️ Impossible travel detected");
                }
            }

        } catch (geoErr) {
            console.log("Geo check skipped", geoErr);
        }

        const level =
            score >= 0.7 ? "HIGH" :
            (score >= 0.4 ? "MEDIUM" : "LOW");

        // 3. สร้างรหัส MFA
        let mfaCode = null;

        // FIX: MFA ส่งเฉพาะ MEDIUM
        if (level === "MEDIUM") {

            mfaCode = Math.floor(100000 + Math.random() * 900000).toString();

            try {

                const transporter = nodemailer.createTransport({
                    service: 'gmail',
                    auth: {
                        user: process.env.EMAIL_USER,
                        pass: process.env.EMAIL_PASS
                    }
                });

                const mailOptions = {
                    from: `"ระบบรักษาความปลอดภัย" <${process.env.EMAIL_USER}>`,
                    to: email,
                    subject: '🔒 รหัสยืนยันตัวตน (MFA Code) สำหรับการเข้าสู่ระบบ',
                    html: `
                        <h2>ตรวจพบการเข้าสู่ระบบจากอุปกรณ์ใหม่</h2>
                        <p>คุณ <b>${username}</b>,</p>
                        <p>เราพบความพยายามเข้าสู่ระบบจากอุปกรณ์ที่ยังไม่เคยได้รับการยืนยัน</p>
                        <p>รหัสยืนยันตัวตน (MFA) 6 หลักของคุณคือ:</p>
                        <h1 style="color: #3b82f6; letter-spacing: 5px;">${mfaCode}</h1>
                        <p><i>โปรดอย่านำรหัสนี้ไปให้บุคคลอื่นเด็ดขาด</i></p>
                    `
                };

                await transporter.sendMail(mailOptions);

                console.log(`✅ ส่ง MFA Code ไปที่อีเมล ${email} สำเร็จ!`);

            } catch (mailError) {

                console.error("❌ เกิดข้อผิดพลาดในการส่งอีเมล:", mailError);

            }
        }

        // ADD: block high risk
        if (level === "HIGH") {

            const result = await client.query(
                `INSERT INTO login_risks 
                (username, ip_address, device_info, current_fingerprint, fingerprint_match, risk_score, risk_level, country, is_success) 
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,FALSE)
                 RETURNING id`,
                [username, ip, device, fingerprint, fp_match, score, level, country]
            );

            await client.query("COMMIT");

            return res.status(403).json({
                risk_level: "HIGH",
                logId: result.rows[0].id
            });
        }

        // 4. บันทึกลง login_risks
        const result = await client.query(
            `INSERT INTO login_risks 
            (username, ip_address, device_info, current_fingerprint, fingerprint_match, risk_score, risk_level, mfa_code, country, is_success) 
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,FALSE)
             RETURNING id`,
            [username, ip, device, fingerprint, fp_match, score, level, mfaCode, country]
        );

        await client.query("COMMIT"); // ADD

        res.status(200).json({
            risk_level: level,
            logId: result.rows[0].id
        });

    } catch (err) {

        await client.query("ROLLBACK"); // ADD

        console.error(err);

        res.status(500).json({ error: err.message });

    } finally {

        await client.end();

    }
}