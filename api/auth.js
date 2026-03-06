import pkg from 'pg';
import bcrypt from 'bcryptjs';

const { Client } = pkg;

export default async function handler(req, res) {

    if (req.method !== 'POST') return res.status(405).send();

    const { action, username, email, password, fingerprint } = req.body;

    const client = new Client({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false }
    });

    try {

        await client.connect();
        await client.query("BEGIN"); // ADD: transaction safety

        // FIX: รับ IP ให้ถูกต้อง (รองรับ proxy)
        let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        if (ip && ip.includes(",")) ip = ip.split(",")[0];

        if (action === 'register') {

            // validation username
            if (!/^[a-zA-Z0-9]+$/.test(username))
                return res.status(400).json({ error: "Username ภาษาอังกฤษเท่านั้น" });

            // validation password
            if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(password)) {
                return res.status(400).json({ error: "Password ไม่ปลอดภัยพอ" });
            }

            const hashed = await bcrypt.hash(password, 10);

            await client.query(
                "INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)",
                [username, email, hashed]
            );

            await client.query("COMMIT"); // ADD

            return res.status(200).json({ success: true });
        }

        else if (action === 'login') {

            // ADD: brute force protection
            const attempts = await client.query(
                `SELECT COUNT(*) FROM login_risks
                 WHERE username=$1
                 AND is_success=false
                 AND updated_at > NOW() - INTERVAL '10 minutes'`,
                [username]
            );

            if (Number(attempts.rows[0].count) >= 5) {

                await client.query("COMMIT");

                return res.status(429).json({
                    error: "Too many login attempts. Try again later."
                });
            }

            const user = await client.query(
                "SELECT * FROM users WHERE username = $1",
                [username]
            );

            if (user.rows.length > 0 &&
                await bcrypt.compare(password, user.rows[0].password_hash)
            ) {

                // ADD: บันทึก login success
                await client.query(
                    `INSERT INTO login_risks 
                    (username, ip_address, is_success) 
                    VALUES ($1,$2,true)`,
                    [username, ip]
                );

                // logic เดิมของคุณ (ไม่ลบ)
                if (!user.rows[0].authorized_fingerprint && fingerprint) {

                    await client.query(
                        "UPDATE users SET authorized_fingerprint = $1 WHERE username = $2",
                        [fingerprint, username]
                    );

                }

                await client.query("COMMIT");

                return res.status(200).json({ success: true });

            }

            // ADD: log failed login
            await client.query(
                `INSERT INTO login_risks 
                (username, ip_address, is_success)
                VALUES ($1,$2,false)`,
                [username, ip]
            );

            await client.query("COMMIT");

            return res.status(401).json({ error: "Invalid credentials" });
        }

    } catch (err) {

        await client.query("ROLLBACK"); // ADD

        res.status(500).json({ error: err.message });

    } finally {

        await client.end();

    }
}