import pkg from 'pg';
import bcrypt from 'bcryptjs';
const { Client } = pkg;

export default async function handler(req, res) {
    const { action, username, email, password, fingerprint } = req.body;
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

    try {
        await client.connect();
        if (action === 'register') {
            const hashed = await bcrypt.hash(password, 10);
            await client.query("INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)", [username, email, hashed]);
            res.status(200).json({ success: true });
        } else {
            const user = await client.query("SELECT * FROM users WHERE username = $1", [username]);
            if (user.rows.length > 0 && await bcrypt.compare(password, user.rows[0].password_hash)) {
                // บันทึกเครื่องหลักถ้ายังไม่มี
                if (!user.rows[0].authorized_fingerprint && fingerprint) {
                    await client.query("UPDATE users SET authorized_fingerprint = $1 WHERE username = $2", [fingerprint, username]);
                }
                res.status(200).json({ success: true });
            } else { res.status(401).json({ error: "Fail" }); }
        }
    } catch (e) { res.status(500).json({ error: e.message }); }
    finally { await client.end(); }
}