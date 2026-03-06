import pkg from 'pg';
import bcrypt from 'bcryptjs';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    const { action, username, password } = req.body;

    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
    try {
        await client.connect();
        if (action === 'register') {
            const hashed = await bcrypt.hash(password, 10);
            await client.query("INSERT INTO users (username, password_hash) VALUES ($1, $2)", [username, hashed]);
            res.status(200).json({ success: true });
        } else {
            const user = await client.query("SELECT * FROM users WHERE username = $1", [username]);
            if (user.rows.length > 0 && await bcrypt.compare(password, user.rows[0].password_hash)) {
                res.status(200).json({ success: true, user: user.rows[0].username });
            } else {
                res.status(401).json({ error: "ชื่อผู้ใช้หรือรหัสผ่านผิด" });
            }
        }
    } catch (err) { res.status(500).json({ error: "Authentication system error" }); }
    finally { await client.end(); }
}