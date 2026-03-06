import pkg from 'pg';
import bcrypt from 'bcrypt';
const { Client } = pkg;

export default async function handler(req, res) {
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
    try {
        await client.connect();
        const { action, username, email, password, fingerprint } = req.body;

        if (action === 'register') {
            const check = await client.query("SELECT id FROM users WHERE username = $1", [username]);
            if (check.rows.length > 0) return res.status(400).json({ error: "User exists" });

            // 🔐 Hash Password ก่อนเก็บ (ความแรงระดับ 10)
            const hashedPassword = await bcrypt.hash(password, 10);
            
            await client.query(
                "INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)",
                [username, email, hashedPassword]
            );
            return res.status(201).json({ message: "Registered" });
        }

        if (action === 'login') {
            const userRes = await client.query("SELECT * FROM users WHERE username = $1", [username]);
            if (userRes.rows.length === 0) return res.status(401).json({ error: "Invalid credentials" });

            const user = userRes.rows[0];
            // 🔐 ตรวจสอบ Hash Password
            const match = await bcrypt.compare(password, user.password_hash);
            if (!match) return res.status(401).json({ error: "Invalid credentials" });

            // บันทึกเครื่องแรกหากยังไม่มี
            if (!user.authorized_fingerprint) {
                await client.query("UPDATE users SET authorized_fingerprint = $1 WHERE username = $2", [fingerprint, username]);
            }

            return res.status(200).json({ message: "Login success" });
        }
    } catch (e) {
        res.status(500).json({ error: e.message });
    } finally {
        await client.end();
    }
}