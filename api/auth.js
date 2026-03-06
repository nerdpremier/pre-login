import pkg from 'pg';
import bcrypt from 'bcryptjs';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    const { action, username, email, password, fingerprint } = req.body;
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

    try {
        await client.connect();

        if (action === 'register') {
            if (!/^[a-zA-Z0-9]+$/.test(username)) return res.status(400).json({ error: "Username ภาษาอังกฤษเท่านั้น" });
            if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(password)) {
                return res.status(400).json({ error: "Password ไม่ปลอดภัยพอ" });
            }
            const hashed = await bcrypt.hash(password, 10);
            await client.query(
                "INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)", 
                [username, email, hashed]
            );
            return res.status(200).json({ success: true });
        } 
        
        else if (action === 'login') {
            const user = await client.query("SELECT * FROM users WHERE username = $1", [username]);
            if (user.rows.length > 0 && await bcrypt.compare(password, user.rows[0].password_hash)) {
                if (!user.rows[0].authorized_fingerprint && fingerprint) {
                    await client.query("UPDATE users SET authorized_fingerprint = $1 WHERE username = $2", [fingerprint, username]);
                }
                return res.status(200).json({ success: true });
            }
            return res.status(401).json({ error: "Invalid credentials" });
        }
    } catch (err) { res.status(500).json({ error: err.message }); } 
    finally { await client.end(); }
}