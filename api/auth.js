import pkg from 'pg';
import bcrypt from 'bcryptjs';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
    try {
        await client.connect();
        const { action, username, password } = req.body;

        if (action === 'register') {
            const hashed = await bcrypt.hash(password, 10);
            await client.query("INSERT INTO users (username, password_hash) VALUES ($1, $2)", [username, hashed]);
            return res.status(200).json({ success: true });
        } else {
            const userRes = await client.query("SELECT * FROM users WHERE username = $1", [username]);
            if (userRes.rows.length > 0 && await bcrypt.compare(password, userRes.rows[0].password_hash)) {
                return res.status(200).json({ success: true });
            }
            return res.status(401).json({ error: "Invalid Credentials" });
        }
    } catch (err) { return res.status(500).json({ error: err.message }); }
    finally { await client.end(); }
}