import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    const { logId, success } = req.body;
    if (!logId) return res.status(200).json({ success: true });

    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
    try {
        await client.connect();
        await client.query("UPDATE login_risks SET is_success = $1, updated_at = NOW() WHERE id = $2", [success, logId]);
        res.status(200).json({ success: true });
    } catch (err) { res.status(500).json({ error: "Log Update Error" }); }
    finally { await client.end(); }
}