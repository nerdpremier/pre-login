import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();

    const { logId, code } = req.body;
    const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

    try {
        await client.connect();
        const result = await client.query(
            `SELECT id, username, current_fingerprint
             FROM login_risks
             WHERE id = $1
               AND mfa_code = $2
               AND updated_at > NOW() - INTERVAL '10 minutes'`,
            [logId, code]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid Code' });
        }

        const { username, current_fingerprint } = result.rows[0];

        await client.query(
            'UPDATE users SET authorized_fingerprint = $1 WHERE username = $2',
            [current_fingerprint, username]
        );

        await client.query(
            'UPDATE login_risks SET is_success = TRUE, mfa_code = NULL, updated_at = NOW() WHERE id = $1',
            [logId]
        );

        return res.status(200).json({ success: true });
    } catch (e) {
        return res.status(500).json({ error: e.message });
    } finally {
        await client.end();
    }
}
