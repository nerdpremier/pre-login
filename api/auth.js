import pkg from 'pg';
import bcrypt from 'bcrypt';
import nodemailer from 'nodemailer';

const { Client } = pkg;

function createClient() {
    return new Client({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false }
    });
}

function createMailer() {
    return nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT || 587),
        secure: String(process.env.SMTP_SECURE || 'false') === 'true',
        auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS
        }
    });
}

function generateMfaCode() {
    return String(Math.floor(100000 + Math.random() * 900000));
}

async function sendMfaEmail(to, username, code) {
    if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS || !process.env.MAIL_FROM) {
        throw new Error('SMTP is not configured. Please set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, and MAIL_FROM');
    }

    const transporter = createMailer();
    await transporter.sendMail({
        from: process.env.MAIL_FROM,
        to,
        subject: 'รหัสยืนยัน MFA ของคุณ',
        text: `สวัสดี ${username}\n\nรหัสยืนยันของคุณคือ ${code}\nรหัสนี้มีอายุ 10 นาที\n\nหากคุณไม่ได้พยายามเข้าสู่ระบบ กรุณาเปลี่ยนรหัสผ่านทันที`,
        html: `
            <div style="font-family:Segoe UI,Arial,sans-serif;max-width:520px;margin:auto;padding:24px;background:#0f172a;color:#fff;border-radius:16px;">
                <h2 style="margin-top:0;color:#60a5fa;">ยืนยันการเข้าสู่ระบบ</h2>
                <p>สวัสดี <b>${username}</b></p>
                <p>รหัสยืนยัน MFA ของคุณคือ</p>
                <div style="font-size:32px;font-weight:700;letter-spacing:8px;background:#1e293b;padding:16px;border-radius:12px;text-align:center;margin:18px 0;">${code}</div>
                <p>รหัสนี้มีอายุ <b>10 นาที</b></p>
                <p style="color:#cbd5e1;">หากคุณไม่ได้พยายามเข้าสู่ระบบ กรุณาเปลี่ยนรหัสผ่านทันที</p>
            </div>
        `
    });
}

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();

    const { action, username, password, fingerprint, email, riskLevel, logId } = req.body;
    const client = createClient();

    try {
        await client.connect();

        if (action === 'register') {
            if (!username || !password || !email) {
                return res.status(400).json({ error: 'Username, password, and email are required' });
            }

            const existing = await client.query(
                'SELECT 1 FROM users WHERE username = $1 OR email = $2 LIMIT 1',
                [username, email]
            );

            if (existing.rows.length > 0) {
                return res.status(409).json({ error: 'Username หรือ Email นี้ถูกใช้แล้ว' });
            }

            const hashed = await bcrypt.hash(password, 10);
            await client.query(
                'INSERT INTO users (username, password_hash, email) VALUES ($1, $2, $3)',
                [username, hashed, email]
            );

            return res.status(200).json({ success: true });
        }

        if (action !== 'login') {
            return res.status(400).json({ error: 'Unsupported action' });
        }

        const user = await client.query(
            'SELECT username, password_hash, email, authorized_fingerprint FROM users WHERE username = $1',
            [username]
        );

        if (user.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const currentUser = user.rows[0];
        const passwordOk = await bcrypt.compare(password, currentUser.password_hash);

        if (!passwordOk) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const needsMfa = riskLevel === 'MEDIUM' || (currentUser.authorized_fingerprint && fingerprint && currentUser.authorized_fingerprint !== fingerprint);

        if (needsMfa) {
            if (!currentUser.email) {
                return res.status(400).json({ error: 'บัญชีนี้ยังไม่มีอีเมลสำหรับ MFA' });
            }
            if (!logId) {
                return res.status(400).json({ error: 'Missing MFA log reference' });
            }

            const code = generateMfaCode();
            await client.query(
                'UPDATE login_risks SET mfa_code = $1, updated_at = NOW() WHERE id = $2',
                [code, logId]
            );

            await sendMfaEmail(currentUser.email, currentUser.username, code);

            return res.status(200).json({
                requiresMfa: true,
                logId,
                maskedEmail: currentUser.email.replace(/(^.).*(@.*$)/, '$1***$2')
            });
        }

        if (!currentUser.authorized_fingerprint && fingerprint) {
            await client.query(
                'UPDATE users SET authorized_fingerprint = $1 WHERE username = $2',
                [fingerprint, username]
            );
        }

        return res.status(200).json({ success: true, user: currentUser.username });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    } finally {
        await client.end();
    }
}
