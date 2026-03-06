import pkg from 'pg';
import nodemailer from 'nodemailer';

const { Client } = pkg;

export default async function handler(req,res){

if(req.method !== 'POST') return res.status(405).send();

const { username, device, fingerprint } = req.body;

const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

const client = new Client({
 connectionString:process.env.DATABASE_URL,
 ssl:{rejectUnauthorized:false}
});

try{

await client.connect();

// user info
const user = await client.query(
"SELECT email,authorized_fingerprint FROM users WHERE username=$1",
[username]
);

if(user.rows.length === 0)
 return res.status(404).json({error:"user not found"});

const email = user.rows[0].email;
const savedFp = user.rows[0].authorized_fingerprint;

const fp_match = savedFp === fingerprint;

let score = 0.1;

if(!fp_match) score += 0.4;

const level =
score >=0.7 ? "HIGH" :
score >=0.4 ? "MEDIUM" :
"LOW";

let mfaCode = null;

if(level === "MEDIUM"){

mfaCode = Math.floor(
100000 + Math.random()*900000
).toString();

const transporter = nodemailer.createTransport({
 service:'gmail',
 auth:{
  user:process.env.EMAIL_USER,
  pass:process.env.EMAIL_PASS
 }
});

await transporter.sendMail({
 from:`Security <${process.env.EMAIL_USER}>`,
 to:email,
 subject:"MFA Code",
 html:`<h2>MFA Code</h2><h1>${mfaCode}</h1>`
});

}

// log
const log = await client.query(
`INSERT INTO login_risks
(username,ip_address,device_info,current_fingerprint,
fingerprint_match,risk_score,risk_level,mfa_code,is_success)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,true)
RETURNING id`,
[
 username,
 ip,
 device,
 fingerprint,
 fp_match,
 score,
 level,
 mfaCode
]);

res.status(200).json({
 risk_level:level,
 logId:log.rows[0].id
});

}
catch(err){
 res.status(500).json({error:err.message});
}
finally{
 await client.end();
}

}