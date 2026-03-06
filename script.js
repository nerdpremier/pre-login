function getSecureFp(){

const screenSize = `${screen.width}x${screen.height}`
const cpu = navigator.hardwareConcurrency || 4
const platform = navigator.platform

const raw = `${screenSize}|${cpu}|${platform}`

return btoa(raw)

}

async function login(){

const username = document.getElementById("username").value
const password = document.getElementById("password").value

const fingerprint = getSecureFp()

const device = `Screen:${screen.width}x${screen.height} | CPU:${navigator.hardwareConcurrency}`

const res = await fetch("/api/auth",{
method:"POST",
headers:{"Content-Type":"application/json"},
body:JSON.stringify({
username,
password,
fingerprint,
device
})
})

const data = await res.json()

if(!res.ok){

alert(data.error)
return

}

sessionStorage.setItem("logId",data.logId)
sessionStorage.setItem("username",username)

if(data.require_mfa){

window.location.href="mfa.html"

}else{

window.location.href="welcome.html"

}

}

async function verifyMFA(){

const code = document.getElementById("mfa-code").value
const rememberDevice = document.getElementById("remember-device").checked

const logId = sessionStorage.getItem("logId")
const username = sessionStorage.getItem("username")

const fingerprint = getSecureFp()

const res = await fetch("/api/verify-mfa",{
method:"POST",
headers:{"Content-Type":"application/json"},
body:JSON.stringify({
logId,
code,
rememberDevice,
fingerprint,
username
})
})

if(res.ok)
 window.location.href="welcome.html"
else
 alert("Invalid MFA Code")

}