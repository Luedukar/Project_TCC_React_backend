const nodemailer = require("nodemailer");
const template_twoFactor = require("./templates/template_twoFactor");
const template_twoFactorPassword = require("./templates/template_twoFactorPassword");

// Configura o transporte de email
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  auth: {
    user: process.env.user_email,
    pass: process.env.email_senha,
  },
});

// Envia o email para duplo fator
async function sendTwoFactorEmail(to, codigo) {
  await transporter.sendMail({
    from: `"ADM do projeto" <${process.env.user_email}>`,
    to,
    subject: "Código de dois fatores",
    html: template_twoFactor(codigo), // função com o template de envio
    text: `Seu código é ${codigo}`,
  });
}

// Envia o email para recuperar senha
async function sendTwoFactorEmailPassword(to, codigo) {
  await transporter.sendMail({
    from: `"ADM do projeto" <${process.env.user_email}>`,
    to,
    subject: "Código de recuperação de senha",
    html: template_twoFactorPassword(codigo), // função com o template de envio
    text: `Seu código de recuperação de senha é ${codigo}`,
  });
}

module.exports = {
  sendTwoFactorEmail,
  sendTwoFactorEmailPassword,
};
