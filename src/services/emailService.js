const nodemailer = require("nodemailer");
const template_twoFactor = require("./templates/template_twoFactor");

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

// Envia o email
async function sendTwoFactorEmail(to, codigo) {
  await transporter.sendMail({
    from: '"ADM do projeto" <luedukar@gmail.com>',
    to,
    subject: "Código de dois fatores",
    html: template_twoFactor(codigo), // função com o template de envio
    text: `Seu código é ${codigo}`,
  });
}

module.exports = {
  sendTwoFactorEmail,
};
