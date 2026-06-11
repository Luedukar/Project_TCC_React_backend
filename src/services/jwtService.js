const crypto = require("crypto");
const bcrypt = require("bcrypt");
const pool = require("../config/db");
const {
  sendTwoFactorEmail,
  sendTwoFactorEmailPassword,
} = require("../services/emailService");
// Função para limpar cookies
async function limparCookie(res, cookie, isProduction) {
  res.clearCookie(cookie, {
    httpOnly: true,
    secure: isProduction, // true em produção (HTTPS)
    sameSite: "Strict",
  });
}

// Função para o envio do e-mail da autenticação de duplo fator
async function sendTwoFactorCode(usuario, tipo) {
  try {
    // ID do código de duplo fator (enviar também como Cookie)
    const id = crypto.randomUUID();

    // Código do duplo fator (enviar somente esse por e-mail)
    const codigo = crypto.randomInt(100000, 999999);

    // Conversão do código do duplo fator para hash (enviar somente esse ao banco)
    const hash = await bcrypt.hash(codigo.toString(), 10);

    // Insere o código no banco
    await pool.query(
      `INSERT INTO two_factor_codes (id, user_id, code, type, expires_at) VALUES ($1, $2, $3, $4, DATE_ADD(NOW(), INTERVAL '5 minutes'))`,
      [id, usuario.id, hash, tipo],
    );

    // usa a função para enviar o e-mail
    if (tipo == "2fa") {
      await sendTwoFactorEmail(usuario.email, codigo);
    } else if (tipo == "recover") {
      await sendTwoFactorEmailPassword(usuario.email, codigo);
    }
    // Retorna ID para salvar em Cookies
    return id;
  } catch (err) {
    console.error("Erro ao enviar código de dois fatores:", err);
    throw err; // Lança o erro para ser tratado na rota
  }
}

module.exports = { limparCookie, sendTwoFactorCode };
