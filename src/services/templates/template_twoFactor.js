// Função contendo o template para o envio do e-mail com o código de duplo fator
function twoFactorTemplate(codigo) {
  return `
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f4f4; padding:20px; font-family: Arial, sans-serif;">
    <tr>
      <td align="center">

        <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff; border-radius:8px; padding:24px;">
          
          <!-- MAIN -->
          <tr>
            <td style="padding-top:24px;">

              <h2 style="color:#374151; margin:0;">Olá,</h2>

              <p style="margin-top:12px; color:#4b5563; line-height:1.6;">
                Use o código abaixo para continuar seu login:
              </p>

              <!-- CÓDIGO -->
              <div style="
                margin-top:20px;
                margin-bottom:20px;
                font-size:28px;
                font-weight:bold;
                letter-spacing:4px;
                background:#f3f4f6;
                padding:16px;
                text-align:center;
                border-radius:8px;
                color:#111827;
              ">
                ${codigo}
              </div>

              <p style="margin-top:24px; color:#4b5563;">
                Se você não solicitou este código, ignore este email.
              </p>

              <p style="margin-top:24px; color:#4b5563;">
                Obrigado,<br>
                Luiz Eduardo Karpinski
              </p>

            </td>
          </tr>

          <!-- FOOTER -->
          <tr>
            <td style="padding-top:30px; font-size:12px; color:#9ca3af;">
              <p>
                Este email foi enviado automaticamente.
              </p>
              <p style="margin-top:8px;">
                © 2026 Project TCC. Todos os direitos reservados.
              </p>
            </td>
          </tr>

        </table>

      </td>
    </tr>
  </table>
  `;
}

module.exports = twoFactorTemplate;
