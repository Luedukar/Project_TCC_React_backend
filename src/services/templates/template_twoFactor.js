// Função contendo o template para o envio do e-mail com o código de duplo fator
function twoFactorTemplate(codigo) {
  return `Seu código: ${codigo}`;
}

module.exports = twoFactorTemplate;
