const dns = require("dns").promises;

// Valida formato do email (se contém . @, etc)
function validarFormatoEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// Valida se o dominio existe
async function validarDominioEmail(email) {
  try {
    // Extrai apenas o dominio
    const domain = email.split("@")[1];

    // Busca pelo dominio
    const registros = await dns.resolveMx(domain);

    // Se encontrar, retorna TRUE
    if (registros.length > 0) {
      return true;
      // Do contrario retorna FALSE
    } else {
      return false;
    }
    // Em caso de erro vai printar o erro e retorna FALSE por segurança
  } catch (error) {
    console.log(error);
    return false;
  }
}

module.exports = {
  validarFormatoEmail,
  validarDominioEmail,
};
