const jwt = require("jsonwebtoken");

// Função contendo o Middleware a ser utilizado, recebe o JWT que deve ser buscado e a assinatura a usar
function criarMiddleware(nomeCookie, assinatura) {
  return function (req, res, next) {
    // Recupera o Token dos cookies
    const token = req.cookies[nomeCookie];

    // Se o Token não for encontrado, retorna erro
    if (!token) {
      return res.status(401).json({ erro: "Token não informado" });
    }

    // Valida a assinatura e decodifica o Token
    try {
      const decoded = jwt.verify(token, assinatura);

      //Permite usar o conteudo decodificado
      req.user = decoded;

      //Libera seguir
      next();
    } catch (err) {
      //Caso Não sejá possivel autenticar
      console.log("Falha ao autenticar Token: ", err);
      return res.status(401).json({ erro: "Token inválido" });
    }
  };
}

//Criar Token de login
const autenticar = criarMiddleware("token", process.env.JWT_SECRET);
// Cria Token de redefinição de senha
const autenticarReset = criarMiddleware("Redefinicao", process.env.JWT_SECRET2);

module.exports = { autenticar, autenticarReset };
