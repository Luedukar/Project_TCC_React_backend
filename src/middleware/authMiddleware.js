const jwt = require("jsonwebtoken");

function autenticar(req, res, next) {
  // Acessar cookies
  const token = req.cookies.token;

  // Valida se foi encontrado o token nos cookies
  if (!token) {
    return res.status(401).json({ erro: "Token não informado" });
  }

  // Decodifica o token, salvar as informações e libera seguir
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    req.user = decoded;

    next();
    // Em caso de erro, esse bloco é usado
  } catch (err) {
    return res.status(401).json({ erro: "Token inválido" });
  }
}

module.exports = autenticar;
