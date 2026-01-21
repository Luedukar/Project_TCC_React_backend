const jwt = require("jsonwebtoken");

/* Função de nome autenticas que recebe req, res e next
req = requisição
res = resposta
next = liberada a execução*/
function autenticar(req, res, next) {
  /* Leitura do header do token*/
  const authHeader = req.headers.authorization;

  /* Se for vazio (não existir token) para tudo*/
  if (!authHeader) {
    return res.status(401).json({ erro: "Token não informado" });
  }

  /* O header vem com algo como "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", aqui deixamos o "Bearer" de lado*/
  const token = authHeader.split(" ")[1];

  /* Valida o token*/
  try {
    /* verifica se o tojen foi assinado pelo JWT_SECRET do .env, se não expirou e extrai o "corpo" do token*/
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    /* Salva as informações decodificadas*/
    req.usuario = decoded;
    /* Libera o acesso*/
    next();
    /* Caso algumas coisa falhar, retorna erro*/
  } catch {
    res.status(401).json({ erro: "Token inválido" });
  }
}

module.exports = autenticar;
