const jwt = require("jsonwebtoken");

function createAuthMiddleware({ secret, secretEnv = "JWT_SECRET" } = {}) {
  return function autenticar(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({ erro: "Token nÃ£o informado" });
    }

    const token = authHeader.split(" ")[1];

    const jwtSecret = secret ?? process.env[secretEnv];
    if (!jwtSecret) {
      return res
        .status(500)
        .json({ erro: `JWT secret nÃ£o configurado (${secretEnv})` });
    }

    try {
      const decoded = jwt.verify(token, jwtSecret);
      req.user = decoded;
      next();
    } catch {
      res.status(401).json({ erro: "Token invÃ¡lido" });
    }
  };
}

// Middleware padrão (assinado por JWT_SECRET)
const autenticar = createAuthMiddleware({ secretEnv: "JWT_SECRET" });

// Ex.: router.get("/rotaA", autenticar, handler)
// Ex.: router.get("/rotaB", autenticar.comAssinatura("JWT_SECRET2"), handler)
autenticar.comAssinatura = (secretEnv) => createAuthMiddleware({ secretEnv });
autenticar.comSecret = (secret) => createAuthMiddleware({ secret });
autenticar.create = createAuthMiddleware;

module.exports = autenticar;
