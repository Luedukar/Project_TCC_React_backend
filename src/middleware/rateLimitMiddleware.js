const rateLimit = require("express-rate-limit");

function createRateLimiter(
  // Parâmetros a serem definidos
  windowMs,
  max,
  // Parâmetro com valor padrão definido
  message = "Aguarde para tentar novamente",
) {
  return rateLimit({
    //Define o número de requisições maxima na rota dentro do intervalo de tempo
    windowMs,
    max,

    standardHeaders: true,
    legacyHeaders: false,

    // Mensagem de erro (passou do limite de reqs)
    message: {
      erro: message,
    },
  });
}

// Ratelimit para login, register, validar duplo-fator, recuperação de conta e reenvio de duplo fator
const loginLimiter = createRateLimiter(5 * 60 * 1000, 6);

const registerLimiter = createRateLimiter(10 * 60 * 1000, 3);

const duploFatorLimiter = createRateLimiter(5 * 60 * 1000, 4);

const emailRecoverLimiter = createRateLimiter(20 * 60 * 1000, 5);

const resendLimiter = createRateLimiter(10 * 60 * 1000, 6);

module.exports = {
  loginLimiter,
  registerLimiter,
  duploFatorLimiter,
  emailRecoverLimiter,
  resendLimiter,
};
