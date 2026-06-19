const rateLimit = require("express-rate-limit");

function createRateLimiter(
  windowMs,
  max,
  message = "Aguarde para tentar novamente",
) {
  return rateLimit({
    windowMs,
    max,

    standardHeaders: true,
    legacyHeaders: false,

    message: {
      erro: message,
    },
  });
}

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
