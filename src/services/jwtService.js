async function limparCookie(res, cookie) {
  res.clearCookie(cookie, {
    httpOnly: true,
    secure: false, // true em produção (HTTPS)
    sameSite: "Strict",
  });
}

module.exports = limparCookie;
