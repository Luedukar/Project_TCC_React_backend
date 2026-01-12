const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const pool = require("../config/db");

const router = express.Router();

router.post("/login", async (req, res) => {
  console.log("BODY RECEBIDO:", req.body);
  const { email, senha } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE "email" = $1', [
      email,
    ]);

    if (result.rows.length === 0) {
      return res.status(401).json({ erro: "Usuário não encontrado" });
    }

    const usuario = result.rows[0];
    const senhaValida = await bcrypt.compare(senha, usuario.senha);

    if (!senhaValida) {
      return res.status(401).json({ erro: "Senha inválida" });
    }

    const token = jwt.sign(
      { id: usuario.id, email: usuario.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      token,
      usuario: {
        id: usuario.id,
        nome: usuario.nome,
        email: usuario.email,
      },
    });
  } catch (err) {
    console.error("ERRO NO LOGIN:", err);
    res.status(500).json({ erro: err.message });
  }
});

module.exports = router;
