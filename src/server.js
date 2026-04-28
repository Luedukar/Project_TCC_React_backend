const express = require("express");
const cors = require("cors");
require("dotenv").config();

/* Importa as rotas de autenticação (dentro desse file chamado abaixo que está login e register)
Ou seja, podemos acessar os "router.post" neste file*/
const authRoutes = require("./routes/authRoutes");

// Inicializa a API
const app = express();

// Permite que o front consiga acessar a API
app.use(cors());
// Permite json (ler o body, converter em JS, o que permite alimentar as variaveis, tipo const { email, senha } = req.body
app.use(express.json());

// até o momento o enderoço do back é http://localhost:3000, isso permite acessar authRoutes por meio de http://localhost:3000/auth
app.use("/auth", authRoutes);

// Testa se está funcionando
app.get("/", (req, res) => {
  res.send("API rodando");
});

// Abre uma porta para receber requisições, nesta caso, porta 3000
app.listen(3000, () => {
  console.log("Servidor rodando em http://localhost:3000");
});
