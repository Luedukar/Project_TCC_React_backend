const express = require("express");
const cors = require("cors");
require("dotenv").config();

const authRoutes = require("./routes/authRoutes");

const app = express();

app.use(cors());
app.use(express.json());

app.use("/auth", authRoutes);

app.get("/", (req, res) => {
  res.send("API rodando");
});

app.listen(3000, () => {
  console.log("Servidor rodando em http://localhost:3000");
});
