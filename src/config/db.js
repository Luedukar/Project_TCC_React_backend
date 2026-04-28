const { Pool } = require("pg");
require("dotenv").config();

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  ssl: {
    rejectUnauthorized: false,
  },
});

module.exports = pool;

// Aqui é feito o primeiro contato com o banco
// Para usar um ".query("SELECT * FROM sla")" eu posso usar o pool criado acima, pois ele carrega as credenciais para acessar o banco
