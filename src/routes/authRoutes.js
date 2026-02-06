const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const pool = require("../config/db");
const authMiddleware = require("../middleware/authMiddleware");

const router = express.Router();

/* Essa cara aqui que cria a rota a ser usado no frontend (http://localhost:3000/auth/login)*/
router.post("/login", async (req, res) => {
  /* Se ele for acinado/receber algo, ele mostra por meio do log abaixo (excluir quando não for mais necessário)*/
  console.log("BODY RECEBIDO:", req.body);
  /* pega o conteudo recebido em json e devide o mesmo em variaveis algo como const email = req.body.email, neste caso fazendo por ordem (o nome é desestruturação) */
  const { email, senha } = req.body;

  try {
    /* Busca pelo e-mail no banco, utilizando o valor email obtido acima, usa o pool para executar uma consulta no banco e aguarda um resultado*/
    const result = await pool.query('SELECT * FROM users WHERE "email" = $1', [
      email,
    ]);

    /* Se o retorno for 0 (zero linhas encontradas) ele não encontrou esse e-mail no banco, envia o erro e encerrar o bloco com o return*/
    if (result.rows.length === 0) {
      return res.status(401).json({ erro: "Usuário não encontrado" });
    }

    /*Nosso banco não permite e-mails iguais, se ele encontrar algo vai ser apenas 1 user, ele salva os valores da linha entre eles a senha */
    const usuario = result.rows[0];
    /*Compara nosso valor senha obtido através do front com o valor obtido do banco, 
    no banco a senha é um hash, então ele converte a senha do front em hash (mesma logica aplicada para sair o mesmo resultado)
    e então faz a comparação*/
    const senhaValida = await bcrypt.compare(senha, usuario.senha);

    /* Se o resultado não for TRUE, as senhas não são iguais (senha errada), retorna a msg de erro e impede o bloco de seguir usando o return*/
    if (!senhaValida) {
      return res.status(401).json({ erro: "Senha inválida" });
    }

    /* Cria um token com a biblioteca exportada no topo
     só é executado se o user e senha passarem nas validações acima
     cria uma chave valor com id: id do banco 
     e email: email obtido do banco (igual ao e-mail inserido e enviado no front)
     ele experia em 1 hora
     JWT_SECRET é do nosso .env, uma especie de assinatura*/
    const token = jwt.sign(
      { id: usuario.id, email: usuario.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" },
    );

    /* ele enviar uma resposta para onde foi recebeu o conteudo (manda para o front) em formato json
    O token gerado logo acima
    um arrey chave valor com:
      id: obtido do banco
      nome: obtido do banco
      email:obtido do banco
      no front ele aguarda o recedimento de uma resposta (const data = await response.json();) é daqui que ela parte*/
    res.json({
      token,
      usuario: {
        id: usuario.id,
        nome: usuario.nome,
        email: usuario.email,
      },
    });
    /* Caso aconteça alguma falha, mensagem de erro contendo o erro que aconteceu */
  } catch (err) {
    console.error("ERRO NO LOGIN:", err);
    res.status(500).json({ erro: err.message });
  }
});

/* Essa cara aqui que cria a rota a ser usado no frontend (http://localhost:3000/auth/register)*/
router.post("/register", async (req, res) => {
  /* Se ele for acinado/receber algo, ele mostra por meio do log abaixo (excluir quando não for mais necessário)*/
  console.log("BODY RECEBIDO:", req.body);
  /* pega o conteudo recebido em json e devide o mesmo em variaveis algo como const email = req.body.email, neste caso fazendo por ordem (o nome é desestruturação) */
  const { nome, sobrenome, email, senha, celular, dataNascimento } = req.body;

  try {
    /* Verifica se o email já existe no banco (o banco também não aceita mais de um e-mail igual, dupla precaução)*/
    const exists = await pool.query("SELECT id FROM users WHERE email = $1", [
      email,
    ]);

    /* Se o e-mail já existe, retorna o log abaixo e interrompe o restante da execução
    Caso não exista, segue o restante da execução*/
    if (exists.rows.length > 0) {
      return res.status(400).json({ erro: "Email já cadastrado" });
    }

    /*pega a nossa "variavel" senha e trasforma ela em hash e armazena na "variavel" hash */
    const hash = await bcrypt.hash(senha, 10);

    /* Insere todos os nossos dados no banco, lembrando, a senha que vai para o banco é a senha em hash*/
    await pool.query(
      `INSERT INTO users
      (nome, sobrenome, email, senha, contato, aniversario)
      VALUES ($1, $2, $3, $4, $5, $6)`,
      [nome, sobrenome, email, hash, celular, dataNascimento],
    );

    /* se sucesso, retorna status de sucesso e a mensagem em json*/
    res.status(201).json({ mensagem: "Usuário criado com sucesso" });
    /* caso ocorra algum erro nesta etapam retorna o status de erro e a mensagem em json*/
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: "Erro no servidor" });
  }
});

/* acessado pela rota /me (http://localhost:3000/auth/me), chama a função authMiddleware que valida o token recebido e decodifica o mesmo
o authMiddleware retorna se foi sucesso ou falha, em caso de sucesso retorna código de sucesso e também req.user
em caso de falha retorna código de falha e também Token inválido */
router.get("/me", authMiddleware, async (req, res) => {
  try {
    /* Consulta no banco com req.user.id para obter informações do usuario que está fazendo login*/
    const result = await pool.query(
      "SELECT u.nome AS usuarioNome, u.sobrenome, u.email, u.id FROM users u WHERE u.id = $1",
      [req.user.id],
    );

    /* Em caso de sucesso, envia como resposta de http://localhost:3000/auth/me a mensagem de sucesso mais o resultado da consulta
    Lembrando, a consulta pode ter sucesso mas não retornar nenhuma informação*/
    res.json(result.rows);
    /* Validação do retorno enviado, excluir quando não for mais necessario*/
    console.log(result.rows);
  } catch (err) {
    /* Em caso de erro, vai mostrar o erro aqui mesmo, mas também envia a resposta de erro (status 500) mais Erro ao buscar usuário*/
    console.error(err);
    res.status(500).json({ erro: "Erro ao buscar usuário" });
  }
});

/* acessado pela rota /me (http://localhost:3000/auth/productsMe), chama a função authMiddleware que valida o token recebido e decodifica o mesmo
o authMiddleware retorna se foi sucesso ou falha, em caso de sucesso retorna código de sucesso e também req.user
em caso de falha retorna código de falha e também Token inválido */
router.get("/productsMe", authMiddleware, async (req, res) => {
  try {
    /* Consulta no banco com req.user.id, dessa vez, usando o userID da tabela de produtos*/
    const result = await pool.query(
      "SELECT p.productid AS idProduto, p.nome AS produtoNome, p.precoDesejado, p.enviarAviso FROM produtos p WHERE p.userID = $1",
      [req.user.id],
    );

    /* Em caso de sucesso, envia como resposta de http://localhost:3000/auth/productsMe a mensagem de sucesso mais o resultado da consulta
    Lembrando, a consulta pode ter sucesso mas não retornar nenhuma informação*/
    res.json(result.rows);
    /* Validação do retorno enviado, excluir quando não for mais necessario*/
    console.log(result.rows);
  } catch (err) {
    /* Em caso de erro, vai mostrar o erro aqui mesmo, mas também envia a resposta de erro (status 500) mais Erro ao buscar produtos do usuario*/
    console.error(err);
    res.status(500).json({ erro: "Erro ao buscar produtos do usuario" });
  }
});

// acessa a rota /delete através de http://localhost:3000/auth/delete
router.post("/delete", async (req, res) => {
  // quando ele for chamado, vai receber uma req, isso é para validar o recebimento (excluir quando não precisar mais)
  console.log("BODY RECEBIDO:", req.body);
  // a req recebida possui um body, que é justamente a informação necessaria, o ID do produto a ser excluido
  const { idProduto } = req.body;
  //validação da extração do ID (excluir quando não for mais necessario)
  console.log(idProduto);

  try {
    // realiza o delete no banco usando o pool e executando a query abaixo onde $1 assume o valor do ID (isso previne SQL injection)
    const result = await pool.query(
      "DELETE FROM produtos WHERE productid = $1",
      [idProduto],
    );

    /* Em caso de sucesso, envia como resposta de http://localhost:3000/auth/delete o log de sucesso mais uma mensagem em formato Json
    Lembrando, a consulta pode ter sucesso mas não retornar nenhuma informação*/
    res.json({ mensagem: "Produto deletado com sucesso" });
    /* Validação do retorno enviado, excluir quando não for mais necessario*/
    console.log(result);
  } catch (err) {
    /* Em caso de erro, vai mostrar o erro aqui mesmo, mas também envia a resposta de erro (status 500) mais Erro ao deleter produto*/
    console.error(err);
    res.status(500).json({ erro: "Erro ao deletar produto" });
  }
});

module.exports = router;
