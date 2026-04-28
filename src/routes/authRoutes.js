const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const pool = require("../config/db");
const authMiddleware = require("../middleware/authMiddleware");
const nodemailer = require("nodemailer");

const router = express.Router();

// Função para o envio do e-mail da autenticação de duplo fator
async function sendTwoFactorCode(usuario) {
  try {
    const codigo = Math.floor(100000 + Math.random() * 900000);
    const id = Math.floor(100000 + Math.random() * 900000);

    // Insere o código no banco
    await pool.query(
      "INSERT INTO two_factor_codes (id, user_id, code, expires_at) VALUES ($1, $2, $3, DATE_ADD(NOW(), INTERVAL '5 minutes'))",
      [id, usuario.id, codigo],
    );

    // Configura o transporte de email
    const transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 587,
      secure: false,
      auth: {
        user: process.env.user_email,
        pass: process.env.email_senha,
      },
    });

    // Envia o email
    await transporter.sendMail({
      from: '"ADM do projeto" <luedukar@gmail.com>',
      to: usuario.email,
      subject: "Código de dois fatores",
      html: `<p>Seu código é ${codigo}</p>`,
      text: `Seu código é ${codigo}`,
    });

    // Retorna ID para envio ao front
    return id;
  } catch (err) {
    console.error("Erro ao enviar código de dois fatores:", err);
    throw err; // Lança o erro para ser tratado na rota
  }
}

// Essa cara aqui que cria a rota a ser usado no frontend (http://localhost:3000/auth/login)
router.post("/login", async (req, res) => {
  // pega o conteudo recebido em json e devide o mesmo em variaveis algo como const email = req.body.email, neste caso fazendo por ordem (o nome é desestruturação)
  const { email, senha } = req.body;

  try {
    // Busca pelo e-mail no banco, utilizando o valor email obtido acima, usa o pool para executar uma consulta no banco e aguarda um resultado
    const result = await pool.query('SELECT * FROM users WHERE "email" = $1', [
      email,
    ]);

    // Se o retorno for 0 (zero linhas encontradas) ele não encontrou esse e-mail no banco, envia o erro e encerrar o bloco com o return
    if (result.rows.length === 0) {
      return res.status(401).json({ erro: "Usuário não encontrado" });
    }

    // Nosso banco não permite e-mails iguais, se ele encontrar algo vai ser apenas 1 user, ele salva os valores da linha entre eles a senha
    const usuario = result.rows[0];
    /*Compara nosso valor senha obtido através do front com o valor obtido do banco, 
    no banco a senha é um hash, então ele converte a senha do front em hash (mesma logica aplicada para sair o mesmo resultado)
    e então faz a comparação*/
    const senhaValida = await bcrypt.compare(senha, usuario.senha);

    // Se o resultado não for TRUE, as senhas não são iguais (senha errada), retorna a msg de erro e impede o bloco de seguir usando o return
    if (!senhaValida) {
      return res.status(401).json({ erro: "Senha inválida" });
    }

    // gera o duplo fator e recbe como resposta o ID do duplo fator criado
    const codigo = await sendTwoFactorCode(usuario);

    // cria e salva o cookie referente ao duplo fator
    res.cookie("id_2fa", codigo, {
      httpOnly: true,
      secure: false, // true em produção
      sameSite: "Strict",
      maxAge: 5 * 60 * 1000, // 5 minutos (tempo de expiração no banco)
    });
    res.status(200).json({ sucesso: "e-mail e senha validados com sucesso" });
    // Caso aconteça alguma falha, mensagem de erro contendo o erro que aconteceu
  } catch (err) {
    console.error("ERRO NO LOGIN:", err);
    res.status(500).json({ erro: err.message });
  }
});

// Essa cara aqui que cria a rota a ser usado no frontend (http://localhost:3000/auth/register)
router.post("/register", async (req, res) => {
  // pega o cnteudo recebido em json e devide o mesmo em variaveis algo como const email = req.body.email, neste caso fazendo por ordem (o nome é desestruturação)
  const { nome, sobrenome, email, senha, celular, dataNascimento } = req.body;

  try {
    // Verifica se o email já existe no banco (o banco também não aceita mais de um e-mail igual, dupla precaução)
    const exists = await pool.query("SELECT id FROM users WHERE email = $1", [
      email,
    ]);

    /* Se o e-mail já existe, retorna o log abaixo e interrompe o restante da execução
    Caso não exista, segue o restante da execução*/
    if (exists.rows.length > 0) {
      return res.status(400).json({ erro: "Email já cadastrado" });
    }

    // pega a nossa "variavel" senha e trasforma ela em hash e armazena na "variavel" hash
    const hash = await bcrypt.hash(senha, 10);

    // Insere todos os nossos dados no banco, lembrando, a senha que vai para o banco é a senha em hash
    await pool.query(
      `INSERT INTO users
      (nome, sobrenome, email, senha, contato, aniversario)
      VALUES ($1, $2, $3, $4, $5, $6)`,
      [nome, sobrenome, email, hash, celular, dataNascimento],
    );

    // se sucesso, retorna status de sucesso e a mensagem em json
    res.status(201).json({ mensagem: "Usuário criado com sucesso" });
    // caso ocorra algum erro nesta etapam retorna o status de erro e a mensagem em json
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
    // Consulta no banco com req.user.id para obter informações do usuario que está fazendo login
    const result = await pool.query(
      "SELECT u.nome AS usuarioNome, u.sobrenome, u.email, u.id FROM users u WHERE u.id = $1",
      [req.user.id],
    );

    /* Em caso de sucesso, envia como resposta de http://localhost:3000/auth/me a mensagem de sucesso mais o resultado da consulta
    Lembrando, a consulta pode ter sucesso mas não retornar nenhuma informação*/
    res.json(result.rows);
  } catch (err) {
    // Em caso de erro, vai mostrar o erro aqui mesmo, mas também envia a resposta de erro (status 500) mais Erro ao buscar usuário
    console.error(err);
    res.status(500).json({ erro: "Erro ao buscar usuário" });
  }
});

/* acessado pela rota /me (http://localhost:3000/auth/productsMe), chama a função authMiddleware que valida o token recebido e decodifica o mesmo
o authMiddleware retorna se foi sucesso ou falha, em caso de sucesso retorna código de sucesso e também req.user
em caso de falha retorna código de falha e também Token inválido */
router.get("/productsMe", authMiddleware, async (req, res) => {
  try {
    // Consulta no banco com req.user.id, dessa vez, usando o userID da tabela de produtos
    const result = await pool.query(
      "SELECT p.productid AS idProduto, p.nome AS produtoNome, p.precoDesejado, p.enviarAviso FROM produtos p WHERE p.userID = $1 ORDER by productID",
      [req.user.id],
    );

    /* Em caso de sucesso, envia como resposta de http://localhost:3000/auth/productsMe a mensagem de sucesso mais o resultado da consulta
    Lembrando, a consulta pode ter sucesso mas não retornar nenhuma informação*/
    res.json(result.rows);
  } catch (err) {
    // Em caso de erro, vai mostrar o erro aqui mesmo, mas também envia a resposta de erro (status 500) mais Erro ao buscar produtos do usuario
    console.error(err);
    res.status(500).json({ erro: "Erro ao buscar produtos do usuario" });
  }
});

// acessa a rota /delete através de http://localhost:3000/auth/delete
router.post("/delete", async (req, res) => {
  // a req recebida possui um body, que é justamente a informação necessaria, o ID do produto a ser excluido
  const { idProduto } = req.body;

  try {
    // realiza o delete no banco usando o pool e executando a query abaixo onde $1 assume o valor do ID (isso previne SQL injection)
    const result = await pool.query(
      "DELETE FROM produtos WHERE productid = $1",
      [idProduto],
    );

    // Em caso de sucesso, envia como resposta de http://localhost:3000/auth/delete o log de sucesso mais uma mensagem em formato Json
    res.json({ mensagem: "Produto deletado com sucesso" });
    // Validação do retorno enviado, excluir quando não for mais necessario
    console.log(result);
  } catch (err) {
    // Em caso de erro, vai mostrar o erro aqui mesmo, mas também envia a resposta de erro (status 500) mais Erro ao deleter produto
    console.error(err);
    res.status(500).json({ erro: "Erro ao deletar produto" });
  }
});

// acessa a rota /avsiOff através de http://localhost:3000/auth/avisoOff
router.post("/avisoOff", async (req, res) => {
  // a req recebida possui um body, que é justamente a informação necessaria, o ID do que o aviso diario deve ser desativado
  const { idProduto } = req.body;

  try {
    // realiza o update no banco usando o pool e executando a query abaixo onde $1 assume o valor do ID (isso previne SQL injection)
    const result = await pool.query(
      "UPDATE produtos SET enviaraviso = FALSE WHERE productid = $1",
      [idProduto],
    );

    // Em caso de sucesso, envia como resposta de http://localhost:3000/auth/avisoOff o log de sucesso mais uma mensagem em formato Json
    res.json({ mensagem: "Aviso dasativado com sucesso" });
    // Validação do retorno enviado, excluir quando não for mais necessario*/
    console.log(result);
  } catch (err) {
    // Em caso de erro, vai mostrar o erro aqui mesmo, mas também envia a resposta de erro (status 500) mais Erro ao deleter produto*/
    console.error(err);
    res.status(500).json({ erro: "Erro ao desativar aviso" });
  }
});

// acessa a rota /avsiOff através de http://localhost:3000/auth/avisoOn
router.post("/avisoOn", async (req, res) => {
  // a req recebida possui um body, que é justamente a informação necessaria, o ID do que o aviso diario deve ser desativado
  const { idProduto } = req.body;

  try {
    // realiza o update no banco usando o pool e executando a query abaixo onde $1 assume o valor do ID (isso previne SQL injection)
    const result = await pool.query(
      "UPDATE produtos SET enviaraviso = TRUE WHERE productid = $1",
      [idProduto],
    );

    // Em caso de sucesso, envia como resposta de http://localhost:3000/auth/avisoOn o log de sucesso mais uma mensagem em formato Json
    res.json({ mensagem: "Aviso habilitado com sucesso" });
    // Validação do retorno enviado, excluir quando não for mais necessario
    console.log(result);
  } catch (err) {
    // Em caso de erro, vai mostrar o erro aqui mesmo, mas também envia a resposta de erro (status 500) mais Erro ao deleter produto
    console.error(err);
    res.status(500).json({ erro: "Erro ao ativar aviso" });
  }
});

// Rota para criação de avisos
router.post("/createProdutos", authMiddleware, async (req, res) => {
  // vai receber o token autenticado e decodificado do authMiddleware, assim consigo o ID do user
  // vai receber também a req do frot contendo o nome do produto, o preço desejado e o link da Amazon
  // pega o conteudo recebido em json e devide o mesmo em variaveis algo como const email = req.body.email, neste caso fazendo por ordem (o nome é desestruturação)
  const { nome, preco, link } = req.body;

  try {
    // Executa a criação de avisos no banco
    const result = await pool.query(
      "INSERT INTO produtos (UserID, Nome, PrecoDesejado, Link) VALUES ($1, $2, $3, $4)",
      [req.user.id, nome, preco, link],
    );

    /* Em caso de sucesso, envia como resposta de http://localhost:3000/auth/createProdutos a mensagem de sucesso
    Lembrando, a consulta pode ter sucesso mas não retornar nenhuma informação*/
    res.json({ mensagem: "Aviso criado com sucesso" });
  } catch (err) {
    // Em caso de erro, vai mostrar o erro aqui mesmo, mas também envia a resposta de erro (status 500) mais Erro ao criar aviso
    console.error(err);
    res.status(500).json({ erro: "Erro ao criar aviso" });
  }
});

// Essa cara aqui que cria a rota a ser usado no frontend (http://localhost:3000/auth/autenticarDuploFator)
router.post("/autenticarDuploFator", async (req, res) => {
  // pega o conteudo recebido em json e devide o mesmo em variaveis algo como const email = req.body.email, neste caso fazendo por ordem (o nome é desestruturação)
  const id_2fa = req.cookies.id_2fa;
  const codigoInserido = req.body.codigoInserido;
  console.log(id_2fa, codigoInserido);

  try {
    // Busca pelo 2fa com o ID correspondente no banco
    const result = await pool.query(
      "SELECT * FROM two_factor_codes WHERE id = $1 AND attempts < 3 AND expires_at > NOW() AND mfa_status = TRUE;",
      [id_2fa],
    );

    // Se o retorno for 0 (zero linhas encontradas) o 2fa deste código é invalido (expirado ou inexistente), envia o erro e encerrar o bloco com o return
    if (result.rows.length === 0) {
      return res.status(401).json({
        erro: "Erro ao identificar código, tente gerar um novo código",
      });
    }

    // Será encontrado somente um resultado ou nenhum
    const validar_2fa = result.rows[0];

    // comparava valor de código fornecido x valor de código no banco
    const autenticar_sfa = codigoInserido == validar_2fa.code;

    // Se o resultado não for TRUE, os códigos não correspondem, altera o número de tentativas restantes no banco eretorna a msg de erro
    if (!autenticar_sfa) {
      const result = await pool.query(
        "UPDATE two_factor_codes SET attempts = attempts + 1 WHERE id = $1;",
        [id_2fa],
      );
      return res.status(401).json({ erro: "Codigo invalido" });
    }

    // se estiver tudo certo, torna o código utilizado invalido (já utilizado)
    await pool.query(
      "UPDATE two_factor_codes SET mfa_status = FALSE WHERE id = $1;",
      [id_2fa],
    );

    // retorna as informações do user para fazer login
    const result_user = await pool.query(
      'SELECT * FROM users WHERE "id" = $1;',
      [validar_2fa.user_id],
    );

    const usuario = result_user.rows[0];

    // gera o token de login
    const token = jwt.sign(
      { id: usuario.id, email: usuario.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" },
    );

    // cria e salva o cookie de login
    res.cookie("token", token, {
      httpOnly: true,
      secure: true, // true em produção
      sameSite: "Strict",
      maxAge: 60 * 60 * 1000, // 1 hora
    });
    console.log("cookie de login enviado com sucesso");
    res.status(200).json({ sucesso: "Duplo fator autenticado com sucesso" });

    // Caso aconteça alguma falha, mensagem de erro contendo o erro que aconteceu
  } catch (err) {
    console.error("ERRO NO LOGIN:", err);
    res.status(500).json({ erro: err.message });
  }
});

// validar cookie assinado, caso ok, libera a rota
router.get("/protect", authMiddleware, (req, res) => {
  res.json({
    usuario: req.user,
  });
});

module.exports = router;
