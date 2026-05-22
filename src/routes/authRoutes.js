const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const pool = require("../config/db");
const authMiddleware = require("../middleware/authMiddleware");
const router = express.Router();
const {
  sendTwoFactorEmail,
  sendTwoFactorEmailPassword,
} = require("../services/emailService");
const {
  validarFormatoEmail,
  validarDominioEmail,
} = require("../services/checkEmail");
// Função para o envio do e-mail da autenticação de duplo fator
async function sendTwoFactorCode(usuario, tipo) {
  try {
    // ID do código de duplo fator (enviar também como Cookie)
    const id = Math.floor(100000 + Math.random() * 900000);

    // Código do duplo fator (enviar somente esse por e-mail)
    const codigo = Math.floor(100000 + Math.random() * 900000);

    // Conversão do código do duplo fator para hash (enviar somente esse ao banco)
    const hash = await bcrypt.hash(codigo.toString(), 10);

    // Insere o código no banco
    await pool.query(
      `INSERT INTO two_factor_codes (id, user_id, code, type, expires_at) VALUES ($1, $2, $3, $4, DATE_ADD(NOW(), INTERVAL '5 minutes'))`,
      [id, usuario.id, hash, tipo],
    );

    // usa a função para enviar o e-mail

    if (tipo == "2fa") {
      await sendTwoFactorEmail(usuario.email, codigo);
    } else if (tipo == "recover") {
      await sendTwoFactorEmailPassword(usuario.email, codigo);
    }
    // Retorna ID para salvar em Cookies
    return id;
  } catch (err) {
    console.error("Erro ao enviar código de dois fatores:", err);
    throw err; // Lança o erro para ser tratado na rota
  }
}

// Cria a rota a ser usado no frontend (http://localhost:3000/auth/login)
router.post("/login", async (req, res) => {
  // pega o conteudo recebido em json e devide o mesmo em variaveis como const email = req.body.email, neste caso fazendo por ordem (desestruturação)
  const { email, senha } = req.body;

  try {
    // Busca pelo e-mail no banco, utilizando o valor email obtido acima, usa o pool para executar uma consulta no banco e aguarda um resultado
    const result = await pool.query(
      `SELECT * FROM users WHERE email = $1 AND status = 'ativo'`,
      [email],
    );

    // Se o retorno for 0 (zero linhas encontradas) ele não encontrou esse e-mail no banco, envia o erro e encerrar o bloco com o return
    if (result.rows.length === 0) {
      return res.status(401).json({ erro: "Usuário não encontrado" });
    }

    // O banco não permite e-mails iguais, se ele encontrar algo vai ser apenas 1 linha, salva os valores da linha
    const usuario = result.rows[0];
    /* Compara nosso valor senha obtido através do front com o valor obtido do banco, 
    no banco a senha é um hash, então ele converte a senha do front em hash (mesma logica aplicada para sair o mesmo resultado)
    e então faz a comparação */
    const senhaValida = await bcrypt.compare(senha, usuario.senha);

    // Se o resultado não for TRUE, as senhas não são iguais (senha errada), retorna a msg de erro e impede o bloco de seguir usando o return
    if (!senhaValida) {
      return res.status(401).json({ erro: "Senha inválida" });
    }

    // Gera o duplo fator e recebe como resposta o ID do duplo fator criado
    const codigo = await sendTwoFactorCode(usuario, "2fa");

    // Cria e salva o cookie referente ao duplo fator
    res.cookie("id_2fa", codigo, {
      httpOnly: true,
      secure: false, // true em produção
      sameSite: "Strict",
      maxAge: 5 * 60 * 1000, // 5 minutos (tempo de expiração no banco)
    });
    // Status de sucesso para o front (que aguarda resposta)
    res.json({ sucesso: "e-mail e senha validados com sucesso" });
    // Caso aconteça alguma falha, mensagem de erro contendo o erro que aconteceu
  } catch (err) {
    console.error("Erro no login:", err);
    res.status(500).json({ erro: err.message });
  }
});

// Cria a rota a ser usado no frontend (http://localhost:3000/auth/register)
router.post("/register", async (req, res) => {
  const { nome, sobrenome, email, senha, celular, dataNascimento } = req.body;

  // Verifica novamente o formato do e-mail
  if (!validarFormatoEmail(email)) {
    return res.status(400).json({
      erro: "Formato de e-mail inválido",
    });
  }

  // Verifica o dominio do e-mail
  const domainValido = await validarDominioEmail(email);

  if (!domainValido) {
    return res.status(400).json({
      erro: "Domínio de e-mail inválido",
    });
  }

  try {
    // Verifica se o email já existe no banco (o banco também não aceita mais de um e-mail igual, dupla precaução)
    const exists = await pool.query(`SELECT id FROM users WHERE email = $1`, [
      email,
    ]);

    /* Se o e-mail já existe, retorna o log abaixo e interrompe o restante da execução
    Caso não exista, segue o restante da execução*/
    if (exists.rows.length > 0) {
      return res.status(401).json({ erro: "Email já cadastrado" });
    }

    // Pega senha e transforma ela em hash
    const hash = await bcrypt.hash(senha, 10);

    // Insere todos os nossos dados no banco, lembrando, a senha que vai para o banco é a senha em hash
    await pool.query(
      `INSERT INTO users
      (nome, sobrenome, email, senha, contato, aniversario)
      VALUES ($1, $2, $3, $4, $5, $6)`,
      [nome, sobrenome, email, hash, celular, dataNascimento],
    );

    // Se sucesso, retorna status de sucesso e a mensagem em json
    res.status(201).json({ mensagem: "Usuário criado com sucesso" });
    // Caso ocorra algum erro nesta etapam retorna o status de erro e a mensagem em json
  } catch (err) {
    console.error("Erro ao criar cadastro:", err);
    res.status(500).json({ erro: err.message });
  }
});

/* Acessado pela rota /me (http://localhost:3000/auth/me), chama a função authMiddleware que valida e decodifica o token presente nos cookies 
retorna se foi sucesso ou falha, em caso de sucesso libera seguir e também req.user
em caso de falha impede de seguir de seguir e retorna código de falha */
router.get("/me", authMiddleware, async (req, res) => {
  try {
    // Consulta no banco com req.user.id para obter informações do usuario que está fazendo login
    const result = await pool.query(
      `SELECT u.nome AS usuarioNome, u.sobrenome, u.email, u.id FROM users u WHERE u.id = $1`,
      [req.user.id],
    );

    /* Em caso de sucesso, envia como resposta o resultado da consulta
    Lembrando, a consulta pode ter sucesso mas não retornar nenhuma informação*/
    res.json(result.rows);
  } catch (err) {
    console.error("Erro ao buscar user:", err);
    res.status(500).json({ erro: err.message });
  }
});

// Cria a rota a ser usado no frontend (http://localhost:3000/auth/productsMe) usando authMiddleware da mesma forma que a rota acima
router.get("/productsMe", authMiddleware, async (req, res) => {
  try {
    // Consulta no banco com req.user.id, dessa vez, usando o userID da tabela de produtos
    const result = await pool.query(
      `SELECT p.productid AS idProduto, p.nome AS produtoNome, p.precoDesejado, p.enviarAviso FROM produtos p WHERE p.userID = $1 ORDER by productID`,
      [req.user.id],
    );

    /* Em caso de sucesso, envia como resposta o resultado da consulta.
    Lembrando, a consulta pode ter sucesso mas não retornar nenhuma informação (sem produtos cadastrados)*/
    res.json(result.rows);
  } catch (err) {
    console.error("Erro ao buscar produtos de user:", err);
    res.status(500).json({ erro: err.message });
  }
});

// Acessa a rota /delete através de http://localhost:3000/auth/delete
router.post("/delete", authMiddleware, async (req, res) => {
  // A req recebida possui um body, que é justamente a informação necessaria, o ID do produto a ser excluido
  const { idProduto } = req.body;

  try {
    // Realiza o delete no banco usando o pool e executando a query abaixo onde $1 assume o valor do ID (isso previne SQL injection)
    const result = await pool.query(
      `DELETE FROM produtos WHERE productid = $1`,
      [idProduto],
    );

    // Em caso de sucesso, envia como resposta o log de sucesso mais mensagem em formato Json
    res.json({ mensagem: "Produto deletado com sucesso" });
  } catch (err) {
    console.error("Erro ao deletar produto:", err);
    res.status(500).json({ erro: err.message });
  }
});

// Acessa a rota /avsiOff através de http://localhost:3000/auth/avisoOff
router.post("/avisoOff", authMiddleware, async (req, res) => {
  const { idProduto } = req.body;

  try {
    const result = await pool.query(
      `UPDATE produtos SET enviaraviso = FALSE WHERE productid = $1`,
      [idProduto],
    );

    // Em caso de sucesso, envia como resposta o log de sucesso mais mensagem em formato Json
    res.json({ mensagem: "Aviso dasativado com sucesso" });
  } catch (err) {
    console.error("Erro ao desativar aviso:", err);
    res.status(500).json({ erro: err.message });
  }
});

// Acessa a rota /avsiOff através de http://localhost:3000/auth/avisoOn
router.post("/avisoOn", authMiddleware, async (req, res) => {
  const { idProduto } = req.body;

  try {
    const result = await pool.query(
      `UPDATE produtos SET enviaraviso = TRUE WHERE productid = $1`,
      [idProduto],
    );

    // Em caso de sucesso, envia como resposta o log de sucesso mais mensagem em formato Json
    res.json({ mensagem: "Aviso habilitado com sucesso" });
  } catch (err) {
    console.error("Erro ao ativar aviso", err);
    res.status(500).json({ erro: err.message });
  }
});

// Cria a rota a ser usado no frontend (http://localhost:3000/auth/createProdutos) usando authMiddleware como explicado mais acima
router.post("/createProdutos", authMiddleware, async (req, res) => {
  const { nome, preco, link } = req.body;

  const qtProdutos = await pool.query(
    `SELECT * FROM produtos WHERE userid = $1;`,
    [req.user.id],
  );

  if (qtProdutos.rows.length >= 3) {
    return res.status(401).json({
      erro: "Você tem 10 avisos criados, exclua ao menos 1 para criar um novo",
    });
  }

  try {
    // Executa a criação de avisos no banco
    const result = await pool.query(
      `INSERT INTO produtos (UserID, Nome, PrecoDesejado, Link) VALUES ($1, $2, $3, $4)`,
      [req.user.id, nome, preco, link],
    );

    // Em caso de sucesso, envia como resposta a mensagem de sucesso
    res.json({ mensagem: "Aviso criado com sucesso" });
  } catch (err) {
    console.error("Erro ao criar produto", err);
    res.status(500).json({ erro: err.message });
  }
});

// Cria a rota a ser usado no frontend (http://localhost:3000/auth/autenticarDuploFator)
router.post("/autenticarDuploFator", async (req, res) => {
  // Salva o token obtido via Cookies e o código enviado via corpo da req
  const id_2fa = req.cookies.id_2fa;
  const codigoInserido = req.body.codigoInserido;

  try {
    // Busca pelo 2fa com o ID correspondente no banco
    const result = await pool.query(
      `SELECT * FROM two_factor_codes WHERE id = $1 AND attempts < 3 AND expires_at > NOW() AND mfa_status = TRUE AND type = '2fa';`,
      [id_2fa],
    );

    // Se o retorno for 0 (zero linhas encontradas) o 2fa deste código é invalido (expirado ou inexistente), envia o erro e encerrar o bloco com o return
    if (result.rows.length === 0) {
      return res.status(401).json({
        erro: "Erro ao identificar código, tente gerar um novo código",
      });
    }

    // Será encontrado somente um resultado
    const validar_2fa = result.rows[0];

    /* Compara nosso valor senha obtido através do front com o valor obtido do banco, 
    no banco a senha é um hash, então ele converte a senha do front em hash (mesma logica aplicada para sair o mesmo resultado)
    e então faz a comparação */
    const autenticar_2fa = await bcrypt.compare(
      codigoInserido,
      validar_2fa.code,
    );

    // Se o resultado não for TRUE, os códigos não correspondem, altera o número de tentativas restantes no banco e retorna a msg de erro
    if (!autenticar_2fa) {
      const result = await pool.query(
        `UPDATE two_factor_codes SET attempts = attempts + 1 WHERE id = $1;`,
        [id_2fa],
      );
      return res.status(401).json({ erro: "Codigo invalido" });
    }

    // Se estiver tudo certo, torna o código utilizado invalido (já utilizado)
    await pool.query(
      `UPDATE two_factor_codes SET mfa_status = FALSE WHERE id = $1;`,
      [id_2fa],
    );

    // Retorna as informações do user para fazer login
    const result_user = await pool.query(
      'SELECT * FROM users WHERE "id" = $1;',
      [validar_2fa.user_id],
    );

    //limpa Cookie contendo o código do 2fa
    res.clearCookie("id_2fa", {
      httpOnly: true,
      secure: false, // true em produção (HTTPS)
      sameSite: "Strict",
    });

    const usuario = result_user.rows[0];

    // Gera o token assinado de login
    const token = jwt.sign(
      { id: usuario.id, email: usuario.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" },
    );

    // Cria e salva o Cookie de login
    res.cookie("token", token, {
      httpOnly: true,
      secure: true, // true em produção
      sameSite: "Strict",
      maxAge: 60 * 60 * 1000, // 1 hora
    });
    // retorna msg de sucesso aguardada pelo front
    res.json({ sucesso: "Duplo fator autenticado com sucesso" });

    // Caso aconteça alguma falha, mensagem de erro contendo o erro que aconteceu
  } catch (err) {
    console.error("Erro ao tentar validar duplo fator", err);
    res.status(500).json({ erro: err.message });
  }
});

// Validar Cookie assinado, caso ok, libera a rota do contrario impede acesso a rota
router.get("/protect", authMiddleware, (req, res) => {
  res.json({
    usuario: req.user,
  });
});

//Excluir token de login (realizar logout)
router.post("/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: false, // true em produção (HTTPS)
    sameSite: "Strict",
  });

  res.json({ mensagem: "Logout realizado com sucesso" });
});

// Cria a rota a ser usado no frontend (http://localhost:3000/auth/deleteUser) usando authMiddleware como explicado mais acima
// Rota para desativar usuarios
router.post("/deleteUser", authMiddleware, async (req, res) => {
  try {
    // Executa a desativação de user no banco
    // Apenas muda o user_status para "desativado" não realiza a exclusão no sentido literal (no momento) para fins de auditoria
    const excluirProdutos = await pool.query(
      `DELETE FROM produtos WHERE userid = $1;`,
      [req.user.id],
    );
    const desativarUser = await pool.query(
      `UPDATE users SET status = 'desativado', datadesativacao = now() WHERE id = $1;`,
      [req.user.id],
    );

    // Em caso de sucesso, envia como resposta a mensagem de sucesso
    res.json({
      mensagem:
        "Usuario desativado com sucesso, seus informações serão excluidas em instantes",
    });
  } catch (err) {
    console.error("Erro ao desativar user", err);
    res.status(500).json({ erro: err.message });
  }
});

// Cria a rota a ser usado no frontend (http://localhost:3000/auth/emailRecoverPassword)
// Rota para enviar e-mail de recuperação de senha
router.post("/emailRecoverPassword", async (req, res) => {
  // endereço de email insero no corpo da req
  const email = req.body.email;

  try {
    //Valida se o e-mail existe no banco e está ativo
    const result = await pool.query(
      `SELECT * FROM users WHERE email = $1 AND status = 'ativo'`,
      [email],
    );

    //Caso não encontre, retorna erro
    if (result.rows.length === 0) {
      return res.status(401).json({ erro: "Usuário não encontrado" });
    }

    // O banco não permite e-mails iguais, se ele encontrar algo vai ser apenas 1 linha, salva os valores da linha
    const usuario = result.rows[0];

    // Gera o código para recuperar a senha recebe como resposta o ID do duplo fator criado
    const codigo = await sendTwoFactorCode(usuario, "recover");

    // Cria e salva o cookie referente a recuperação de senha
    res.cookie("recoverPassword", codigo, {
      httpOnly: true,
      secure: false, // true em produção
      sameSite: "Strict",
      maxAge: 5 * 60 * 1000, // 5 minutos (tempo de expiração no banco)
    });
    // Status de sucesso para o front (que aguarda resposta)
    res.json({ sucesso: "e-mail enviado com sucesso" });
    // Caso aconteça alguma falha, mensagem de erro contendo o erro que aconteceu
  } catch (err) {
    console.error("Erro ao gerar código de recuperação:", err);
    res.status(500).json({ erro: err.message });
  }
});

module.exports = router;
