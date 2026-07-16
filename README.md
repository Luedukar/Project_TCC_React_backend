# Monitor de Preços — TCC (Backend)

API REST desenvolvida para o Trabalho de Conclusão de Curso (TCC) do curso de Engenharia de Software. Responsável pela autenticação de usuários, autenticação de dois fatores (2FA) por e-mail, gerenciamento de sessão via JWT em cookies e CRUD dos produtos monitorados.

> Este repositório é o **backend**. O frontend correspondente está em [Project_TCC_React](https://github.com/Luedukar/Project_TCC_React).

## ✨ Funcionalidades

- **Cadastro e login** com senha criptografada (bcrypt)
- **Autenticação de dois fatores (2FA)** por e-mail, com código de 6 dígitos, expiração e reenvio controlado
- **Sessão via JWT** armazenado em cookie `httpOnly`
- **Recuperação de senha** com fluxo próprio de 2FA e token de redefinição de curta duração
- **Rate limiting** por rota sensível (login, cadastro, 2FA, recuperação de senha, reenvio)
- **CRUD de produtos monitorados**, com limite de 10 produtos por usuário
- **Ativação/desativação de aviso** por produto
- **Exclusão lógica de conta** (soft delete, mantendo dados para auditoria)
- Validação de formato **e** domínio de e-mail no cadastro

## 🛠️ Tecnologias

- [Node.js](https://nodejs.org/) + [Express 5](https://expressjs.com/)
- [PostgreSQL](https://www.postgresql.org/) via [`pg`](https://node-postgres.com/)
- [JWT](https://github.com/auth0/node-jsonwebtoken) para autenticação de sessão
- [bcrypt](https://www.npmjs.com/package/bcrypt) para hash de senhas e códigos 2FA
- [Nodemailer](https://nodemailer.com/) para envio de e-mails (2FA e recuperação de senha)
- [express-rate-limit](https://www.npmjs.com/package/express-rate-limit)
- `cookie-parser`, `cors`, `dotenv`

## 📁 Estrutura do projeto

```
src/
├── config/
│   └── db.js                    # Configuração do pool de conexão PostgreSQL
├── middleware/
│   ├── authMiddleware.js        # Valida JWT (login e redefinição de senha)
│   └── rateLimitMiddleware.js   # Limitadores de requisição por rota
├── routes/
│   └── authRoutes.js            # Todas as rotas da API (prefixo /auth)
├── services/
│   ├── checkEmail.js            # Validação de formato/domínio de e-mail
│   ├── emailService.js          # Envio de e-mails via Nodemailer
│   ├── jwtService.js            # Geração/validação de códigos 2FA e cookies
│   └── templates/               # Templates HTML dos e-mails de 2FA
└── server.js                    # Ponto de entrada da aplicação
```

## 🔗 Endpoints (prefixo `/auth`)

| Método | Rota                         | Autenticação        | Descrição                                                    |
| ------ | ---------------------------- | ------------------- | ------------------------------------------------------------ |
| POST   | `/login`                     | —                   | Valida e-mail/senha e dispara o envio do 2FA                 |
| POST   | `/register`                  | —                   | Cria um novo usuário                                         |
| POST   | `/autenticarDuploFator`      | Cookie `id_2fa`     | Valida o código 2FA e gera o token de sessão                 |
| GET    | `/protect`                   | JWT (`token`)       | Verifica se a sessão é válida                                |
| GET    | `/me`                        | JWT (`token`)       | Retorna dados do usuário logado                              |
| POST   | `/logout`                    | —                   | Remove o cookie de sessão                                    |
| POST   | `/deleteUser`                | JWT (`token`)       | Desativa a conta (soft delete)                               |
| GET    | `/productsMe`                | JWT (`token`)       | Lista os produtos do usuário                                 |
| POST   | `/createProdutos`            | JWT (`token`)       | Cria um novo produto monitorado (máx. 10 por usuário)        |
| POST   | `/delete`                    | JWT (`token`)       | Remove um produto                                            |
| POST   | `/avisoOn` / `/avisoOff`     | JWT (`token`)       | Ativa/desativa aviso de um produto                           |
| POST   | `/emailRecoverPassword`      | —                   | Envia código de recuperação de senha por e-mail              |
| POST   | `/autenticarDuploFatorSenha` | Cookie `id_2fa`     | Valida o código e gera token de redefinição                  |
| POST   | `/RedefinirPassword`         | JWT (`Redefinicao`) | Define a nova senha                                          |
| POST   | `/Reenviar`                  | Cookie `id_2fa`     | Reenvia o código 2FA (limite de 3 reenvios, cooldown de 60s) |

## 🔒 Segurança

- Senhas e códigos 2FA nunca são armazenados em texto puro (hash com `bcrypt`)
- Cookies de sessão são `httpOnly` e `sameSite: Strict`
- Rate limiting configurado por rota sensível para mitigar força bruta
- Códigos 2FA expiram em 5 minutos e têm limite de 3 tentativas

> **Nota:** a flag `isProduction` em `authRoutes.js` está fixa como `false`, o que desativa o atributo `secure` dos cookies. Ao publicar em produção (HTTPS), será ajustada para `true`.

## 📌 Status do projeto

Projeto em desenvolvimento contínuo como parte do TCC do curso de Engenharia de Software.

## 👤 Autor

Desenvolvido por [**Luedukar**](https://github.com/Luedukar) (ME)
