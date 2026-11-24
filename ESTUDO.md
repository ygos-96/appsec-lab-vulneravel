# Estudo: Laboratório vulnerável (antes e depois)

## 1. O que é

Uma API pequena escrita **de propósito com 5 falhas** do OWASP Top 10, mais a versão **corrigida**, mais um script que ataca as duas. Provado por teste automático: **na vulnerável os 5 ataques funcionam; na corrigida, nenhum**.

Ensina o que recrutador de appsec quer ver: você entende a falha, sabe explorar e sabe corrigir.

⚠ Rode só em `localhost`. Nunca publique a versão vulnerável.

## 2. Estrutura

```
vulneravel/server.js   API com as 5 falhas (marcadas [FALHA n])
corrigido/server.js    mesma API corrigida
exploits/atacar.js     5 ataques; imprime EXPLORADO ou BLOQUEADO
test.js                roda tudo nas duas versões e confere
```

Sem dependências. Usa o `node:sqlite` do Node 22.5+ (banco em memória). Rode `npm test`.

Dados de teste: usuários `alice`, `bob` (papel user) e `admin`; pedidos 1, 2 e 3.

## 3. As 5 falhas: como é, como explora, como corrige

### Falha 1: SQL Injection (A03:2021 Injection, CWE-89)
- **Código ruim:** `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`
- **Ataque:** usuário `admin'--`. O `--` comenta o resto, então a consulta vira `WHERE username = 'admin'` e a senha nem é conferida. Entra como admin sem saber a senha.
- **Correção:** consulta **parametrizada** (`WHERE username = ?`). A entrada nunca vira SQL. Além disso, a senha agora é guardada com `scrypt` + sal e conferida em código, não no SQL.

### Falha 2: IDOR (A01:2021 Broken Access Control, CWE-639)
- **Código ruim:** `GET /api/pedidos/:id` devolve o pedido sem ver de quem ele é.
- **Ataque:** a Alice (logada) pede `/api/pedidos/2` e lê a compra do Bob. Basta trocar o número.
- **Correção:** checar `pedido.user_id === usuário da sessão` (ou admin). Responde **404** e não 403, para não revelar que o id existe.

### Falha 3: XSS refletido (A03:2021, CWE-79)
- **Código ruim:** `<h1>Resultados para: ${q}</h1>` com o texto do usuário direto no HTML.
- **Ataque:** `/busca?q=<script>alert(1)</script>` executa script no navegador de quem clicar no link.
- **Correção:** escapar a saída (`<` vira `&lt;`) **e** header `Content-Security-Policy: default-src 'none'`. Duas camadas: se uma falhar, a outra segura.

### Falha 4: Token forjável (A07:2021 Identification and Authentication Failures, CWE-345)
- **Código ruim:** o token é `base64("usuario:papel")`. Base64 não é segredo, é só codificação.
- **Ataque:** qualquer um monta `base64("alice:admin")` e vira admin.
- **Correção:** token **aleatório** (32 bytes) guardado numa tabela de sessões **no servidor**, com expiração de 1h. O papel vem do servidor, nunca do que o cliente manda.

### Falha 5: Mass assignment (A04:2021 Insecure Design / API3:2023, CWE-915)
- **Código ruim:** `POST /api/registro` aceita `{"role":"admin"}` e grava.
- **Ataque:** cadastrar-se já como admin.
- **Correção:** **allowlist**: só `username` e `password` são lidos; o papel é sempre `user`. Também valida formato do usuário e exige senha de no mínimo 10 caracteres.

## 4. Endurecimentos extras na versão corrigida

- Limite de 5 tentativas de login por minuto por IP+usuário (código 429): freia força bruta.
- Cabeçalhos `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` em toda resposta.
- Limite de 10 KB no corpo da requisição.
- A listagem de admin **não devolve mais a coluna de senha**.
- Comparação de hash em tempo constante.

## 5. Resultado do teste

```
== VULNERAVEL ==  5/5 EXPLORADO
== CORRIGIDO   ==  5/5 BLOQUEADO
Laboratório validado.
```

## 6. Limites (seja honesto)

- Sessões e tentativas ficam **em memória**: reiniciar o servidor derruba tudo. Produção usaria Redis ou banco.
- O limite de tentativas usa o IP do socket; atrás de proxy seria preciso tratar `X-Forwarded-For` com cuidado.
- Não há HTTPS nem cookies `HttpOnly/Secure`; o token vai no header `Authorization`.
- Não cobre CSRF, SSRF, upload de arquivo, etc. São 5 falhas escolhidas, não o Top 10 inteiro.
- O XSS foi verificado pela **presença do HTML cru na resposta**, não executando num navegador.

## 7. Como estudar com isso

1. Suba a vulnerável: `npm run vulneravel`.
2. Rode cada ataque **na mão** (Postman, Burp Suite ou `curl`) antes de olhar o script.
3. Leia o `diff` entre `vulneravel/server.js` e `corrigido/server.js`. É o melhor material de revisão.
4. Tente inventar um **sexto** ataque na versão corrigida (por exemplo, enumerar usuários pelo tempo de resposta do login).

## 8. Glossário

- **OWASP Top 10**: lista das categorias de falha mais comuns em aplicações web.
- **CWE**: catálogo de tipos de fraqueza de software.
- **Parametrizada**: a query e os dados vão separados ao banco.
- **Allowlist**: lista do que é permitido (melhor que blocklist).
- **Sal (salt)**: valor aleatório misturado à senha antes do hash.
- **CSP**: política que restringe o que a página pode carregar/executar.

## 9. Perguntas de entrevista

1. Por que consulta parametrizada resolve SQL injection?
2. IDOR e quebra de autorização são a mesma coisa? Como testar?
3. Por que 404 em vez de 403 no pedido alheio?
4. O que há de errado em guardar o papel dentro do token?
5. Escapar a saída ou usar CSP: qual escolher?

## 10. Próximos passos

- Adicionar uma falha de SSRF e outra de CSRF.
- Rodar o Semgrep (do projeto devsecops) sobre `vulneravel/` e ver quais das 5 ele acha.
- Escrever o relatório de pentest dessa API (resumo, severidade, evidência, correção).
