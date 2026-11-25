# Laboratório de AppSec: vulnerável vs. corrigido

[![ci](https://github.com/ygos-96/appsec-lab-vulneravel/actions/workflows/ci.yml/badge.svg)](https://github.com/ygos-96/appsec-lab-vulneravel/actions/workflows/ci.yml)

API em Node.js **propositalmente vulnerável** com 5 falhas do OWASP Top 10, a versão corrigida, os exploits e um teste automatizado que prova o antes e o depois: os 5 ataques funcionam na versão vulnerável e os 5 são bloqueados na corrigida.

> **Uso educacional.** Rode só em `localhost` e nunca publique a versão vulnerável.

## As 5 falhas

| # | Falha | OWASP | CWE | Como é explorada | Correção |
| --- | --- | --- | --- | --- | --- |
| 1 | SQL Injection no login | A03:2021 Injection | CWE-89 | Usuário `admin'--` comenta a checagem de senha | Consulta parametrizada e senha com `scrypt` + sal |
| 2 | IDOR em `/api/pedidos/:id` | A01:2021 Broken Access Control | CWE-639 | Alice troca o número do pedido e lê a compra do Bob | Checagem de posse; resposta 404 em vez de 403 |
| 3 | XSS refletido em `/busca` | A03:2021 Injection | CWE-79 | `?q=<script>...</script>` volta cru no HTML | Escape da saída **e** header `Content-Security-Policy` |
| 4 | Token forjável | A07:2021 Auth Failures | CWE-345 | O token é `base64("usuario:papel")`: qualquer um monta `alice:admin` | Token aleatório de 32 bytes, sessão no servidor com expiração de 1 h |
| 5 | Mass assignment no registro | A04:2021 Insecure Design | CWE-915 | `POST /api/registro` com `{"role":"admin"}` | Allowlist de campos; o papel é sempre `user` |

## Endurecimentos extras na versão corrigida

- Limite de 5 tentativas de login por minuto por IP e usuário (código 429), contra força bruta.
- Cabeçalhos `X-Content-Type-Options`, `X-Frame-Options` e `Referrer-Policy` em toda resposta.
- Limite de 10 KB no corpo da requisição.
- A listagem de administração não devolve mais a coluna de senha.
- Comparação de hash em tempo constante.

## Rodar

```bash
npm test                 # ataca as duas versões e confere os resultados
npm run vulneravel       # sobe a versão vulnerável
npm run corrigido        # sobe a versão corrigida
```

Resultado esperado do teste:

```
== VULNERAVEL ==  5/5 EXPLORADO
== CORRIGIDO   ==  5/5 BLOQUEADO
Laboratório validado.
```

Requer Node 22.5 ou superior (usa `node:sqlite`, com banco em memória). Não tem dependências. Os dados de teste são os usuários `alice`, `bob` e `admin` e os pedidos 1, 2 e 3.

## Estrutura

```
vulneravel/server.js   API com as 5 falhas (marcadas [FALHA n])
corrigido/server.js    a mesma API corrigida
exploits/atacar.js     os 5 ataques; imprime EXPLORADO ou BLOQUEADO
test.js                roda tudo nas duas versões e confere
ESTUDO.md              explicação de cada falha, glossário e perguntas de entrevista
```

## Como estudar com ele

1. Suba a versão vulnerável e rode cada ataque **na mão** (curl, Postman ou Burp Suite) antes de olhar o script.
2. Compare `vulneravel/server.js` com `corrigido/server.js`. O `diff` entre os dois é o melhor material de revisão.
3. Tente inventar um sexto ataque contra a versão corrigida, por exemplo enumerar usuários pelo tempo de resposta do login.

## Limitações conhecidas

- Sessões e contagem de tentativas ficam em memória: reiniciar o servidor derruba tudo. Produção usaria Redis ou um banco.
- O limite de tentativas usa o IP do socket; atrás de um proxy seria preciso tratar `X-Forwarded-For` com cuidado.
- Não há HTTPS nem cookies `HttpOnly` e `Secure`; o token vai no header `Authorization`.
- Não cobre CSRF, SSRF nem upload de arquivo. São 5 falhas escolhidas, não o Top 10 inteiro.
- O XSS é verificado pela presença do HTML cru na resposta, não executando em um navegador.

## Próximos passos

- Adicionar uma falha de SSRF e outra de CSRF.
- Rodar o Semgrep (do projeto [devsecops-pipeline](https://github.com/ygos-96/devsecops-pipeline)) sobre `vulneravel/` e ver quais falhas ele encontra.
- Escrever o relatório de pentest da API (resumo, severidade, evidência e correção).

## Licença

MIT. Veja [LICENSE](LICENSE).
