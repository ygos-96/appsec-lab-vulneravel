# Laboratório de AppSec: vulnerável vs. corrigido

API em Node.js **propositalmente vulnerável** com 5 falhas do OWASP Top 10, a versão corrigida, os exploits e um teste automático que prova o antes e o depois.

⚠ Uso educacional. Rode só em localhost.

| # | Falha | Categoria OWASP | Correção |
| --- | --- | --- | --- |
| 1 | SQL Injection no login | A03 Injection | Query parametrizada + scrypt |
| 2 | IDOR em `/api/pedidos/:id` | A01 Broken Access Control | Checagem de posse |
| 3 | XSS refletido em `/busca` | A03 Injection | Escape de saída + CSP |
| 4 | Token forjável (base64) | A07 Auth Failures | Sessão aleatória no servidor |
| 5 | Mass assignment no registro | A04 Insecure Design | Allowlist de campos |

```bash
npm test    # 5 ataques na vulnerável (todos funcionam) e na corrigida (todos bloqueados)
```

Requer Node 22.5+ (usa `node:sqlite`). Sem dependências. Detalhes em `ESTUDO.md`.
