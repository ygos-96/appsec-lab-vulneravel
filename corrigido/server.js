'use strict';
// Versão corrigida do laboratório. Cada correção cita a falha de ../vulneravel/server.js.
const http = require('node:http');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

// [FALHA 4/1] Senha nunca em texto puro: scrypt com sal aleatório.
const hash = (senha) => {
  const sal = crypto.randomBytes(16);
  return sal.toString('hex') + ':' + crypto.scryptSync(senha, sal, 32).toString('hex');
};
const confere = (senha, guardado) => {
  const [sal, h] = guardado.split(':');
  const novo = crypto.scryptSync(senha, Buffer.from(sal, 'hex'), 32);
  return crypto.timingSafeEqual(novo, Buffer.from(h, 'hex'));
};
const escapar = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

function criar() {
  const db = new DatabaseSync(':memory:');
  db.exec(`
    CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT);
    CREATE TABLE orders(id INTEGER PRIMARY KEY, user_id INTEGER, item TEXT, total REAL);
    INSERT INTO orders VALUES (1,1,'Curso de n8n',197),(2,2,'Mentoria',497),(3,3,'Pedido interno',0);
  `);
  const novoUsuario = db.prepare('INSERT INTO users(id, username, password, role) VALUES (?, ?, ?, ?)');
  novoUsuario.run(1, 'alice', hash('alice123'), 'user');
  novoUsuario.run(2, 'bob', hash('bob123'), 'user');
  novoUsuario.run(3, 'admin', hash('S3nh4-do-admin'), 'admin');

  const sessoes = new Map(); // token aleatório -> { id, role, expira }
  const tentativas = new Map(); // ip+usuario -> { n, desde }

  const ler = (req) => new Promise((ok) => {
    let b = '';
    req.on('data', (c) => { b += c; if (b.length > 10_000) req.destroy(); }); // limite de tamanho
    req.on('end', () => { try { ok(JSON.parse(b || '{}')); } catch { ok({}); } });
  });
  // Cabeçalhos de segurança em toda resposta.
  const base = { 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY', 'referrer-policy': 'no-referrer' };
  const json = (res, status, obj) => { res.writeHead(status, { ...base, 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };

  // [FALHA 4] A identidade vem do SERVIDOR (mapa de sessões), não de dados que o cliente controla.
  const sessaoDe = (req) => {
    const s = sessoes.get((req.headers.authorization || '').replace('Bearer ', ''));
    return s && s.expira > Date.now() ? s : null;
  };

  return http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x');

    if (req.method === 'POST' && url.pathname === '/api/login') {
      const { username, password } = await ler(req);
      if (typeof username !== 'string' || typeof password !== 'string') return json(res, 400, { erro: 'dados invalidos' });
      // Limite de tentativas: 5 por minuto por IP+usuário (freia força bruta).
      const chave = req.socket.remoteAddress + '|' + username;
      const t = tentativas.get(chave) || { n: 0, desde: Date.now() };
      if (Date.now() - t.desde > 60_000) { t.n = 0; t.desde = Date.now(); }
      if (++t.n > 5) return json(res, 429, { erro: 'muitas tentativas' });
      tentativas.set(chave, t);

      // [FALHA 1] Consulta parametrizada: a entrada nunca vira SQL.
      const u = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
      if (!u || !confere(password, u.password)) return json(res, 401, { erro: 'credenciais invalidas' });
      const token = crypto.randomBytes(32).toString('hex');
      sessoes.set(token, { id: u.id, role: u.role, expira: Date.now() + 3_600_000 });
      return json(res, 200, { token });
    }

    if (req.method === 'POST' && url.pathname === '/api/registro') {
      const b = await ler(req);
      if (typeof b.username !== 'string' || typeof b.password !== 'string' || b.password.length < 10 || !/^[a-z0-9_]{3,20}$/.test(b.username)) {
        return json(res, 400, { erro: 'usuario (3-20, a-z0-9_) e senha (min 10) obrigatorios' });
      }
      try {
        // [FALHA 5] Allowlist: só username e password são lidos. O papel é sempre 'user'.
        db.prepare('INSERT INTO users(username, password, role) VALUES (?, ?, ?)').run(b.username, hash(b.password), 'user');
      } catch { return json(res, 409, { erro: 'usuario ja existe' }); }
      return json(res, 201, { ok: true });
    }

    if (req.method === 'GET' && url.pathname.startsWith('/api/pedidos/')) {
      const eu = sessaoDe(req);
      if (!eu) return json(res, 401, { erro: 'nao autenticado' });
      const o = db.prepare('SELECT * FROM orders WHERE id = ?').get(Number(url.pathname.split('/').pop()));
      // [FALHA 2] Checa a posse. 404 (e não 403) para não revelar que o id existe.
      if (!o || (o.user_id !== eu.id && eu.role !== 'admin')) return json(res, 404, { erro: 'nao encontrado' });
      return json(res, 200, o);
    }

    if (req.method === 'GET' && url.pathname === '/busca') {
      // [FALHA 3] Escapa a saída + CSP que proíbe script inline.
      res.writeHead(200, { ...base, 'content-type': 'text/html; charset=utf-8', 'content-security-policy': "default-src 'none'; style-src 'self'" });
      return res.end(`<h1>Resultados para: ${escapar(url.searchParams.get('q') || '')}</h1>`);
    }

    if (req.method === 'GET' && url.pathname === '/api/admin/usuarios') {
      const eu = sessaoDe(req);
      if (!eu) return json(res, 401, { erro: 'nao autenticado' });
      if (eu.role !== 'admin') return json(res, 403, { erro: 'so admin' });
      return json(res, 200, db.prepare('SELECT id, username, role FROM users').all()); // sem coluna de senha
    }

    json(res, 404, { erro: 'rota inexistente' });
  });
}

if (require.main === module) {
  criar().listen(process.env.PORT || 3102, () => console.log('CORRIGIDO em http://localhost:' + (process.env.PORT || 3102)));
}
module.exports = { criar };
