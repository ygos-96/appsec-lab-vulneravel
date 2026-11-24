'use strict';
// ⚠ PROPOSITALMENTE VULNERÁVEL. Laboratório de estudo: rode só na sua máquina (localhost).
// Cada falha está marcada com [FALHA n]. A versão corrigida está em ../corrigido/server.js.
const http = require('node:http');
const { DatabaseSync } = require('node:sqlite');

function criar() {
  const db = new DatabaseSync(':memory:');
  db.exec(`
    CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT);
    CREATE TABLE orders(id INTEGER PRIMARY KEY, user_id INTEGER, item TEXT, total REAL);
    INSERT INTO users VALUES (1,'alice','alice123','user'),(2,'bob','bob123','user'),(3,'admin','S3nh4-do-admin','admin');
    INSERT INTO orders VALUES (1,1,'Curso de n8n',197),(2,2,'Mentoria',497),(3,3,'Pedido interno',0);
  `);

  const ler = (req) => new Promise((ok) => {
    let b = '';
    req.on('data', (c) => (b += c));
    req.on('end', () => { try { ok(JSON.parse(b || '{}')); } catch { ok({}); } });
  });
  const json = (res, status, obj) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };

  // [FALHA 4] token = base64("usuario:papel"). Qualquer um fabrica um token de admin.
  const usuarioDoToken = (req) => {
    const t = (req.headers.authorization || '').replace('Bearer ', '');
    try {
      const [username, role] = Buffer.from(t, 'base64').toString().split(':');
      return username && role ? { username, role, id: db.prepare('SELECT id FROM users WHERE username = ?').get(username)?.id } : null;
    } catch { return null; }
  };

  return http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x');

    if (req.method === 'POST' && url.pathname === '/api/login') {
      const { username, password } = await ler(req);
      // [FALHA 1] SQL Injection: entrada do usuário concatenada na query.
      const u = db.prepare(`SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`).get();
      if (!u) return json(res, 401, { erro: 'credenciais invalidas' });
      return json(res, 200, { token: Buffer.from(`${u.username}:${u.role}`).toString('base64') });
    }

    if (req.method === 'POST' && url.pathname === '/api/registro') {
      const b = await ler(req);
      // [FALHA 5] Mass assignment: o cliente escolhe o próprio papel (role).
      try {
        db.prepare('INSERT INTO users(username, password, role) VALUES (?, ?, ?)').run(b.username, b.password, b.role || 'user');
      } catch { return json(res, 409, { erro: 'usuario ja existe' }); }
      return json(res, 201, { ok: true });
    }

    if (req.method === 'GET' && url.pathname.startsWith('/api/pedidos/')) {
      const eu = usuarioDoToken(req);
      if (!eu) return json(res, 401, { erro: 'nao autenticado' });
      // [FALHA 2] IDOR: devolve o pedido pelo id sem checar de quem ele é.
      const o = db.prepare('SELECT * FROM orders WHERE id = ?').get(Number(url.pathname.split('/').pop()));
      return o ? json(res, 200, o) : json(res, 404, { erro: 'nao encontrado' });
    }

    if (req.method === 'GET' && url.pathname === '/busca') {
      // [FALHA 3] XSS refletido: o parâmetro q volta no HTML sem escapar.
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return res.end(`<h1>Resultados para: ${url.searchParams.get('q') || ''}</h1>`);
    }

    if (req.method === 'GET' && url.pathname === '/api/admin/usuarios') {
      const eu = usuarioDoToken(req);
      if (!eu) return json(res, 401, { erro: 'nao autenticado' });
      if (eu.role !== 'admin') return json(res, 403, { erro: 'so admin' });
      return json(res, 200, db.prepare('SELECT id, username, password, role FROM users').all());
    }

    json(res, 404, { erro: 'rota inexistente' });
  });
}

if (require.main === module) {
  criar().listen(process.env.PORT || 3101, () => console.log('VULNERAVEL em http://localhost:' + (process.env.PORT || 3101)));
}
module.exports = { criar };
