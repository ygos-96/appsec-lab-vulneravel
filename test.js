'use strict';
// Prova automática: na versão vulnerável os 5 ataques funcionam; na corrigida, nenhum.
const { atacar } = require('./exploits/atacar');

async function rodar(nome, modulo, esperadoExplorado) {
  const srv = require(modulo).criar().listen(0);
  await new Promise((r) => srv.once('listening', r));
  const resultados = await atacar(`http://localhost:${srv.address().port}`);
  srv.closeAllConnections();
  srv.close();
  let falhas = 0;
  console.log(`\n== ${nome} ==`);
  for (const [ataque, explorado] of resultados) {
    const ok = explorado === esperadoExplorado;
    if (!ok) falhas++;
    console.log(`${ok ? 'OK   ' : 'FALHA'} ${explorado ? 'EXPLORADO' : 'BLOQUEADO'}  ${ataque}`);
  }
  return falhas;
}

(async () => {
  const f = (await rodar('VULNERAVEL (esperado: tudo explorado)', './vulneravel/server', true))
          + (await rodar('CORRIGIDO (esperado: tudo bloqueado)', './corrigido/server', false));
  console.log(f === 0 ? '\nLaboratório validado.' : `\n${f} resultado(s) fora do esperado.`);
  process.exitCode = f ? 1 : 0;
})();
