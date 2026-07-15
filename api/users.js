// =====================================================================
// GET /api/users
//   ->  { mode:'cyc'|'po', sections:[{k, players:[{v,i}]}], loose:[{v,i}] }
//
// Alimenta el desplegable de la pantalla de login. Es PÚBLICO por
// necesidad: hace falta antes de que exista una sesión.
//
// Se reorganiza solo según el momento de la liga:
//   - Liga en curso  -> agrupa por los grupos del CICLO ACTIVO
//   - Playoffs       -> agrupa por CUADRO (A, B, C...)
//
// Devuelve el mínimo: nombre, sección y marca de inactivo.
// Nada de emails, teléfonos, hashes ni resultados.
// =====================================================================
const { readState, envOK } = require('./_lib');

module.exports = async function handler(req, res){
  if(!envOK(res)) return;

  let state;
  try { state = await readState(); }
  catch(e){ return res.status(503).json({ error: 'No se pudo leer la lista de usuarios.' }); }
  if(!state || !state.users) return res.status(200).json({ mode: 'cyc', sections: [], loose: [] });

  const users = state.users;
  const inact = n => (users[n] && users[n].inactive) ? 1 : 0;
  const abc   = (a, b) => a.localeCompare(b, 'es');

  const seen     = new Set();
  const sections = [];
  const po       = state.playoff || {};
  const enPO     = !!(po.started && Array.isArray(po.tramos) && po.tramos.length);
  let   mode     = 'cyc';

  if(enPO){
    // --- Playoffs: una sección por cuadro ---
    // Da igual si el jugador está en el cuadro principal o en consolación:
    // los seeds del tramo son los mismos, solo importa en qué cuadro está.
    mode = 'po';
    po.tramos.forEach((tr, i) => {
      const players = (tr.seeds || [])
        .filter(n => users[n])                 // descarta BYE / TBD
        .slice().sort(abc)
        .map(n => { seen.add(n); return { v: n, i: inact(n) }; });
      sections.push({ k: tr.label || String.fromCharCode(65 + i), players });
    });
  }else{
    // --- Liga en curso: una sección por grupo del ciclo activo ---
    const cyc = (state.cycles || [])[(state.activeN || 1) - 1];
    if(cyc && Array.isArray(cyc.groups)){
      cyc.groups.forEach((g, i) => {
        const players = (g.players || [])
          .filter(n => users[n])
          .slice().sort(abc)
          .map(n => { seen.add(n); return { v: n, i: inact(n) }; });
        sections.push({ k: i + 1, players });
      });
    }
  }

  // Red de seguridad: jugadores que existen pero no cayeron en ninguna sección.
  // Sin esto quedarían sin poder entrar, porque ya no hay campo de texto donde
  // escribir el nombre a mano.
  const loose = Object.keys(users)
    .filter(n => users[n] && users[n].role === 'player' && !seen.has(n))
    .sort(abc)
    .map(n => ({ v: n, i: inact(n) }));

  res.setHeader('Cache-Control', 'no-store');
  return res.status(200).json({ mode, sections, loose });
};
