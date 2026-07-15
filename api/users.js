// =====================================================================
// GET /api/users  ->  { groups: [{g, players:[{v,i}]}], loose: [{v,i}] }
//
// Alimenta el desplegable de la pantalla de login. Es PÚBLICO por
// necesidad: hace falta antes de que exista una sesión.
//
// Agrupa por los grupos del CICLO ACTIVO, así el desplegable sigue solo
// a la liga: al cambiar de ciclo, cada jugador aparece donde le toca.
//
// Devuelve el mínimo: nombre, grupo y marca de inactivo.
// Nada de emails, teléfonos, hashes ni resultados.
// =====================================================================
const { readState, envOK } = require('./_lib');

module.exports = async function handler(req, res){
  if(!envOK(res)) return;

  let state;
  try { state = await readState(); }
  catch(e){ return res.status(503).json({ error: 'No se pudo leer la lista de usuarios.' }); }
  if(!state || !state.users) return res.status(200).json({ groups: [], loose: [] });

  const users   = state.users;
  const inact   = n => (users[n] && users[n].inactive) ? 1 : 0;
  const activeN = state.activeN || 1;
  const cyc     = (state.cycles || [])[activeN - 1];

  const seen   = new Set();
  const groups = [];

  if(cyc && Array.isArray(cyc.groups)){
    cyc.groups.forEach((g, i) => {
      const players = (g.players || [])
        .filter(n => users[n])
        .slice()
        .sort((a, b) => a.localeCompare(b, 'es'))
        .map(n => { seen.add(n); return { v: n, i: inact(n) }; });
      groups.push({ g: i + 1, players });
    });
  }

  // Red de seguridad: jugadores que existen pero no están en ningún grupo del
  // ciclo activo. Sin esto quedarían sin poder entrar, porque ya no hay campo
  // de texto donde escribir el nombre a mano.
  const loose = Object.keys(users)
    .filter(n => users[n] && users[n].role === 'player' && !seen.has(n))
    .sort((a, b) => a.localeCompare(b, 'es'))
    .map(n => ({ v: n, i: inact(n) }));

  res.setHeader('Cache-Control', 'no-store');
  return res.status(200).json({ groups, loose });
};
