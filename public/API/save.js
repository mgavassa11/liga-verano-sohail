// =====================================================================
// POST /api/save    (Authorization: Bearer <token>)   { state }
// Sin token no se escribe nada. Y lo que un jugador nunca vio,
// tampoco lo puede pisar: se reinyecta desde la base.
// =====================================================================
const { auth, readState, writeState, envOK, isAdminRole } = require('./_lib');

module.exports = async function handler(req, res){
  if(req.method !== 'POST') return res.status(405).json({ error: 'Método no permitido' });
  if(!envOK(res)) return;

  const session = auth(req);
  if(!session) return res.status(401).json({ error: 'Sesión inválida o expirada. Volvé a entrar.' });

  const incoming = req.body && req.body.state;
  if(!incoming || typeof incoming !== 'object' || !incoming.users || !incoming.cycles){
    return res.status(400).json({ error: 'Estado inválido: no se guarda.' });
  }

  let current;
  try { current = await readState(); }
  catch(e){ return res.status(503).json({ error: 'No se pudo leer la base de datos; no se guardó nada.' }); }

  // Nunca sobrescribimos una base que no pudimos leer: misma protección que ya
  // tenía el cliente contra el incidente de "liga vacía".
  if(!current) return res.status(409).json({ error: 'La base respondió vacía; no se sobrescribe.' });

  const admin    = isAdminRole(session.r);
  const curUsers = current.users || {};

  if(!admin){
    // Un jugador no puede alterar el padrón: ni crear, ni borrar, ni renombrar.
    const before = Object.keys(curUsers).sort().join('|');
    const after  = Object.keys(incoming.users).sort().join('|');
    if(before !== after){
      return res.status(403).json({ error: 'No tenés permiso para modificar los jugadores.' });
    }
    // Y los campos privados vuelven tal cual estaban en la base: el cliente
    // nunca los recibió, así que no puede ni pisarlos ni filtrarlos.
    for(const name of Object.keys(incoming.users)){
      const inU = incoming.users[name], curU = curUsers[name];
      if(!inU || !curU) continue;
      inU.pass = curU.pass;
      inU.role = curU.role;                       // nadie se auto-asciende
      if('email' in curU) inU.email = curU.email; else delete inU.email;
      if('tel'   in curU) inU.tel   = curU.tel;   else delete inU.tel;
    }
  }

  try { await writeState(incoming); }
  catch(e){ return res.status(503).json({ error: 'No se pudo guardar: ' + e.message }); }

  return res.status(200).json({ ok: true });
};
