// =====================================================================
// POST /api/password   (Authorization: Bearer <token>)
//   { oldPass, newPass }            -> el usuario cambia SU contraseña
//   { target, newPass }             -> un admin le fija la contraseña a otro
//
// Existe porque el jugador ya no recibe ningún hash: la verificación de la
// contraseña anterior tiene que ocurrir del lado del servidor.
// =====================================================================
const { hashV1, hashV2, auth, readState, writeState, envOK, isAdminRole, SUPER_HASH } = require('./_lib');

module.exports = async function handler(req, res){
  if(req.method !== 'POST') return res.status(405).json({ error: 'Método no permitido' });
  if(!envOK(res)) return;

  const session = auth(req);
  if(!session) return res.status(401).json({ error: 'Sesión inválida o expirada. Volvé a entrar.' });

  const body    = (req.body && typeof req.body === 'object') ? req.body : {};
  const newPass = String(body.newPass || '');
  const target  = body.target ? String(body.target) : null;
  const admin   = isAdminRole(session.r);

  if(newPass.length < 4) return res.status(400).json({ error: 'La contraseña debe tener al menos 4 caracteres.' });
  if(target && !admin)   return res.status(403).json({ error: 'No tenés permiso para cambiar la contraseña de otro jugador.' });

  let state;
  try { state = await readState(); }
  catch(e){ return res.status(503).json({ error: 'No se pudo leer la base de datos.' }); }
  if(!state || !state.users) return res.status(503).json({ error: 'La base de datos no tiene datos.' });

  const name = target || session.u;
  const u = state.users[name];
  if(!u) return res.status(404).json({ error: 'No se encontró ese usuario.' });

  // La contraseña del super administrador solo la cambia él mismo. Antes acá
  // solo se chequeaba que quien pedía fuera admin, no A QUIÉN apuntaba: un
  // admin podía fijarle la clave al super y entrar como él.
  if(u.role === 'superadmin' && session.u !== name){
    return res.status(403).json({ error: 'La contraseña del super administrador solo la puede cambiar él mismo.' });
  }

  // Cambiando la propia: hay que probar que sabés la anterior.
  if(!target){
    const oldPass  = String(body.oldPass || '');
    const stored   = u.pass || '';
    const isLegacy = !/^v[12]:/.test(stored);
    const oldV2    = hashV2(oldPass);
    const oldOK    = (SUPER_HASH && oldV2 === SUPER_HASH)
                  || (isLegacy ? stored === oldPass : (stored === oldV2 || stored === hashV1(oldPass)));
    if(!oldOK) return res.status(401).json({ error: 'La contraseña actual no es correcta.' });
  }

  u.pass = hashV2(newPass);
  try { await writeState(state); }
  catch(e){ return res.status(503).json({ error: 'No se pudo guardar la contraseña nueva.' }); }

  return res.status(200).json({ ok: true });
};
