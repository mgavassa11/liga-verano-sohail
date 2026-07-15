// =====================================================================
// GET /api/users  ->  { users: [{v, l, i}, ...] }
//
// Alimenta el desplegable de la pantalla de login. Es PÚBLICO por
// necesidad: hace falta antes de que exista una sesión.
//
// Devuelve el MÍNIMO posible: la clave del usuario, su etiqueta y si está
// inactivo. Nada de roles, grupos, emails, teléfonos ni hashes.
// =====================================================================
const { readState, envOK } = require('./_lib');

module.exports = async function handler(req, res){
  if(!envOK(res)) return;

  let state;
  try { state = await readState(); }
  catch(e){ return res.status(503).json({ error: 'No se pudo leer la lista de usuarios.' }); }
  if(!state || !state.users) return res.status(200).json({ users: [] });

  const users = [];
  for(const key of Object.keys(state.users)){
    const u = state.users[key];
    if(!u || typeof u !== 'object') continue;
    users.push({
      v: key,                    // valor que se manda a /api/login
      l: u.name || key,          // etiqueta visible
      i: u.inactive ? 1 : 0      // marca de inactivo
    });
  }

  res.setHeader('Cache-Control', 'no-store');
  return res.status(200).json({ users });
};
