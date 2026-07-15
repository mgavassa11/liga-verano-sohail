// =====================================================================
// GET /api/state    (Authorization: Bearer <token>)  ->  { state }
// Devuelve el estado FILTRADO según quién pregunta.
// Sin token válido no devuelve absolutamente nada.
// =====================================================================
const { auth, readState, envOK, isAdminRole } = require('./_lib');

function filterForSession(state, session){
  const admin = isAdminRole(session.r);
  const out   = JSON.parse(JSON.stringify(state));
  const users = out.users || {};

  for(const name of Object.keys(users)){
    const u = users[name];
    if(!u || typeof u !== 'object') continue;

    if(!admin){
      // Un jugador NO recibe el hash de nadie (ni el suyo): el login es del servidor.
      delete u.pass;
      // Ni los datos de contacto de los demás. Los propios sí.
      if(name !== session.u){
        delete u.email;
        delete u.tel;
      }
    }
    // El admin sí recibe los hashes, porque los necesita para el panel de
    // gestión de contraseñas. Es el único rol que los ve.
  }
  return out;
}

module.exports = async function handler(req, res){
  if(!envOK(res)) return;

  const session = auth(req);
  if(!session) return res.status(401).json({ error: 'Sesión inválida o expirada. Volvé a entrar.' });

  let state;
  try { state = await readState(); }
  catch(e){ return res.status(503).json({ error: 'No se pudo leer la base de datos.' }); }

  if(!state) return res.status(200).json({ empty: true });

  res.setHeader('Cache-Control', 'no-store');
  return res.status(200).json({ state: filterForSession(state, session), role: session.r, name: session.u });
};
