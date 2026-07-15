// =====================================================================
// GET /api/state    (Authorization: Bearer <token>)  ->  { state }
// Devuelve el estado FILTRADO según quién pregunta.
// Sin token válido no devuelve absolutamente nada.
//
// El login ya trae el estado en su propia respuesta, así que esto queda
// para recargas y para cualquier refresco posterior.
// =====================================================================
const { auth, readState, envOK, filterForSession } = require('./_lib');

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
