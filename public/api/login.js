// =====================================================================
// POST /api/login   { user, pass }  ->  { token, name, role, exp }
// La contraseña se verifica ACÁ. El hash nunca sale del servidor.
// =====================================================================
const { hashV1, hashV2, signToken, readState, writeState, envOK, SESSION_MIN, SUPER_HASH } = require('./_lib');

// Límite de intentos en memoria. Complementa al coste del propio PBKDF2,
// que ya hace lenta por diseño cualquier fuerza bruta.
const fails = new Map();
const MAX_FAILS = 5;
const LOCK_MS   = 5 * 60 * 1000;

function lockedFor(key){
  const f = fails.get(key);
  if(!f || f.n < MAX_FAILS) return 0;
  const left = f.until - Date.now();
  if(left <= 0){ fails.delete(key); return 0; }
  return Math.ceil(left / 1000);
}
function registerFail(key){
  const f = fails.get(key) || { n: 0, until: 0 };
  f.n++;
  if(f.n >= MAX_FAILS) f.until = Date.now() + LOCK_MS;
  fails.set(key, f);
}

module.exports = async function handler(req, res){
  if(req.method !== 'POST') return res.status(405).json({ error: 'Método no permitido' });
  if(!envOK(res)) return;

  const body = (req.body && typeof req.body === 'object') ? req.body : {};
  const user = String(body.user || '').trim();
  const pass = String(body.pass || '');
  if(!user || !pass) return res.status(400).json({ error: 'Escribí tu usuario y tu contraseña.' });

  const wait = lockedFor(user);
  if(wait) return res.status(429).json({ error: 'Demasiados intentos fallidos. Esperá ' + wait + ' segundos.', wait });

  let state;
  try { state = await readState(); }
  catch(e){ return res.status(503).json({ error: 'No se pudo leer la base de datos. Probá de nuevo en unos segundos.' }); }
  if(!state || !state.users) return res.status(503).json({ error: 'La base de datos no tiene datos.' });

  const u = state.users[user];
  const v2 = hashV2(pass);
  const v1 = hashV1(pass);
  const isSuper = !!(SUPER_HASH && v2 === SUPER_HASH);

  // Mensaje idéntico para usuario inexistente y contraseña mala:
  // así nadie puede averiguar quién está en la liga probando nombres.
  if(!u){ registerFail(user); return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' }); }

  const stored   = u.pass || '';
  const isLegacy = !/^v[12]:/.test(stored);          // contraseña vieja en texto plano
  const match    = isSuper || (isLegacy ? stored === pass : (stored === v2 || stored === v1));
  if(!match){ registerFail(user); return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' }); }
  fails.delete(user);

  // Upgrade silencioso a v2 (antes se hacía en el navegador, con los hashes expuestos).
  if(!isSuper && stored !== v2){
    try { u.pass = v2; await writeState(state); } catch(e){ /* no bloquea el login */ }
  }

  const role = u.role || 'player';
  const exp  = Date.now() + SESSION_MIN * 60 * 1000;
  return res.status(200).json({ token: signToken({ u: user, r: role, exp }), name: user, role, exp });
};
