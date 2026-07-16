// =====================================================================
// POST /api/login   { user, pass }  ->  { token, name, role, exp }
// La contraseña se verifica ACÁ. El hash nunca sale del servidor.
// =====================================================================
const { hashV1, hashV2, signToken, readState, writeState, envOK, filterForSession, SESSION_MIN, SUPER_HASH } = require('./_lib');

// Límite de intentos en memoria. Complementa al coste del propio PBKDF2,
// que ya hace lenta por diseño cualquier fuerza bruta.
//
// Se cuenta por USUARIO y también por IP. Solo por usuario no alcanzaba: los
// nombres son públicos (los necesita el desplegable del login), así que barrer
// los 60 probando la clave por defecto daba 1 intento por usuario y no
// disparaba nunca el bloqueo.
const fails = new Map();
const MAX_FAILS = 5;      // por usuario
const MAX_IP    = 12;     // por IP: tolera una familia tras el mismo router
const LOCK_MS   = 5 * 60 * 1000;

function clientIP(req){
  const xf = req.headers['x-forwarded-for'];
  if(xf) return String(xf).split(',')[0].trim();
  return req.headers['x-real-ip'] || 'desconocida';
}

function lockedFor(key, max){
  const f = fails.get(key);
  if(!f || f.n < max) return 0;
  const left = f.until - Date.now();
  if(left <= 0){ fails.delete(key); return 0; }
  return Math.ceil(left / 1000);
}
function registerFail(key, max){
  const f = fails.get(key) || { n: 0, until: 0 };
  f.n++;
  if(f.n >= max) f.until = Date.now() + LOCK_MS;
  fails.set(key, f);
}
function fail(user, ip){ registerFail('u:' + user, MAX_FAILS); registerFail('i:' + ip, MAX_IP); }

module.exports = async function handler(req, res){
  if(req.method !== 'POST') return res.status(405).json({ error: 'Método no permitido' });
  if(!envOK(res)) return;

  const body = (req.body && typeof req.body === 'object') ? req.body : {};
  const user = String(body.user || '').trim();
  const pass = String(body.pass || '');
  if(!user || !pass) return res.status(400).json({ error: 'Escribí tu usuario y tu contraseña.' });

  const ip     = clientIP(req);
  const waitU  = lockedFor('u:' + user, MAX_FAILS);
  const waitIP = lockedFor('i:' + ip, MAX_IP);
  const wait   = Math.max(waitU, waitIP);
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
  if(!u){ fail(user, ip); return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' }); }

  const stored   = u.pass || '';
  const isLegacy = !/^v[12]:/.test(stored);          // contraseña vieja en texto plano
  const match    = isSuper || (isLegacy ? stored === pass : (stored === v2 || stored === v1));
  if(!match){ fail(user, ip); return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' }); }
  fails.delete('u:' + user); fails.delete('i:' + ip);

  // Upgrade silencioso a v2 (antes se hacía en el navegador, con los hashes expuestos).
  // OJO con el orden: esto tiene que pasar ANTES de filtrar, porque filtrar borra
  // los hashes del objeto y guardaríamos un estado sin contraseñas.
  if(!isSuper && stored !== v2){
    try { u.pass = v2; await writeState(state); } catch(e){ /* no bloquea el login */ }
  }

  const role = u.role || 'player';

  // Las cuentas dadas de baja no reciben token. Antes esto SOLO lo chequeaba el
  // navegador, así que un jugador inactivo podía saltearse la app y usar la API.
  if(u.inactive && role === 'player'){
    return res.status(403).json({ error: 'Tu cuenta está inactiva. Contactá al administrador.' });
  }

  const exp  = Date.now() + SESSION_MIN * 60 * 1000;
  const session = { u: user, r: role, exp };

  // Devolvemos el estado ya filtrado acá mismo. Antes el cliente tenía que hacer
  // una segunda llamada a /api/state, que releía los mismos 222 KB de la base:
  // dos viajes y dos arranques en frío para lo mismo.
  res.setHeader('Cache-Control', 'no-store');
  return res.status(200).json({
    token: signToken(session),
    name: user,
    role,
    exp,
    state: filterForSession(state, session)
  });
};
