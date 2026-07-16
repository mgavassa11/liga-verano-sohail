// =====================================================================
// LIGA SOHAIL — utilidades internas del servidor
// El prefijo "_" hace que Vercel NO publique este archivo como ruta.
// Es una librería interna: nadie puede llamarlo desde fuera.
// =====================================================================
const crypto = require('crypto');

const SUPA_URL       = process.env.SUPABASE_URL;
const SUPA_SECRET    = process.env.SUPABASE_SERVICE_KEY;   // clave service_role — SOLO servidor
const SESSION_SECRET = process.env.SESSION_SECRET;
const SUPER_HASH     = process.env.SUPER_HASH || '';

// Mismos parámetros que usaba el navegador: las contraseñas existentes siguen valiendo.
const PBKDF2_SALT  = 'LigaSohailSecure2026';
const PBKDF2_ITERS = 100000;
const SESSION_MIN  = 90;

function hashV2(pw){
  if(!pw) return 'v2:';
  return 'v2:' + crypto.pbkdf2Sync(pw, PBKDF2_SALT, PBKDF2_ITERS, 32, 'sha256').toString('hex');
}
function hashV1(pw){
  if(!pw) return 'v1:';
  return 'v1:' + crypto.createHash('sha256').update(pw, 'utf8').digest('hex');
}

// --- Sesiones: token firmado con HMAC. Sin dependencias externas. ---
function signToken(payload){
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig  = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  return body + '.' + sig;
}

function verifyToken(tok){
  if(!tok || typeof tok !== 'string') return null;
  const i = tok.indexOf('.');
  if(i < 1) return null;
  const body = tok.slice(0, i), sig = tok.slice(i + 1);
  const expect = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(expect);
  if(a.length !== b.length) return null;
  if(!crypto.timingSafeEqual(a, b)) return null;
  let p;
  try { p = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')); }
  catch(e){ return null; }
  if(!p || !p.exp || Date.now() > p.exp) return null;
  return p;
}

function auth(req){
  const h = req.headers['authorization'] || '';
  return verifyToken(h.startsWith('Bearer ') ? h.slice(7) : '');
}

// Sesión deslizante: si al token le queda menos de la mitad de vida, se emite
// uno nuevo. Sin esto, un admin trabajando 2 horas seguidas veía cómo los
// guardados empezaban a fallar aunque el cliente creyera la sesión viva.
function renewIfStale(session){
  const total = SESSION_MIN * 60 * 1000;
  if(session.exp - Date.now() > total / 2) return null;   // todavía fresco
  return signToken({ u: session.u, r: session.r, a: session.a, exp: Date.now() + total });
}

// Una cuenta dada de baja pierde el acceso aunque tenga un token vivo.
function blockedUser(state, session){
  const u = (state.users || {})[session.u];
  if(!u) return 'Tu usuario ya no existe en la liga.';
  if(u.inactive && (u.role || 'player') === 'player') return 'Tu cuenta está inactiva. Contactá al administrador.';
  return null;
}

function isAdminRole(r){ return r === 'admin' || r === 'superadmin'; }

// ¿La sesión puede administrar? El rol dice QUÉ es en la liga; el flag 'a' del
// token dice si PUEDE ADMINISTRARLA. Un jugador ascendido es role:'player' + a:true.
// El fallback a isAdminRole mantiene vivos los tokens emitidos antes de este cambio.
function sesionEsAdmin(session, users){
  if(!session) return false;
  // Las cuentas del sistema mandan por rol: eso no cambia nunca.
  if(isAdminRole(session.r)) return true;
  // El flag de un jugador ascendido se lee de la BASE, no del token. Si se leyera
  // del token, quitarle el rol no surtiría efecto hasta que expirara su sesión —
  // y como renewIfStale copia el flag hacia adelante, un jugador activo se
  // quedaba de administrador para siempre.
  if(users && users[session.u]) return users[session.u].isAdmin === true;
  // Sin la base a mano no se asume nada: se niega.
  return false;
}

// Solo la cuenta original 'admin' y el super admin reparten el rol de administrador.
// Un admin ascendido no puede crear más: si le roban la cuenta, no puede dejarse
// una puerta trasera que sobreviva al cambio de contraseña.
function puedeGestionarAdmins(session){
  return !!session && (session.u === 'admin' || session.r === 'superadmin');
}

// Filtra el estado según quién pregunta. MUTA el objeto recibido: no hace falta
// copiarlo porque readState() devuelve uno nuevo en cada request, y clonar 222 KB
// en cada login costaba tiempo y memoria para nada.
function filterForSession(state, session){
  const admin = sesionEsAdmin(session, state && state.users);
  const users = state.users || {};
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
    // El admin sí recibe los hashes: los necesita para el panel de contraseñas.
  }
  return state;
}

// --- Acceso a Supabase con la clave secreta (se salta RLS) ---
// OJO con los headers: las claves NUEVAS (sb_secret_...) no son JWT y Supabase
// las rechaza si viajan en Authorization: Bearer. Las LEGACY (service_role, que
// sí es un JWT) en cambio lo necesitan. Detectamos el formato y mandamos lo justo.
function supaHeaders(extra){
  const h = Object.assign({ apikey: SUPA_SECRET }, extra || {});
  if(!/^sb_(secret|publishable)_/.test(SUPA_SECRET || '')){
    h.Authorization = 'Bearer ' + SUPA_SECRET;   // clave legacy en formato JWT
  }
  return h;
}

async function readState(){
  const r = await fetch(SUPA_URL + '/rest/v1/liga_state?id=eq.1&select=data', {
    headers: supaHeaders()
  });
  if(!r.ok) throw new Error('Supabase read ' + r.status);
  const rows = await r.json();
  if(!Array.isArray(rows) || !rows.length || rows[0].data == null) return null;
  const d = rows[0].data;
  return typeof d === 'string' ? JSON.parse(d) : d;
}

// Se guarda igual que antes: la columna `data` recibe el JSON como texto.
async function writeState(obj){
  const r = await fetch(SUPA_URL + '/rest/v1/liga_state', {
    method: 'POST',
    headers: supaHeaders({
      'Content-Type': 'application/json',
      Prefer: 'resolution=merge-duplicates,return=minimal'
    }),
    body: JSON.stringify({ id: 1, data: JSON.stringify(obj) })
  });
  if(!r.ok) throw new Error('Supabase write ' + r.status + ' ' + (await r.text()));
}

function envOK(res){
  const missing = [];
  if(!SUPA_URL) missing.push('SUPABASE_URL');
  if(!SUPA_SECRET) missing.push('SUPABASE_SERVICE_KEY');
  if(!SESSION_SECRET) missing.push('SESSION_SECRET');
  if(missing.length){
    res.status(500).json({ error: 'Servidor mal configurado. Faltan variables de entorno: ' + missing.join(', ') });
    return false;
  }
  return true;
}

module.exports = {
  hashV1, hashV2, signToken, verifyToken, auth, isAdminRole, sesionEsAdmin, puedeGestionarAdmins, filterForSession, renewIfStale, blockedUser,
  readState, writeState, envOK, SESSION_MIN, SUPER_HASH
};
