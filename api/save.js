// =====================================================================
// POST /api/save    (Authorization: Bearer <token>)   { state }
// Sin token no se escribe nada. Y lo que un jugador nunca vio,
// tampoco lo puede pisar: se reinyecta desde la base.
// =====================================================================
const { auth, readState, writeState, envOK, sesionEsAdmin, puedeGestionarAdmins, renewIfStale, blockedUser } = require('./_lib');

module.exports = async function handler(req, res){
  if(req.method !== 'POST') return res.status(405).json({ error: 'Método no permitido' });
  if(!envOK(res)) return;

  const session = auth(req);
  if(!session) return res.status(401).json({ error: 'Sesión inválida o expirada. Volvé a entrar.' });

  const incoming = req.body && req.body.state;
  if(!incoming || typeof incoming !== 'object' || !incoming.users || !incoming.cycles){
    return res.status(400).json({ error: 'Estado inválido: no se guarda.' });
  }

  // Techo de tamaño: sin esto, cualquiera con sesión puede inflar la base.
  const bytes = JSON.stringify(incoming).length;
  if(bytes > 8 * 1024 * 1024){
    return res.status(413).json({ error: 'El estado es demasiado grande. No se guardó.' });
  }

  // Los nombres se concatenan dentro de innerHTML en todo el cliente. La función
  // esc() del cliente SOLO escapa apóstrofos (para los onclick), no HTML: por eso
  // se filtra acá, en la puerta, en vez de en 61 sitios distintos.
  // El apóstrofo NO se bloquea: esc() ya lo maneja y apellidos como O'Brien son reales.
  const PELIGRO = /[<>"`\\]/;
  for(const name of Object.keys(incoming.users)){
    if(PELIGRO.test(name)){
      return res.status(400).json({ error: 'El nombre "' + name.slice(0, 40) + '" tiene caracteres no permitidos: < > " ` \\' });
    }
    // email y tel también se dibujan en la pantalla, dentro de value="...".
    // esc() no escapa la comilla doble, así que un email como  " onfocus="...
    // rompía el atributo. Se cierra acá, en la puerta, igual que el nombre.
    const u = incoming.users[name] || {};
    for(const campo of ['email', 'tel']){
      if(u[campo] && PELIGRO.test(String(u[campo]))){
        return res.status(400).json({ error: 'El campo ' + campo + ' de "' + name.slice(0, 40) + '" tiene caracteres no permitidos: < > " ` \\' });
      }
    }
  }

  // Los clubes también se dibujan en pantalla (nombre en badges, color en style=).
  // Mismo filtro que los nombres de jugador, más un chequeo de que el color sea un
  // hex válido: si no, un club podría inyectar CSS o romper el atributo style.
  if(Array.isArray(incoming.CLUBS)){
    // Tope razonable: una liga real tiene un puñado de clubes. Más de 50 es señal
    // de error o abuso, y aunque el tope de 8MB del estado lo contendría, un límite
    // explícito da un error claro en vez de dejar crecer el estado sin sentido.
    if(incoming.CLUBS.length > 50){
      return res.status(400).json({ error: 'Demasiados clubes (máximo 50).' });
    }
    const HEX = /^#[0-9a-fA-F]{6}$/;
    const vistos = new Set();
    for(const c of incoming.CLUBS){
      if(!c || typeof c.name !== 'string' || PELIGRO.test(c.name)){
        return res.status(400).json({ error: 'Un club tiene un nombre inválido o con caracteres no permitidos.' });
      }
      if(c.name.length > 40){
        return res.status(400).json({ error: 'El nombre de un club es demasiado largo (máx. 40 caracteres).' });
      }
      if(typeof c.bg !== 'string' || !HEX.test(c.bg)){
        return res.status(400).json({ error: 'El color de "' + String(c.name).slice(0, 40) + '" no es un hex válido (#rrggbb).' });
      }
      // Nombres únicos (case-insensitive): dos clubes con el mismo nombre romperían
      // clubByName, que resuelve el color por nombre.
      const clave = c.name.trim().toLowerCase();
      if(!clave){
        return res.status(400).json({ error: 'Un club quedó sin nombre.' });
      }
      if(vistos.has(clave)){
        return res.status(400).json({ error: 'Hay dos clubes con el mismo nombre: "' + c.name.slice(0, 40) + '".' });
      }
      vistos.add(clave);
    }
    if(incoming.CLUBS.length < 1){
      return res.status(400).json({ error: 'Tiene que haber al menos un club.' });
    }
  }
  if(incoming.COLOR_DISPUTA !== undefined && !/^#[0-9a-fA-F]{6}$/.test(String(incoming.COLOR_DISPUTA))){
    return res.status(400).json({ error: 'El color de disputa no es un hex válido (#rrggbb).' });
  }

  let current;
  try { current = await readState(); }
  catch(e){ return res.status(503).json({ error: 'No se pudo leer la base de datos; no se guardó nada.' }); }

  // Nunca sobrescribimos una base que no pudimos leer: misma protección que ya
  // tenía el cliente contra el incidente de "liga vacía".
  if(!current) return res.status(409).json({ error: 'La base respondió vacía; no se sobrescribe.' });

  const blocked = blockedUser(current, session);
  if(blocked) return res.status(403).json({ error: blocked });

  // BLOQUEO OPTIMISTA. Todo el estado es un único bloque y cada guardado lo
  // reescribe entero: si dos personas tienen la app abierta, la segunda en
  // guardar pisaba el resultado de la primera y NADIE se enteraba.
  // Ahora, si la versión no coincide, se rechaza y el cliente recarga.
  const curV = current._v || 0;
  const inV  = incoming._v || 0;
  if(inV !== curV){
    return res.status(409).json({
      error: 'Otra persona guardó un cambio mientras cargabas el tuyo. Recargá la página y volvé a cargarlo.',
      conflict: true
    });
  }
  incoming._v = curV + 1;

  const curUsers = current.users || {};
  const admin    = sesionEsAdmin(session, curUsers);

  // =====================================================================
  // EL SUPER ADMINISTRADOR ES ÚNICO E INTRANSFERIBLE
  // Esto va FUERA del if(!admin) a propósito: aplica también a los admins.
  // Sin esto un admin podía (a) darse el rol a sí mismo, (b) borrar al super
  // y crear otro, o (c) pisarle el hash y entrar como él. Las tres vías
  // esquivaban la validación, porque toda vivía dentro de if(!admin).
  // =====================================================================
  const supers = o => Object.keys(o || {})
    .filter(n => o[n] && o[n].role === 'superadmin')
    .sort().join('|');

  const superAntes = supers(curUsers), superAhora = supers(incoming.users);
  if(superAntes !== superAhora){
    // Única excepción: una base vieja que no tiene superadmin y el cliente crea
    // el primero (la migración de _hydrate). Solo con la clave canónica: así un
    // admin no puede aprovechar el hueco para coronarse a sí mismo.
    const esMigracion = superAntes === '' && superAhora === 'superadmin';
    if(!esMigracion){
      return res.status(403).json({
        error: 'El super administrador es único: no se puede crear, duplicar, transferir ni eliminar.'
      });
    }
  }

  // =====================================================================
  // LAS CONTRASEÑAS NUNCA VIAJAN EN /api/save
  // Se cambian ÚNICAMENTE por /api/password. Acá el hash de cualquier usuario
  // que ya exista se reinyecta desde la base, para TODOS los roles.
  //
  // Sin esto: el navegador del admin conserva el hash viejo en memoria
  // (changePw no actualiza USERS local), y el autosave de 12 segundos pisaba
  // la contraseña recién cambiada. A los jugadores no les pasaba porque su
  // reinyección ya existía; al admin sí, porque la suya vivía dentro de
  // if(!admin) y él nunca entraba ahí.
  //
  // Un usuario NUEVO no está en la base todavía: se respeta el hash que manda
  // el cliente, que es la clave por defecto de alta.
  // =====================================================================
  for(const n of Object.keys(incoming.users)){
    const cu = curUsers[n];
    if(cu && incoming.users[n]) incoming.users[n].pass = cu.pass;
  }

  // Los roles válidos son solo estos tres. Y 'superadmin' ya está blindado arriba,
  // así que un admin solo puede mover gente entre 'player' y 'admin'.
  for(const n of Object.keys(incoming.users)){
    const r = incoming.users[n] && incoming.users[n].role;
    if(r !== 'player' && r !== 'admin' && r !== 'superadmin'){
      return res.status(400).json({ error: 'Rol inválido para "' + n.slice(0, 40) + '".' });
    }
  }

  // El rol de administrador solo lo reparte la cuenta original o el super admin.
  // Sin esto, un admin ascendido podía crear más admins: si le roban la cuenta,
  // se deja una puerta trasera que sobrevive al cambio de contraseña.
  const flags = o => Object.keys(o || {}).filter(n => o[n] && o[n].isAdmin === true).sort().join('|');
  if(flags(curUsers) !== flags(incoming.users) && !puedeGestionarAdmins(session)){
    // Borrar a un jugador que además es admin también cambia la lista de flags.
    // Se distingue el caso: el bloqueo es correcto, pero el mensaje tiene que
    // decir la verdad en vez de hablar de repartir roles que nadie repartió.
    const borrados = Object.keys(curUsers).filter(n => curUsers[n] && curUsers[n].isAdmin === true && !incoming.users[n]);
    if(borrados.length){
      return res.status(403).json({ error: 'No podés eliminar a ' + borrados[0].slice(0, 40) + ': tiene rol de administrador. Quitáselo primero, o pedíselo al administrador original.' });
    }
    return res.status(403).json({ error: 'Solo el administrador original y el super admin pueden repartir el rol de administrador.' });
  }

  // Siempre tiene que quedar al menos un admin: si no, nadie puede volver a
  // administrar la liga salvo el super admin.
  // Cuenta admins EFECTIVOS: la cuenta del sistema y los jugadores ascendidos.
  // Antes solo miraba role==='admin', así que con 5 ascendidos igual creía que
  // la liga se quedaba sin nadie.
  const cuentaAdmins = o => Object.keys(o || {}).filter(n => o[n] && (o[n].role === 'admin' || o[n].isAdmin === true)).length;
  if(cuentaAdmins(curUsers) > 0 && cuentaAdmins(incoming.users) === 0){
    return res.status(403).json({ error: 'Tiene que quedar al menos un administrador.' });
  }

  // NOTA DE DISEÑO: acá vivía el bloqueo que impedía a un admin-jugador validar
  // sus propios partidos. Se quitó a pedido del dueño de la liga: el control pasó
  // de la PROHIBICIÓN a la TRANSPARENCIA. Todo partido confirmado guarda vBy con
  // el nombre de quien lo validó, visible para cualquiera en el modal, y el
  // historial registra la acción con autor y rol. En una liga de conocidos, que
  // un admin que juega tenga que esperar a otro admin trababa más de lo que
  // protegía. La contención real es a quién se asciende, y queda auditado.

  // La configuración de la liga (puntos, ciclos, playoff, fechas, nombre) la toca
  // SOLO el administrador original o el super admin. El panel ya lo gatea en pantalla,
  // pero eso es un botón escondido, no un permiso: un jugador ascendido podía
  // reescribir por curl la tabla de PUNTOS y darle 35 puntos a su propio grupo.
  // La configuración se parte en dos, porque el riesgo es muy distinto.
  //
  // Lo ESTRUCTURAL (puntos, grupos, ciclos, playoff, fechas) sigue siendo del
  // administrador original y del super admin. Un jugador ascendido que pudiera
  // tocar PUNTOS se pondría 35 puntos en su propio grupo y se iría a la punta de
  // la general: es escalada de privilegios disfrazada de configuración.
  //
  // Lo COSMÉTICO (colores, nombre, subtítulo) lo puede tocar cualquier admin.
  // Lo peor que puede pasar es que la liga quede fea, y se deshace en un click.
  if(!admin){
    const COSMETICO = ['LEAGUE_NAME','LEAGUE_SUBTITLE','LEAGUE_COLOR_PRI',
                       'LEAGUE_COLOR_ACC','LEAGUE_COLOR_HL','CLUBS','COLOR_DISPUTA'];
    for(const k of COSMETICO){
      if(JSON.stringify(incoming[k]) !== JSON.stringify(current[k])){
        return res.status(403).json({ error: 'Solo un administrador puede cambiar la apariencia de la liga.' });
      }
    }
  }

  if(!puedeGestionarAdmins(session)){
    const CONFIG = ['cycles','activeN','playoff','DESTINO','FECHAS','PO_FECHAS',
                    'ALLNAMES','PUNTOS'];
    for(const k of CONFIG){
      if(JSON.stringify(incoming[k]) !== JSON.stringify(current[k])){
        return res.status(403).json({ error: 'La configuración estructural (puntos, grupos, ciclos, playoff) solo la cambia el administrador original o el super admin.' });
      }
    }
  }

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
      inU.role = curU.role;                       // nadie se auto-asciende (el pass ya se reinyectó arriba, para todos)
      if('email' in curU) inU.email = curU.email; else delete inU.email;
      if('tel'   in curU) inU.tel   = curU.tel;   else delete inU.tel;
    }

    // La configuración de la liga se reinyecta desde la base. Un jugador no tiene
    // ningún motivo legítimo para tocarla, y sin esto podía reescribir la tabla
    // de puntos, los grupos o el cuadro de playoffs con un solo curl.
    const CONGELADO = ['cycles','activeN','playoff','DESTINO','FECHAS','PO_FECHAS',
                       'ALLNAMES','PUNTOS','LEAGUE_NAME','LEAGUE_SUBTITLE',
                       'LEAGUE_COLOR_PRI','LEAGUE_COLOR_ACC','LEAGUE_COLOR_HL'];
    for(const k of CONGELADO){
      if(k in current) incoming[k] = current[k]; else delete incoming[k];
    }

    // Los partidos: solo los propios. Antes un jugador podía borrar el que perdió,
    // invertir un resultado, inventarse victorias o vaciar la liga entera.
    const soyYo = m => !!m && (m.aName === session.u || m.bName === session.u);
    const curM  = new Map((current.matches  || []).map(m => [m.id, m]));
    const inM   = new Map((incoming.matches || []).map(m => [m.id, m]));

    // Borrados: solo los propios, y solo si todavía no están confirmados.
    for(const [id, m] of curM){
      if(inM.has(id)) continue;
      if(!soyYo(m)) return res.status(403).json({ error: 'No podés borrar partidos de otros jugadores.' });
      if(m.status === 'confirmed'){
        return res.status(403).json({ error: 'No podés borrar un resultado ya confirmado. Pedíselo al administrador.' });
      }
    }
    // Altas y modificaciones.
    for(const [id, m] of inM){
      const antes = curM.get(id);
      if(!antes){
        if(!soyYo(m)) return res.status(403).json({ error: 'No podés cargar partidos de otros jugadores.' });
        if(m.status === 'confirmed') return res.status(403).json({ error: 'Solo el administrador confirma resultados.' });
        continue;
      }
      if(JSON.stringify(antes) === JSON.stringify(m)) continue;   // sin cambios
      if(!soyYo(antes) || !soyYo(m)){
        return res.status(403).json({ error: 'No podés modificar partidos de otros jugadores.' });
      }
      if(antes.status === 'confirmed'){
        // Lo ÚNICO que un jugador puede hacerle a un confirmado propio es disputarlo.
        // Sin esto podía invertir su derrota y ponerse ganador.
        const soloDisputa = m.status === 'disputed' &&
          JSON.stringify(Object.assign({}, antes, { status: 0 })) ===
          JSON.stringify(Object.assign({}, m,    { status: 0 }));
        if(!soloDisputa){
          return res.status(403).json({ error: 'Un resultado confirmado solo lo cambia el administrador. Podés disputarlo.' });
        }
      }else if(m.status === 'confirmed'){
        return res.status(403).json({ error: 'Solo el administrador confirma resultados.' });
      }
    }
  }

  try { await writeState(incoming); }
  catch(e){ return res.status(503).json({ error: 'No se pudo guardar: ' + e.message }); }

  return res.status(200).json({ ok: true, token: renewIfStale(session) || undefined });
};
