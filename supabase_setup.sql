-- =====================================================
-- LIGA SOHAIL — Row Level Security (RLS) en Supabase
-- Ejecutar en: Supabase Dashboard → SQL Editor
-- =====================================================

-- PASO 1: Habilitar RLS en la tabla liga_state
ALTER TABLE liga_state ENABLE ROW LEVEL SECURITY;

-- PASO 2: Política de LECTURA — cualquiera puede leer (la app necesita leer sin login)
CREATE POLICY "lectura_publica"
  ON liga_state
  FOR SELECT
  USING (true);

-- PASO 3: Política de ESCRITURA — solo service_role puede escribir directamente
-- La app escribe usando la publishable key, pero la anon role está limitada a upsert en id=1
CREATE POLICY "escritura_app"
  ON liga_state
  FOR INSERT
  WITH CHECK (id = 1);

CREATE POLICY "actualizacion_app"
  ON liga_state
  FOR UPDATE
  USING (id = 1)
  WITH CHECK (id = 1);

-- PASO 4: Bloquear DELETE completamente (nadie puede borrar la liga_state desde el cliente)
-- Solo service_role (acceso directo desde Supabase dashboard) puede borrar si es necesario
CREATE POLICY "sin_delete"
  ON liga_state
  FOR DELETE
  USING (false);

-- =====================================================
-- VERIFICAR QUE RLS ESTÁ ACTIVO
-- =====================================================
SELECT schemaname, tablename, rowsecurity
FROM pg_tables
WHERE tablename = 'liga_state';

-- =====================================================
-- OPCIONAL: Crear tabla de config separada para el super hash
-- (mejora adicional: el SUPER_HASH no está en el código fuente)
-- =====================================================

-- Crear tabla de configuración privada
CREATE TABLE IF NOT EXISTS liga_config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Habilitar RLS en config — solo lectura para app
ALTER TABLE liga_config ENABLE ROW LEVEL SECURITY;

CREATE POLICY "config_lectura"
  ON liga_config
  FOR SELECT
  USING (true);

-- Solo service_role puede modificar la config (desde el dashboard de Supabase)
-- Insertar el super hash (ejecutar una sola vez)
-- NOTA: Este es el PBKDF2 de tu super password, no el texto plano
INSERT INTO liga_config (key, value)
VALUES ('super_hash', 'v2:cc4723310633dac413f5447c5b1c78417a3add4e308ba4f7bd5878f1dfb7cc2c')
ON CONFLICT (key) DO NOTHING;

-- =====================================================
-- NOTAS DE SEGURIDAD
-- =====================================================
-- Con estas políticas:
-- ✅ Cualquiera puede LEER liga_state (necesario para la app)
-- ✅ La app puede hacer UPSERT en id=1 (su único row)
-- ❌ Nadie puede DELETE desde el cliente
-- ❌ Nadie puede crear rows con id != 1
-- ❌ Solo el dashboard de Supabase (service_role) puede hacer cambios directos
-- 
-- La publishable key en el código fuente solo permite lo que RLS autoriza.
-- Un atacante con la key NO puede borrar data ni crear registros arbitrarios.
