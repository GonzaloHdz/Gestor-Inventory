CREATE TABLE IF NOT EXISTS sat_regimenes (
  clave TEXT PRIMARY KEY,
  descripcion TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS sat_regimenes_descripcion_idx
ON sat_regimenes (descripcion);

CREATE TABLE IF NOT EXISTS sat_unidades (
  clave TEXT PRIMARY KEY,
  nombre TEXT NOT NULL,
  simbolo TEXT NULL
);

CREATE INDEX IF NOT EXISTS sat_unidades_nombre_idx
ON sat_unidades (nombre);

CREATE TABLE IF NOT EXISTS sat_productos (
  clave TEXT PRIMARY KEY,
  descripcion TEXT NOT NULL,
  palabras_similares TEXT NULL
);

CREATE INDEX IF NOT EXISTS sat_productos_descripcion_idx
ON sat_productos (descripcion);
