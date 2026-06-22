import sqlite3

from gestor_inventory.domain.sat import SatProducto, SatRegimen, SatUnidad
from gestor_inventory.infrastructure.sqlite_user_repository import SqliteUserRepository


SAT_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS sat_regimenes (
  clave TEXT PRIMARY KEY,
  descripcion TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS sat_regimenes_descripcion_idx ON sat_regimenes (descripcion);

CREATE TABLE IF NOT EXISTS sat_unidades (
  clave TEXT PRIMARY KEY,
  nombre TEXT NOT NULL,
  simbolo TEXT NULL
);
CREATE INDEX IF NOT EXISTS sat_unidades_nombre_idx ON sat_unidades (nombre);

CREATE TABLE IF NOT EXISTS sat_productos (
  clave TEXT PRIMARY KEY,
  descripcion TEXT NOT NULL,
  palabras_similares TEXT NULL
);
CREATE INDEX IF NOT EXISTS sat_productos_descripcion_idx ON sat_productos (descripcion);
"""


class SqliteSatRepository(SqliteUserRepository):
    def __init__(self, db_path: str):
        super().__init__(db_path=db_path)
        self._ensure_sat_schema()

    def count_sat_regimenes(self, *, search: str | None) -> int:
        return self._count_catalog(
            table="sat_regimenes",
            search=search,
            searchable_columns=("clave", "descripcion"),
        )

    def list_sat_regimenes(self, *, search: str | None, limit: int, offset: int) -> list[SatRegimen]:
        rows = self._list_catalog(
            table="sat_regimenes",
            select_columns="clave, descripcion",
            order_by="clave",
            search=search,
            searchable_columns=("clave", "descripcion"),
            limit=limit,
            offset=offset,
        )
        return [SatRegimen(clave=str(clave), descripcion=str(descripcion)) for (clave, descripcion) in rows]

    def count_sat_unidades(self, *, search: str | None) -> int:
        return self._count_catalog(
            table="sat_unidades",
            search=search,
            searchable_columns=("clave", "nombre"),
        )

    def list_sat_unidades(self, *, search: str | None, limit: int, offset: int) -> list[SatUnidad]:
        rows = self._list_catalog(
            table="sat_unidades",
            select_columns="clave, nombre, simbolo",
            order_by="clave",
            search=search,
            searchable_columns=("clave", "nombre"),
            limit=limit,
            offset=offset,
        )
        return [
            SatUnidad(
                clave=str(clave),
                nombre=str(nombre),
                simbolo=str(simbolo) if simbolo is not None else None,
            )
            for (clave, nombre, simbolo) in rows
        ]

    def count_sat_productos(self, *, search: str | None) -> int:
        return self._count_catalog(
            table="sat_productos",
            search=search,
            searchable_columns=("clave", "descripcion", "palabras_similares"),
        )

    def list_sat_productos(self, *, search: str | None, limit: int, offset: int) -> list[SatProducto]:
        rows = self._list_catalog(
            table="sat_productos",
            select_columns="clave, descripcion, palabras_similares",
            order_by="clave",
            search=search,
            searchable_columns=("clave", "descripcion", "palabras_similares"),
            limit=limit,
            offset=offset,
        )
        return [
            SatProducto(
                clave=str(clave),
                descripcion=str(descripcion),
                palabras_similares=str(palabras_similares) if palabras_similares is not None else None,
            )
            for (clave, descripcion, palabras_similares) in rows
        ]

    def _ensure_sat_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(SAT_SCHEMA_SQL)
            conn.commit()

    def _count_catalog(self, *, table: str, search: str | None, searchable_columns: tuple[str, ...]) -> int:
        with self._connect() as conn:
            sql = f"SELECT COUNT(1) FROM {table} WHERE 1 = 1"
            params: list[object] = []
            sql, params = self._append_search(sql=sql, params=params, search=search, searchable_columns=searchable_columns)
            row = conn.execute(sql, params).fetchone()
            return 0 if row is None else int(row[0])

    def _list_catalog(
        self,
        *,
        table: str,
        select_columns: str,
        order_by: str,
        search: str | None,
        searchable_columns: tuple[str, ...],
        limit: int,
        offset: int,
    ) -> list[tuple]:
        with self._connect() as conn:
            sql = f"SELECT {select_columns} FROM {table} WHERE 1 = 1"
            params: list[object] = []
            sql, params = self._append_search(sql=sql, params=params, search=search, searchable_columns=searchable_columns)
            sql += f" ORDER BY {order_by} LIMIT ? OFFSET ?"
            params.extend([int(limit), int(offset)])
            rows = conn.execute(sql, params).fetchall()
            return [tuple(row) for row in rows]

    def _append_search(
        self,
        *,
        sql: str,
        params: list[object],
        search: str | None,
        searchable_columns: tuple[str, ...],
    ) -> tuple[str, list[object]]:
        search_value = self._normalize_catalog_search(search)
        if search_value is None:
            return sql, params
        like = f"%{search_value}%"
        clauses = [f"lower(coalesce({column}, '')) LIKE ?" for column in searchable_columns]
        sql += " AND (" + " OR ".join(clauses) + ")"
        params.extend([like] * len(searchable_columns))
        return sql, params

    def _normalize_catalog_search(self, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = str(value).strip().lower()
        return normalized or None


__all__ = ["SAT_SCHEMA_SQL", "SqliteSatRepository"]
