import argparse
import os
import posixpath
import sqlite3
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[4]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from gestor_inventory.infrastructure.sqlite_sat_repository import SAT_SCHEMA_SQL


XLSX_MAIN_FILE = "catCFDI_v4.xlsx"
XLSX_PRODUCTOS_FILE = "catCFDI_productos.xlsx"
REGIMENES_SHEET = "c_RegimenFiscal"
UNIDADES_SHEET = "c_ClaveUnidad"
PRODUCTOS_SHEET = "c_ClaveProdServ"

XML_NS = {
    "a": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "pr": "http://schemas.openxmlformats.org/package/2006/relationships",
}


def main() -> None:
    args = _parse_args()
    db_path = args.db_path or os.environ.get("GI_SQLITE_PATH") or str(ROOT / "gestor_inventory.sqlite3")
    data_dir = Path(args.data_dir) if args.data_dir else ROOT / "data"

    started_at = time.perf_counter()
    with sqlite3.connect(db_path) as conn:
        conn.executescript(SAT_SCHEMA_SQL)

        regimenes = _read_regimenes(data_dir / XLSX_MAIN_FILE)
        unidades = _read_unidades(data_dir / XLSX_MAIN_FILE)
        productos = _read_productos(data_dir / XLSX_PRODUCTOS_FILE)

        conn.executemany(
            "INSERT OR IGNORE INTO sat_regimenes (clave, descripcion) VALUES (?, ?)",
            regimenes,
        )
        conn.executemany(
            "INSERT OR IGNORE INTO sat_unidades (clave, nombre, simbolo) VALUES (?, ?, ?)",
            unidades,
        )
        conn.executemany(
            "INSERT OR IGNORE INTO sat_productos (clave, descripcion, palabras_similares) VALUES (?, ?, ?)",
            productos,
        )
        conn.commit()

    elapsed = time.perf_counter() - started_at
    print(
        "Carga SAT completada: "
        f"regimenes={len(regimenes)}, "
        f"unidades={len(unidades)}, "
        f"productos={len(productos)}, "
        f"db='{db_path}', "
        f"segundos={elapsed:.3f}"
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Carga catalogos SAT en SQLite desde archivos XLSX")
    parser.add_argument("--db-path", dest="db_path", help="Ruta del archivo SQLite destino")
    parser.add_argument("--data-dir", dest="data_dir", help="Directorio donde viven los archivos XLSX del SAT")
    return parser.parse_args()


def _read_regimenes(path: Path) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for row in _iter_sheet_rows(path, REGIMENES_SHEET):
        clave = _get_value(row, "c_RegimenFiscal")
        descripcion = _get_value(row, "Descripcion")
        if clave is None or descripcion is None:
            continue
        rows.append((clave, descripcion))
    return rows


def _read_unidades(path: Path) -> list[tuple[str, str, str | None]]:
    rows: list[tuple[str, str, str | None]] = []
    for row in _iter_sheet_rows(path, UNIDADES_SHEET):
        clave = _get_value(row, "c_ClaveUnidad")
        nombre = _get_value(row, "Nombre")
        simbolo = _get_value(row, "Simbolo")
        if clave is None or nombre is None:
            continue
        rows.append((clave, nombre, simbolo))
    return rows


def _read_productos(path: Path) -> list[tuple[str, str, str | None]]:
    rows: list[tuple[str, str, str | None]] = []
    for row in _iter_sheet_rows(path, PRODUCTOS_SHEET):
        clave = _get_value(row, "c_ClaveProdServ", "c_claveprodserv")
        descripcion = _get_value(row, "Descripcion", "descripcion")
        palabras_similares = _get_value(row, "PalabrasSimilares", "palabrasimilares")
        if clave is None or descripcion is None:
            continue
        rows.append((clave, descripcion, palabras_similares))
    return rows


def _iter_sheet_rows(path: Path, sheet_name: str) -> list[dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(f"No se encontro el archivo requerido: {path}")
    with ZipFile(path) as workbook:
        shared_strings = _read_shared_strings(workbook)
        sheet_target = _resolve_sheet_target(workbook, sheet_name)
        sheet_xml = ET.fromstring(workbook.read(sheet_target))
        rows = _extract_sheet_rows(sheet_xml, shared_strings)
        if not rows:
            return []

    headers = [_clean_cell(value) or "" for value in rows[0]]
    data_rows: list[dict[str, str]] = []
    for row in rows[1:]:
        if not any(_clean_cell(value) for value in row):
            continue
        item: dict[str, str] = {}
        for index, header in enumerate(headers):
            if not header:
                continue
            value = row[index] if index < len(row) else ""
            item[header] = _clean_cell(value) or ""
        data_rows.append(item)
    return data_rows


def _read_shared_strings(workbook: ZipFile) -> list[str]:
    if "xl/sharedStrings.xml" not in workbook.namelist():
        return []
    shared_xml = ET.fromstring(workbook.read("xl/sharedStrings.xml"))
    values: list[str] = []
    for item in shared_xml.findall("a:si", XML_NS):
        text_parts = [node.text or "" for node in item.iterfind(".//a:t", XML_NS)]
        values.append("".join(text_parts))
    return values


def _resolve_sheet_target(workbook: ZipFile, sheet_name: str) -> str:
    workbook_xml = ET.fromstring(workbook.read("xl/workbook.xml"))
    rels_xml = ET.fromstring(workbook.read("xl/_rels/workbook.xml.rels"))
    rel_targets = {
        rel.attrib["Id"]: rel.attrib["Target"]
        for rel in rels_xml.findall("pr:Relationship", XML_NS)
    }
    sheets = workbook_xml.find("a:sheets", XML_NS)
    if sheets is None:
        raise ValueError("El archivo XLSX no contiene hojas")
    for sheet in sheets.findall("a:sheet", XML_NS):
        if sheet.attrib.get("name") != sheet_name:
            continue
        rel_id = sheet.attrib.get("{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id")
        if rel_id is None or rel_id not in rel_targets:
            break
        return "xl/" + posixpath.normpath(rel_targets[rel_id]).lstrip("/")
    raise ValueError(f"No se encontro la hoja requerida: {sheet_name}")


def _extract_sheet_rows(sheet_xml: ET.Element, shared_strings: list[str]) -> list[list[str]]:
    rows: list[list[str]] = []
    for row in sheet_xml.findall(".//a:sheetData/a:row", XML_NS):
        values_by_index: dict[int, str] = {}
        max_index = -1
        for cell in row.findall("a:c", XML_NS):
            cell_ref = cell.attrib.get("r", "")
            column_letters = "".join(char for char in cell_ref if char.isalpha())
            column_index = _column_to_index(column_letters)
            values_by_index[column_index] = _read_cell_value(cell, shared_strings)
            if column_index > max_index:
                max_index = column_index
        if max_index < 0:
            continue
        rows.append([values_by_index.get(index, "") for index in range(max_index + 1)])
    return rows


def _read_cell_value(cell: ET.Element, shared_strings: list[str]) -> str:
    cell_type = cell.attrib.get("t")
    if cell_type == "inlineStr":
        return "".join(node.text or "" for node in cell.iterfind(".//a:t", XML_NS))
    value_node = cell.find("a:v", XML_NS)
    if value_node is None or value_node.text is None:
        return ""
    raw_value = value_node.text
    if cell_type == "s":
        index = int(raw_value)
        return shared_strings[index] if 0 <= index < len(shared_strings) else ""
    return raw_value


def _column_to_index(column_name: str) -> int:
    index = 0
    for char in column_name:
        index = (index * 26) + (ord(char.upper()) - 64)
    return index - 1


def _clean_cell(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned or None


def _get_value(row: dict[str, str], *candidates: str) -> str | None:
    normalized = {_normalize_header(key): value for key, value in row.items()}
    for candidate in candidates:
        value = normalized.get(_normalize_header(candidate))
        if value is not None:
            value = value.strip()
            return value or None
    return None


def _normalize_header(value: str) -> str:
    return str(value).strip().lower()


if __name__ == "__main__":
    main()
