from dataclasses import dataclass


@dataclass(frozen=True)
class SatRegimen:
    clave: str
    descripcion: str

    def __post_init__(self) -> None:
        if not isinstance(self.clave, str) or not self.clave.strip():
            raise ValueError("clave inválida")
        if not isinstance(self.descripcion, str) or not self.descripcion.strip():
            raise ValueError("descripcion inválida")


@dataclass(frozen=True)
class SatUnidad:
    clave: str
    nombre: str
    simbolo: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.clave, str) or not self.clave.strip():
            raise ValueError("clave inválida")
        if not isinstance(self.nombre, str) or not self.nombre.strip():
            raise ValueError("nombre inválido")
        if self.simbolo is not None and (not isinstance(self.simbolo, str) or not self.simbolo.strip()):
            raise ValueError("simbolo inválido")


@dataclass(frozen=True)
class SatProducto:
    clave: str
    descripcion: str
    palabras_similares: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.clave, str) or not self.clave.strip():
            raise ValueError("clave inválida")
        if not isinstance(self.descripcion, str) or not self.descripcion.strip():
            raise ValueError("descripcion inválida")
        if self.palabras_similares is not None and (
            not isinstance(self.palabras_similares, str) or not self.palabras_similares.strip()
        ):
            raise ValueError("palabras_similares inválidas")


__all__ = ["SatProducto", "SatRegimen", "SatUnidad"]
