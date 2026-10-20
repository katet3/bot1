# cap_parser/container/cap_container.py

from pathlib import Path
from typing import Dict
from .zip_reader import ZipReader


REQUIRED_COMPONENTS = {
    "Header.cap",
    "Directory.cap",
    "Import.cap",
    "ConstantPool.cap",
    "Class.cap",
    "Method.cap",
    "StaticField.cap",
    "RefLocation.cap",
    "Descriptor.cap",
}


class CAPContainer:
    def __init__(self, path: Path):
        self.path = path
        self.reader = ZipReader(path)
        self.components: Dict[str, bytes] = {}

    def load(self) -> None:
        all_files = self.reader.read_all()

        for full_path, data in all_files.items():
            if "/javacard/" in full_path and full_path.endswith(".cap"):
                short_name = full_path.split("/")[-1]
                self.components[short_name] = data

        self._validate()

    def _validate(self) -> None:
        missing = REQUIRED_COMPONENTS - set(self.components.keys())
        if missing:
            raise ValueError(f"Missing CAP components: {missing}")

    def get_component(self, name: str) -> bytes:
        return self.components[name]

    def list_components(self) -> list[str]:
        return list(self.components.keys())
    
    def print_component(self, name: str, bytes_per_line: int = 16) -> None:
        data = self.get_component(name)

        print(f"{self.path.stem}/javacard/{name} :")

        # Вывод hex-байтов
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i:i + bytes_per_line]
            hex_line = " ".join(f"{b:02x}" for b in chunk)
            print(f" {hex_line}")


    def print_components(self, bytes_per_line: int = 16) -> None:
        for name in REQUIRED_COMPONENTS:
            if name in self.components:
                self.print_component(name, bytes_per_line)