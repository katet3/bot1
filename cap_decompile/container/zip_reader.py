# cap_parser/container/zip_reader.py

import zipfile
from pathlib import Path


class ZipReader:
    def __init__(self, path: Path):
        self.path = path

    def list_files(self) -> list[str]:
        with zipfile.ZipFile(self.path, 'r') as zf:
            return zf.namelist()

    def read_file(self, name: str) -> bytes:
        with zipfile.ZipFile(self.path, 'r') as zf:
            return zf.read(name)

    def read_all(self) -> dict[str, bytes]:
        result = {}
        with zipfile.ZipFile(self.path, 'r') as zf:
            for name in zf.namelist():
                result[name] = zf.read(name)
        return result