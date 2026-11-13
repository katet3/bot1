# cap_parser/container/cap_container.py

from pathlib import Path
from typing import Dict
from .zip_reader import ZipLimits, ZipReader


# Applet.cap is optional for library packages. Header/Directory consistency
# belongs to CAPFile.validate(), after these binary components are parsed.
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
    def __init__(self, path: Path, *, limits: ZipLimits | None = None):
        self.path = Path(path)
        self.reader = ZipReader(self.path, limits=limits)
        self.components: Dict[str, bytes] = {}
        self.component_directory: str | None = None

    def load(self) -> None:
        selected = self.reader.read_selected(self._select_components)
        components = {name.rsplit('/', 1)[1]: data for name, data in selected.items()}
        directory = next(iter(selected)).rsplit('/', 1)[0]
        # Publish only a complete successful read. A reload replaces the previous
        # package; failure preserves its last successful snapshot unchanged.
        self.components = components
        self.component_directory = directory

    def _select_components(self, names: tuple[str, ...]) -> list[str]:
        packages: dict[str, list[str]] = {}
        for name in names:
            parts = name.split('/')
            if not name.endswith('.cap') or 'javacard' not in parts[:-1]:
                continue
            if parts[-2] != 'javacard':
                raise ValueError(f'CAP component must be directly inside javacard/: {name!r}')
            directory = '/'.join(parts[:-1])
            packages.setdefault(directory, []).append(name)
        if len(packages) > 1:
            raise ValueError('Multiple CAP component directories are unsupported: ' +
                             ', '.join(sorted(packages)))
        selected = next(iter(packages.values()), [])
        self._validate({name.rsplit('/', 1)[1] for name in selected})
        return selected

    def _validate(self, names=None) -> None:
        missing = REQUIRED_COMPONENTS - set(self.components if names is None else names)
        if missing:
            raise ValueError('Missing CAP components: ' + ', '.join(sorted(missing)))

    def get_component(self, name: str) -> bytes:
        return self.components[name]

    def get_optional_component(self, name: str) -> bytes | None:
        """Return None only for an absent entry; present empty data stays bytes."""
        return self.components.get(name)

    def list_components(self) -> list[str]:
        return list(self.components.keys())
    
    def print_component(self, name: str, bytes_per_line: int = 16) -> None:
        data = self.get_component(name)

        print(f"{self.component_directory}/{name} :")

        # Вывод hex-байтов
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i:i + bytes_per_line]
            hex_line = " ".join(f"{b:02x}" for b in chunk)
            print(f" {hex_line}")


    def print_components(self, bytes_per_line: int = 16) -> None:
        for name in REQUIRED_COMPONENTS:
            if name in self.components:
                self.print_component(name, bytes_per_line)
