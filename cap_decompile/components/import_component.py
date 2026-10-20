# components/import_component.py

from dataclasses import dataclass
from typing import List
from .base import CAPComponent
from .binary_reader import BinaryReader
from .header import CAPVersion

'''
import_component {
    u1 tag = 4
    u2 size // размер без tag и size
    u1 count
    package_info packages[count]
}
'''

@dataclass
class PackageInfo:
    minor_version: int
    major_version: int
    aid: bytes


@dataclass
class ImportComponent(CAPComponent):
    COMPONENT_TAG = 4

    count: int
    packages: List[PackageInfo]

    @classmethod
    def parse_from_bytes(cls, data: bytes, cap_version: CAPVersion):
        reader = BinaryReader(data)

        tag = reader.read_u1()
        if tag != cls.COMPONENT_TAG:
            raise ValueError(f"Invalid Import tag: {tag}")

        size = reader.read_u2()
        start_remaining = reader.remaining()

        count = reader.read_u1()
        if not (0 <= count <= 128):
            raise ValueError(f"Invalid import count: {count}")

        #todo other cap_version
        if cap_version in (CAPVersion.V22, CAPVersion.V21):
            packages = []
            for _ in range(count):
                minor_version = reader.read_u1()
                major_version = reader.read_u1()
                aid_length = reader.read_u1()
                aid = reader.read_bytes(aid_length)

                packages.append(
                    PackageInfo(
                        minor_version=minor_version,
                        major_version=major_version,
                        aid=aid
                    )
                )
            # Проверка размера
            bytes_read = start_remaining - reader.remaining()
            if bytes_read != size:
                raise ValueError(
                    f"Import component size mismatch: expected {size}, got {bytes_read}"
                )
        else:
            raise ValueError("CAP not 2.2")

        if reader.remaining() != 0:
            raise ValueError("Import parsing incomplete")

        if (start_remaining - reader.remaining()) != size:
            raise ValueError("Import component size mismatch")

        return cls(
            tag=tag,
            size=size,
            count=count,
            packages=packages
        )