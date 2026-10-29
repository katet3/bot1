# components/header.py

from enum import Enum
from dataclasses import dataclass
from .binary_reader import BinaryReader
from .base import CAPComponent


'''
CAP 2.1 → { JC 2.1.0, JC 2.1.1 }
CAP 2.2 → { JC 2.2.2, JC 3.0.1, JC 3.0.4, JC 3.0.5 }
CAP 2.3 → { JC 3.1.0, JC 3.2.0 }
'''


class CAPVersion(Enum):
    V21 = (2, 1)
    V22 = (2, 2)
    V23 = (2, 3)

    @property
    def major(self):
        return self.value[0]

    @property
    def minor(self):
        return self.value[1]

    @classmethod
    def from_numbers(cls, major: int, minor: int):
        for v in cls:
            if v.value == (major, minor):
                return v
        raise ValueError(f"Unsupported CAP version {major}.{minor}")


CAP_TO_PLATFORM = {
    CAPVersion.V21: {
        "JavaCard 2.1.0",
        "JavaCard 2.1.1",
    },
    CAPVersion.V22: {
        "JavaCard 2.2.2",
        "JavaCard 3.0.1",
        "JavaCard 3.0.4",
        "JavaCard 3.0.5",
    },
    CAPVersion.V23: {
        "JavaCard 3.1.0",
        "JavaCard 3.2.0",
    },
}


@dataclass
class PackageInfo:
    minor_version: int
    major_version: int
    aid: bytes


@dataclass
class HeaderComponent(CAPComponent):
    COMPONENT_TAG = 1

    magic: int
    minor_version: int
    major_version: int
    flags: int
    package: PackageInfo

    cap_version: CAPVersion
    # package_name_info is present starting with CAP 2.2 (JVMS 6.4).
    # None denotes CAP 2.1; b"" denotes an explicitly empty name in CAP 2.2+.
    package_name: bytes | None = None

    @classmethod
    def parse_from_bytes(cls, data: bytes):
        if len(data) < 13:
            raise ValueError("Truncated Header component")
        reader = BinaryReader(data)

        tag = reader.read_u1()
        if tag != cls.COMPONENT_TAG:
            raise ValueError(f"Invalid Header tag: {tag}")
        
        size = reader.read_u2()
        if size != len(data) - 3:
            raise ValueError("Header component size mismatch")
        start_remaining = reader.remaining()
        
        magic = reader.read_u4()
        if magic != 0xDECAFFED:
            raise ValueError(f"Invalid CAP magic: {magic}")

        minor_version = reader.read_u1()
        major_version = reader.read_u1()
        if major_version != 2:
            raise ValueError(f"Unsupported CAP major version {major_version}")

        cap_version = CAPVersion.from_numbers(major_version, minor_version)

        flags = reader.read_u1()

        pkg_minor = reader.read_u1()
        pkg_major = reader.read_u1()

        aid_length = reader.read_u1()
        if not 5 <= aid_length <= 16 or reader.remaining() < aid_length:
            raise ValueError("Invalid or truncated package AID in Header")
        aid = reader.read_bytes(aid_length)

        package = PackageInfo(
            aid=aid,
            minor_version=pkg_minor,
            major_version=pkg_major
        )

        package_name = None
        if cap_version != CAPVersion.V21:
            if reader.remaining() < 1:
                raise ValueError("Missing package_name_info in CAP 2.2+ Header")
            name_length = reader.read_u1()
            if reader.remaining() < name_length:
                raise ValueError("Truncated package name in Header")
            package_name = reader.read_bytes(name_length)

        if reader.remaining() != 0:
            raise ValueError("Header parsing incomplete")
        
        if (start_remaining - reader.remaining()) != size:
            raise ValueError("Header component size mismatch")

        return cls(
            tag=tag,
            size=size,
            magic=magic,
            minor_version=minor_version,
            major_version=major_version,
            flags=flags,
            package=package,
            cap_version=cap_version,
            package_name=package_name,
        )
