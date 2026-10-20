# components/applet.py

from dataclasses import dataclass
from typing import List
from .base import CAPComponent
from .binary_reader import BinaryReader
from .header import CAPVersion

'''
struct Applet.cap
u1 tag                // = 3
u2 size               // размер без tag и size
u1 count              // > 0

applets[]
{
    u1 AID_length     // 5..16
    u1 AID[AID_length]
    u2 install_method_offset
}
'''


@dataclass
class AppletInfo:
    aid: bytes
    install_method_offset: int

@dataclass
class AppletComponent(CAPComponent):
    COMPONENT_TAG = 3

    tag: int
    size: int
    count: int
    applets: List[AppletInfo]

    @classmethod
    def parse_from_bytes(cls, data: bytes, cap_version: CAPVersion):
        reader = BinaryReader(data)

        tag = reader.read_u1()
        if tag != cls.COMPONENT_TAG:
            raise ValueError(f"Invalid Directory tag. Tag is {tag}")

        size = reader.read_u2()
        start_remaining = reader.remaining()

        count = reader.read_u1()
        if count == 0:
            raise ValueError("Applet component present but count == 0")

        #todo other cap_version
        if cap_version in (CAPVersion.V22, CAPVersion.V21):
            applets = []
            for _ in range(count):
                aid_length = reader.read_u1()
                if not (5 <= aid_length <= 16):
                    raise ValueError(f"Invalid AID length: {aid_length}")

                aid = reader.read_bytes(aid_length)
                install_method_offset = reader.read_u2()

                applets.append(AppletInfo(aid, install_method_offset))
        else:
            raise ValueError("CAP not 2.2")

        if reader.remaining() != 0:
            raise ValueError("Applet parsing incomplete")
        
        if (start_remaining - reader.remaining()) != size:
            raise ValueError("Applet component size mismatch")

        return cls(
            tag=tag,
            size=size,
            count=count,
            applets=applets
        )