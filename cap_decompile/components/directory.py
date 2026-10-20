# components/directory.py

from dataclasses import dataclass
from typing import List
from .base import CAPComponent
from .binary_reader import BinaryReader
from .header import CAPVersion

'''
struct Directory.cap

u1 tag = 2
u2 size // размер без tag и size

u2 component_sizes[12]

static_field_size_info {
    u2 image_size
    u2 array_init_count
    u2 array_init_size
}

u1 import_count
u1 applet_count
u1 custom_count

custom_component_info custom_components[custom_count]

custom_component_info {
    u1 component_tag
    u2 size
    u1 AID_length
    u1 AID[AID_length]
}
'''

@dataclass
class StaticFieldSizeInfo:
    image_size: int
    array_init_count: int
    array_init_size: int


@dataclass
class CustomComponentInfo:
    component_tag: int
    size: int
    aid: bytes


@dataclass
class DirectoryComponent(CAPComponent):
    COMPONENT_TAG = 2

    component_sizes: List[int]
    static_field_size: StaticFieldSizeInfo
    import_count: int
    applet_count: int
    custom_count: int
    custom_components: List[CustomComponentInfo]

    @classmethod
    def parse_from_bytes(cls, data: bytes, cap_version: CAPVersion):
        reader = BinaryReader(data)

        tag = reader.read_u1()
        if tag != cls.COMPONENT_TAG:
            raise ValueError(f"Invalid Directory tag. Tag is {tag}")

        size = reader.read_u2()
        start_remaining = reader.remaining()

        component_sizes = [reader.read_u2() for _ in range(12)]

        # static_field_size_info
        image_size = reader.read_u2()
        array_init_count = reader.read_u2()
        array_init_size = reader.read_u2()

        static_field_size = StaticFieldSizeInfo(
            image_size=image_size,
            array_init_count=array_init_count,
            array_init_size=array_init_size,
        )

        import_count = reader.read_u1()

        #todo other cap_version
        if cap_version in (CAPVersion.V22, CAPVersion.V21):
            applet_count = 0
            custom_count = 0
            custom_components = None
        else:
            applet_count = reader.read_u1()
            custom_count = reader.read_u1()

            custom_components = []

            for _ in range(custom_count):
                component_tag = reader.read_u1()
                size = reader.read_u2()
                aid_length = reader.read_u1()
                aid = reader.read_bytes(aid_length)

                custom_components.append(
                    CustomComponentInfo(
                        component_tag=component_tag,
                        size=size,
                        aid=aid
                    )
                )

        if reader.remaining() != 0:
            raise ValueError("Directory parsing incomplete")

        if (start_remaining - reader.remaining()) != size:
            raise ValueError("Directory component size mismatch")
        
        return cls(
            tag=tag,
            size=size,
            component_sizes=component_sizes,
            static_field_size=static_field_size,
            import_count=import_count,
            applet_count=applet_count,
            custom_count=custom_count,
            custom_components=custom_components
        )