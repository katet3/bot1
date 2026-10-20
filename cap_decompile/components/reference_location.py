# components/reference_location

from dataclasses import dataclass
from typing import List

from .base import CAPComponent
from .binary_reader import BinaryReader
from .header import CAPVersion


'''
reference_location_component {
    u1 tag
    u2 size
    u2 byte_index_count
    u1 offsets_to_byte_indices[byte_index_count]
    u2 byte2_index_count
    u1 offsets_to_byte2_indices[byte2_index_count]
}
'''


@dataclass
class ReferenceLocationComponent(CAPComponent):
    COMPONENT_TAG = 9

    byte_index_count: int
    offsets_to_byte_indices: List[int]

    byte2_index_count: int
    offsets_to_byte2_indices: List[int]

    @classmethod
    def parse_from_bytes(cls, data: bytes, cap_version: CAPVersion):
        reader = BinaryReader(data)

        tag = reader.read_u1()
        if tag != cls.COMPONENT_TAG:
            raise ValueError(
                f"Invalid ReferenceLocation tag: {tag}"
            )

        size = reader.read_u2()
        if size <= 0:
            raise ValueError(
                "ReferenceLocation component size must be > 0"
            )

        start_remaining = reader.remaining()

        # todo other cap_version
        if cap_version in (
            CAPVersion.V22,
            CAPVersion.V21
        ):

            byte_index_count = reader.read_u2()

            offsets_to_byte_indices = []
            for _ in range(byte_index_count):
                offsets_to_byte_indices.append(
                    reader.read_u1()
                )

            byte2_index_count = reader.read_u2()

            offsets_to_byte2_indices = []
            for _ in range(byte2_index_count):
                offsets_to_byte2_indices.append(
                    reader.read_u1()
                )

            bytes_read = (
                start_remaining - reader.remaining()
            )

            if bytes_read != size:
                raise ValueError(
                    f"ReferenceLocation component "
                    f"size mismatch: "
                    f"expected {size}, "
                    f"got {bytes_read}"
                )

        else:
            raise ValueError("CAP not 2.2")

        if reader.remaining() != 0:
            raise ValueError(
                "ReferenceLocation parsing incomplete"
            )

        if (
            start_remaining - reader.remaining()
        ) != size:
            raise ValueError(
                "ReferenceLocation component "
                "size mismatch"
            )

        return cls(
            tag=tag,
            size=size,
            byte_index_count=byte_index_count,
            offsets_to_byte_indices=offsets_to_byte_indices,
            byte2_index_count=byte2_index_count,
            offsets_to_byte2_indices=offsets_to_byte2_indices
        )