# components/static_field.py

from dataclasses import dataclass
from typing import List

from .base import CAPComponent
from .binary_reader import BinaryReader
from .header import CAPVersion


'''
static_field_component {
    u1 tag
    u2 size
    u2 image_size
    u2 reference_count
    u2 array_init_count
    array_init_info array_init[array_init_count]
    u2 default_value_count
    u2 non_default_value_count
    u1 non_default_values[non_default_value_count]
}

array_init_info {
    u1 type
    u2 count
    u1 values[count]
}
'''


@dataclass
class ArrayInitInfo:
    array_type: int
    count: int
    values: bytes

    @property
    def element_size(self) -> int:
        type_sizes = {
            2: 1,  # boolean
            3: 1,  # byte
            4: 2,  # short
            5: 4   # int
        }
        return type_sizes[self.array_type]

    @property
    def element_count(self) -> int:
        return self.count // self.element_size


@dataclass
class StaticFieldComponent(CAPComponent):
    COMPONENT_TAG = 8

    image_size: int
    reference_count: int
    array_init_count: int
    array_init: List[ArrayInitInfo]
    default_value_count: int
    non_default_value_count: int
    non_default_values: bytes

    @classmethod
    def parse_from_bytes(cls, data: bytes, cap_version: CAPVersion):
        reader = BinaryReader(data)

        tag = reader.read_u1()
        if tag != cls.COMPONENT_TAG:
            raise ValueError(f"Invalid StaticField tag: {tag}")

        size = reader.read_u2()
        if size <= 0:
            raise ValueError("StaticField component size must be > 0")

        start_remaining = reader.remaining()

        # todo other cap_version
        if cap_version in (CAPVersion.V22, CAPVersion.V21):

            image_size = reader.read_u2()
            reference_count = reader.read_u2()

            array_init_count = reader.read_u2()
            array_init = []

            for _ in range(array_init_count):
                array_type = reader.read_u1()

                if array_type not in (2, 3, 4, 5):
                    raise ValueError(
                        f"Invalid array_init type: {array_type}"
                    )

                count = reader.read_u2()
                values = reader.read_bytes(count)

                type_sizes = {
                    2: 1,  # boolean
                    3: 1,  # byte
                    4: 2,  # short
                    5: 4   # int
                }

                element_size = type_sizes[array_type]

                if count % element_size != 0:
                    raise ValueError(
                        f"Invalid array_init count {count} "
                        f"for type {array_type}"
                    )

                array_init.append(
                    ArrayInitInfo(
                        array_type=array_type,
                        count=count,
                        values=values
                    )
                )

            default_value_count = reader.read_u2()
            non_default_value_count = reader.read_u2()

            non_default_values = reader.read_bytes(
                non_default_value_count
            )

            # image_size validation per spec:
            # image_size =
            # reference_count * 2 +
            # default_value_count +
            # non_default_value_count
            expected_image_size = (
                reference_count * 2
                + default_value_count
                + non_default_value_count
            )

            if image_size != expected_image_size:
                raise ValueError(
                    f"Invalid image_size: "
                    f"expected {expected_image_size}, "
                    f"got {image_size}"
                )

            bytes_read = start_remaining - reader.remaining()
            if bytes_read != size:
                raise ValueError(
                    f"StaticField component size mismatch: "
                    f"expected {size}, got {bytes_read}"
                )

        else:
            raise ValueError("CAP not 2.2")

        if reader.remaining() != 0:
            raise ValueError("StaticField parsing incomplete")

        if (start_remaining - reader.remaining()) != size:
            raise ValueError(
                "StaticField component size mismatch"
            )

        return cls(
            tag=tag,
            size=size,
            image_size=image_size,
            reference_count=reference_count,
            array_init_count=array_init_count,
            array_init=array_init,
            default_value_count=default_value_count,
            non_default_value_count=non_default_value_count,
            non_default_values=non_default_values
        )