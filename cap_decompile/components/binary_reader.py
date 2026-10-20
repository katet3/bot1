# components/binary_reader.py

import struct


class BinaryReader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def read_u1(self) -> int:
        value = self.data[self.offset]
        self.offset += 1
        return value

    def read_u2(self) -> int:
        value = struct.unpack_from(">H", self.data, self.offset)[0]
        self.offset += 2
        return value

    def read_u4(self) -> int:
        value = struct.unpack_from(">I", self.data, self.offset)[0]
        self.offset += 4
        return value

    def read_bytes(self, length: int) -> bytes:
        value = self.data[self.offset : self.offset + length]
        self.offset += length
        return value
    
    def remaining(self) -> int:
        return len(self.data) - self.offset
    
    def tell(self) -> int:
        return self.offset

    def seek(self, offset: int):
        if not (0 <= offset <= len(self.data)):
            raise ValueError(f"Invalid seek offset: {offset}")
        self.offset = offset

    def skip(self, length: int):
        self.seek(self.offset + length)