# components/binary_reader.py

import struct


class BinaryParseError(ValueError):
    """Binary range/format error with coordinates; no input bytes are embedded."""

    def __init__(self, message: str, *, offset, context: str,
                 needed: int | None = None, available: int | None = None):
        self.offset = offset
        self.context = context
        self.needed = needed
        self.available = available
        detail = f"{context} at offset {offset}: {message}"
        if needed is not None:
            detail += f" (need {needed} bytes, available {available})"
        super().__init__(detail)


def require_range(data: bytes, offset: int, length: int, *, context: str):
    """Require the complete half-open range; zero bytes at EOF are valid."""
    if type(offset) is not int or not 0 <= offset <= len(data):
        raise BinaryParseError(f"Invalid offset {offset!r}", offset=offset, context=context)
    if type(length) is not int or length < 0:
        raise BinaryParseError(f"Invalid length {length!r}", offset=offset, context=context)
    available = len(data) - offset
    if length > available:
        raise BinaryParseError("Truncated input", offset=offset, context=context,
                               needed=length, available=available)


class BinaryReader:
    """Big-endian reader; unsuccessful reads/seeks/skips leave the cursor intact."""

    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def read_u1(self) -> int:
        require_range(self.data, self.offset, 1, context="read_u1")
        value = self.data[self.offset]
        self.offset += 1
        return value

    def read_u2(self) -> int:
        require_range(self.data, self.offset, 2, context="read_u2")
        value = struct.unpack_from(">H", self.data, self.offset)[0]
        self.offset += 2
        return value

    def read_u4(self) -> int:
        require_range(self.data, self.offset, 4, context="read_u4")
        value = struct.unpack_from(">I", self.data, self.offset)[0]
        self.offset += 4
        return value

    def read_bytes(self, length: int) -> bytes:
        require_range(self.data, self.offset, length, context="read_bytes")
        value = self.data[self.offset : self.offset + length]
        self.offset += length
        return value

    def remaining(self) -> int:
        return len(self.data) - self.offset

    def tell(self) -> int:
        return self.offset

    def seek(self, offset: int):
        require_range(self.data, offset, 0, context="seek")
        self.offset = offset

    def skip(self, length: int):
        require_range(self.data, self.offset, length, context="skip")
        self.offset += length
