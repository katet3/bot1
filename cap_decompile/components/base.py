# components/base.py

from dataclasses import dataclass


@dataclass
class CAPComponent:
    tag: int
    size: int

    @classmethod
    def parse_from_bytes(cls, data: bytes):
        raise NotImplementedError