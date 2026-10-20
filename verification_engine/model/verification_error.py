# verification_engine/model/verification_error.py

from dataclasses import dataclass


@dataclass
class VerificationError:
    """
    Ошибка верификации CFG.
    """

    error_type: str

    message: str

    block_offset: int | None = None

    instruction_offset: int | None = None

    edge_type: str | None = None

    source_block: int | None = None

    target_block: int | None = None

    def __str__(self) -> str:

        location_parts = []

        if self.block_offset is not None:
            location_parts.append(
                f"block={self.block_offset}"
            )

        if self.instruction_offset is not None:
            location_parts.append(
                f"instruction="
                f"{self.instruction_offset}"
            )

        if self.source_block is not None:
            location_parts.append(
                f"source=B{self.source_block}"
            )

        if self.target_block is not None:
            location_parts.append(
                f"target=B{self.target_block}"
            )

        if self.edge_type is not None:
            location_parts.append(
                f"edge={self.edge_type}"
            )

        location = ""

        if location_parts:
            location = (
                " ["
                + ", ".join(location_parts)
                + "]"
            )

        return (
            f"{self.error_type}"
            f"{location}: "
            f"{self.message}"
        )