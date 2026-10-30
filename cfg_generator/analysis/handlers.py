"""Validate method-local exception regions shared by CFG construction stages.

The pipeline supplies jcvm_ir.Handler objects. Only their coordinates are needed
here; catch types, stop bits and table order remain in the original method for
the semantic IR builders. Raw CAP component offsets must be adapted upstream.
"""
from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class ExceptionRegion:
    start: int
    end: int  # exclusive bytecode offset
    target: int


def validated_exception_regions(method) -> tuple[ExceptionRegion, ...]:
    """Read Handler attributes or explicit legacy CFG mappings; never guess offsets."""
    handlers = getattr(method, "exception_handlers", ())
    if not handlers:
        return ()

    bytecodes = getattr(method, "bytecodes", None)
    if not isinstance(bytecodes, (bytes, bytearray, memoryview)):
        raise ValueError("Exception handlers require method.bytecodes to validate region bounds")
    method_end = len(bytecodes)
    instruction_offsets = {instruction.offset for instruction in method.instructions}
    regions = []

    for index, handler in enumerate(handlers):
        prefix = f"Exception handler {index}"
        if isinstance(handler, Mapping):
            try:
                region = ExceptionRegion(
                    handler["start_pc"], handler["end_pc"], handler["handler_pc"],
                )
            except KeyError as error:
                raise ValueError(f"{prefix}: missing legacy field {error.args[0]!r}") from error
        else:
            try:
                region = ExceptionRegion(handler.start, handler.end, handler.target)
            except AttributeError as error:
                raise ValueError(
                    f"{prefix}: expected method-local start/end/target attributes "
                    "or a legacy start_pc/end_pc/handler_pc mapping; "
                    "adapt raw CAP handlers with jcvm_ir.methods_from_cap first"
                ) from error

        for field in ("start", "end", "target"):
            if type(getattr(region, field)) is not int:
                raise ValueError(f"{prefix}: {field} must be an integer method-local offset")
        if not 0 <= region.start < region.end <= method_end:
            raise ValueError(
                f"{prefix}: invalid region [{region.start}, {region.end}) "
                f"for bytecode length {method_end}"
            )
        if not 0 <= region.target < method_end:
            raise ValueError(f"{prefix}: target {region.target} is outside the method")
        for field in ("start", "end", "target"):
            offset = getattr(region, field)
            if field == "end" and offset == method_end:
                continue
            if offset not in instruction_offsets:
                raise ValueError(f"{prefix}: {field} {offset} is not an instruction boundary")
        regions.append(region)

    return tuple(regions)
