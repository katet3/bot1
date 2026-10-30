"""Conservative exceptional CFG edges over validated, split handler regions."""
from cfg_generator.analysis.handlers import validated_exception_regions
from cfg_generator.model.edge import (
    CFGEdge,
    EdgeType
)

def build_exception_edges(blocks, method):
    regions = validated_exception_regions(method)
    if not regions:
        return []

    offset_to_block = {block.start_offset: block.id for block in blocks}
    block_by_id = {block.id: block for block in blocks}

    # Validate every region before mutating any block, including direct calls
    # that did not use find_leaders/split_basic_blocks.
    for index, region in enumerate(regions):
        for field in ("start", "end", "target"):
            offset = getattr(region, field)
            if field == "end" and offset == len(method.bytecodes):
                continue
            if offset not in offset_to_block:
                raise ValueError(
                    f"Exception handler {index}: {field} {offset} is not a block start; "
                    "split blocks at exception-region boundaries first"
                )

    edges = []
    for region in regions:
        handler_block_id = offset_to_block[region.target]
        # Помечаем блок как обработчик исключения
        block_by_id[handler_block_id].is_exception_handler = True

        for block in blocks:
            # Region boundaries are block starts; end is exclusive. Do not use
            # block.end_offset as a byte length (it is the last instruction start).
            if region.start <= block.start_offset < region.end:
                edge = CFGEdge(source=block.id,
                               target=handler_block_id,
                               edge_type=EdgeType.EXCEPTION)
                edges.append(edge)
                block.successors.append(handler_block_id)
                block_by_id[handler_block_id].predecessors.append(block.id)

    return edges
