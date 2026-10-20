# cfg_generator\analysis\exception_edges.py

from cfg_generator.model.edge import (
    CFGEdge,
    EdgeType
)

def build_exception_edges(blocks, method):
    edges = []
    handlers = getattr(method, 'exception_handlers', [])
    if not handlers:
        return edges

    offset_to_block = {block.start_offset: block.id for block in blocks}
    block_by_id = {block.id: block for block in blocks}

    for handler in handlers:
        start_pc = handler['start_pc']
        end_pc = handler['end_pc']
        handler_pc = handler['handler_pc']

        if handler_pc not in offset_to_block:
            continue

        handler_block_id = offset_to_block[handler_pc]
        # Помечаем блок как обработчик исключения
        block_by_id[handler_block_id].is_exception_handler = True

        for block in blocks:
            # Проверка пересечения интервалов
            if not (block.end_offset < start_pc or block.start_offset >= end_pc):
                edge = CFGEdge(source=block.id,
                               target=handler_block_id,
                               edge_type=EdgeType.EXCEPTION)
                edges.append(edge)
                block.successors.append(handler_block_id)
                block_by_id[handler_block_id].predecessors.append(block.id)

    return edges