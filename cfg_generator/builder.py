# cfg_generator/builder.py

from cfg_generator.analysis.leaders import find_leaders
from cfg_generator.analysis.block_splitter import split_basic_blocks
from cfg_generator.analysis.edge_builder import build_edges
from cfg_generator.analysis.exception_edges import build_exception_edges
from cfg_generator.model.cfg import CFG


def build_cfg(method):
    """
    Полный цикл построения CFG для метода.
    :param method: объект Method из cap_decompile
    :return: объект CFG
    """
    # Шаг 1: поиск лидеров
    leaders = find_leaders(method)

    # Шаг 2: разбиение на базовые блоки
    blocks = split_basic_blocks(method.instructions, leaders)

    # Шаг 3: обычные рёбра (условные, безусловные, switch, fallthrough)
    edges = build_edges(blocks)

    # Шаг 4: исключительные рёбра
    exc_edges = build_exception_edges(blocks, method)
    edges.extend(exc_edges)

    # Шаг 5: установка флагов входа/выхода
    if blocks:
        blocks[0].is_entry = True

    for block in blocks:
        if not block.successors:
            block.is_exit = True

    # Построение карты offset -> block_id
    offset_to_block = {block.start_offset: block.id for block in blocks}

    return CFG(
        method_name=method.token,
        entry_block=0,
        blocks=blocks,
        edges=edges,
        offset_to_block=offset_to_block
    )