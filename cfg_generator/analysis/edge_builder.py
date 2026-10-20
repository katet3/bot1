# cfg_generator/analysis/edge_builder.py

from cfg_generator.model.edge import (
    CFGEdge,
    EdgeType
)

from cfg_generator.utils.instruction_utils import (
    is_conditional_branch,
    is_unconditional_branch,
    is_switch,
    is_return
)


def build_edges(blocks):

    edges = []

    offset_to_block = {
        block.start_offset: block.id
        for block in blocks
    }

    for i, block in enumerate(blocks):

        last = block.instructions[-1]
        mnemonic = last.mnemonic

        # -------------------------------------------------
        # CONDITIONAL BRANCH
        # -------------------------------------------------

        if is_conditional_branch(mnemonic):

            target_offset = last.operands[0]

            true_block = offset_to_block[
                target_offset
            ]

            _add_edge(
                edges,
                blocks,
                block.id,
                true_block,
                EdgeType.CONDITIONAL_TRUE
            )

            if i + 1 < len(blocks):

                false_block = (
                    blocks[i + 1].id
                )

                _add_edge(
                    edges,
                    blocks,
                    block.id,
                    false_block,
                    EdgeType.CONDITIONAL_FALSE
                )

        # -------------------------------------------------
        # GOTO / GOTO_W
        # -------------------------------------------------

        elif is_unconditional_branch(
            mnemonic
        ):

            target_offset = (
                last.operands[0]
            )

            target_block = (
                offset_to_block[
                    target_offset
                ]
            )

            _add_edge(
                edges,
                blocks,
                block.id,
                target_block,
                EdgeType.GOTO
            )

        # -------------------------------------------------
        # SWITCH
        # -------------------------------------------------

        elif is_switch(mnemonic):
            operands = last.operands
            default_offset = operands["default"]
            default_block = offset_to_block[default_offset]
            _add_edge(edges, blocks, block.id, default_block, EdgeType.SWITCH)

            # tableswitch
            if "jumps" in operands:
                for target_offset in operands["jumps"]:
                    target_block = offset_to_block[target_offset]
                    _add_edge(edges, blocks, block.id, target_block, EdgeType.SWITCH)
            # lookupswitch
            elif "pairs" in operands:
                for _, target_offset in operands["pairs"]:
                    target_block = offset_to_block[target_offset]
                    _add_edge(edges, blocks, block.id, target_block, EdgeType.SWITCH)

        # -------------------------------------------------
        # RETURN
        # -------------------------------------------------

        elif is_return(mnemonic):
            continue

        # -------------------------------------------------
        # FALLTHROUGH
        # -------------------------------------------------

        else:

            if i + 1 < len(blocks):

                next_block = (
                    blocks[i + 1].id
                )

                _add_edge(
                    edges,
                    blocks,
                    block.id,
                    next_block,
                    EdgeType.FALLTHROUGH
                )

    return edges


def _add_edge(
    edges,
    blocks,
    source,
    target,
    edge_type
):

    edge = CFGEdge(
        source=source,
        target=target,
        edge_type=edge_type
    )

    edges.append(edge)

    blocks[source].successors.append(
        target
    )

    blocks[target].predecessors.append(
        source
    )