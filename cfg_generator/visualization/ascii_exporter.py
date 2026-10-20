# cfg_generator/visualization/ascii_exporter.py

from cfg_generator.model.edge import EdgeType


EDGE_NAMES = {
    EdgeType.FALLTHROUGH: "FALLTHROUGH",
    EdgeType.CONDITIONAL_TRUE: "CONDITIONAL_TRUE",
    EdgeType.CONDITIONAL_FALSE: "CONDITIONAL_FALSE",
    EdgeType.GOTO: "GOTO",
    EdgeType.SWITCH: "SWITCH",
    EdgeType.EXCEPTION: "EXCEPTION",
    EdgeType.RETURN: "RETURN",
}


class ASCIIExporter:

    def export(self, cfg) -> str:

        lines = []

        for block in cfg.blocks:

            lines.append(
                f"BLOCK B{block.id} "
                f"[{block.start_offset}.."
                f"{block.end_offset}]"
            )

            if block.is_entry:
                lines.append("ENTRY")

            if block.is_exit:
                lines.append("EXIT")

            lines.append("Instructions:")

            for ins in block.instructions:

                operands = (
                    ins.operands
                    if ins.operands
                    else []
                )

                lines.append(
                    f"  {ins.offset}: "
                    f"{ins.mnemonic} "
                    f"{operands}"
                )

            lines.append(
                f"Successors: "
                f"{block.successors}"
            )

            lines.append(
                f"Predecessors: "
                f"{block.predecessors}"
            )

            lines.append("")

        lines.append("EDGES")

        for edge in cfg.edges:

            edge_name = EDGE_NAMES.get(
                edge.edge_type,
                edge.edge_type.name
            )

            lines.append(
                f"B{edge.source} "
                f"--{edge_name}--> "
                f"B{edge.target}"
            )

        return "\n".join(lines)