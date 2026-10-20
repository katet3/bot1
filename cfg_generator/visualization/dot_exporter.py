# cfg_generator/visualization/dot_exporter.py

from graphviz import Digraph

from cfg_generator.model.edge import EdgeType


EDGE_COLORS = {
    EdgeType.FALLTHROUGH: "black",
    EdgeType.CONDITIONAL_TRUE: "green",
    EdgeType.CONDITIONAL_FALSE: "red",
    EdgeType.GOTO: "blue",
    EdgeType.SWITCH: "purple",
    EdgeType.EXCEPTION: "orange",
    EdgeType.RETURN: "gray",
}


EDGE_LABELS = {
    EdgeType.FALLTHROUGH: "fallthrough",
    EdgeType.CONDITIONAL_TRUE: "true",
    EdgeType.CONDITIONAL_FALSE: "false",
    EdgeType.GOTO: "goto",
    EdgeType.SWITCH: "switch",
    EdgeType.EXCEPTION: "exception",
    EdgeType.RETURN: "return",
}


class DotExporter:

    def export(
        self,
        cfg,
        output_path: str,
        format: str = "png"
    ):

        graph = Digraph(
            name="CFG",
            format=format
        )

        graph.attr(rankdir="TB")
        graph.attr(
            "node",
            shape="box",
            fontname="Courier"
        )

        for block in cfg.blocks:

            label_lines = []

            header = f"B{block.id}"

            if block.is_entry:
                header += " [ENTRY]"

            if block.is_exit:
                header += " [EXIT]"

            label_lines.append(header)

            for ins in block.instructions:

                operands = (
                    f" {ins.operands}"
                    if ins.operands
                    else ""
                )

                label_lines.append(
                    f"{ins.offset}: "
                    f"{ins.mnemonic}"
                    f"{operands}"
                )

            label = "\n".join(label_lines)

            graph.node(
                name=f"B{block.id}",
                label=label
            )

        for edge in cfg.edges:

            graph.edge(
                tail_name=f"B{edge.source}",
                head_name=f"B{edge.target}",
                label=EDGE_LABELS.get(
                    edge.edge_type,
                    edge.edge_type.name.lower()
                ),
                color=EDGE_COLORS.get(
                    edge.edge_type,
                    "black"
                )
            )

        graph.render(
            filename=output_path,
            cleanup=True
        )