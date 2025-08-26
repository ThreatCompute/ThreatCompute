import json
import networkx as nx
import matplotlib.pyplot as plt
from io import StringIO


def custom_literal_stringizer(value):
    """Convert a `value` to a Python literal in GML representation.

    Parameters
    ----------
    value : object
        The `value` to be converted to GML representation.

    Returns
    -------
    rep : string
        A double-quoted Python literal representing value. Unprintable
        characters are replaced by XML character references.

    Raises
    ------
    ValueError
        If `value` cannot be converted to GML.

    Notes
    -----
    The original value can be recovered using the
    :func:`networkx.readwrite.gml.literal_destringizer` function.
    """

    def stringize(value):
        if isinstance(value, int | bool) or value is None:
            if value is True:  # GML uses 1/0 for boolean values.
                buf.write(str(1))
            elif value is False:
                buf.write(str(0))
            else:
                buf.write(str(value))
        elif isinstance(value, str):
            text = repr(value).strip("'")
            if text[0] != "u":
                try:
                    value.encode("latin1")
                except UnicodeEncodeError:
                    text = "u" + text
            buf.write(text)
        elif isinstance(value, float | complex | str | bytes):
            buf.write(repr(value))
        elif isinstance(value, list):
            buf.write("[")
            first = True
            for item in value:
                if not first:
                    buf.write(",")
                else:
                    first = False
                stringize(item)
            buf.write("]")
        elif isinstance(value, tuple):
            if len(value) > 1:
                buf.write("(")
                first = True
                for item in value:
                    if not first:
                        buf.write(",")
                    else:
                        first = False
                    stringize(item)
                buf.write(")")
            elif value:
                buf.write("(")
                stringize(value[0])
                buf.write(",)")
            else:
                buf.write("()")
        elif isinstance(value, dict):
            buf.write("{")
            first = True
            for key, value in value.items():
                if not first:
                    buf.write(",")
                else:
                    first = False
                stringize(key.replace("-", "_"))
                buf.write(":")
                stringize(value)
            buf.write("}")
        elif isinstance(value, set):
            buf.write("{")
            first = True
            for item in value:
                if not first:
                    buf.write(",")
                else:
                    first = False
                stringize(item)
            buf.write("}")
        else:
            msg = f"{value!r} cannot be converted into a Python literal"
            raise ValueError(msg)

    buf = StringIO()
    stringize(value)
    return buf.getvalue()


def add_outgoing_edges(G, source, technique, tactic):
    """
    Add edges from from source asset to attack targets
    """
    # check if the target is a list (multiple targets)
    if isinstance(technique["target"], list):
        for target in technique["target"]:
            # check if target is among the predefined assets
            if target in G.nodes():
                if G.has_edge(source, target):
                    G[source][target]["techniques"].append(
                        {
                            "technique": technique["technique"],
                            "description": technique["description"],
                            "tactic": tactic,
                            "requirement": technique["requirement"],
                            "selfLoop": False,
                        }
                    )
                    G[source][target]["weight"] += 1
                else:
                    G.add_edge(
                        source,
                        target,
                        techniques=[
                            {
                                "technique": technique["technique"],
                                "description": technique["description"],
                                "tactic": tactic,
                                "requirement": technique["requirement"],
                                "selfLoop": False,
                            }
                        ],
                        weight=1,
                    )
    elif technique["target"] == "self":
        if G.has_edge(source, source):
            G[source][source]["techniques"].append(
                {
                    "technique": technique["technique"],
                    "description": technique["description"],
                    "tactic": tactic,
                    "requirement": technique["requirement"],
                    "selfLoop": True,
                }
            )
            G[source][source]["weight"] += 1
        else:
            G.add_edge(
                source,
                source,
                techniques=[
                    {
                        "technique": technique["technique"],
                        "description": technique["description"],
                        "tactic": tactic,
                        "requirement": technique["requirement"],
                        "selfLoop": True,
                    }
                ],
                weight=1,
            )
    else:
        if technique["target"] in G.nodes():
            target = technique["target"]
            if G.has_edge(source, target):
                G[source][target]["techniques"].append(
                    {
                        "technique": technique["technique"],
                        "description": technique["description"],
                        "tactic": tactic,
                        "requirement": technique["requirement"],
                        "selfLoop": False,
                    }
                )
                G[source][target]["weight"] += 1
            else:
                G.add_edge(
                    source,
                    target,
                    techniques=[
                        {
                            "technique": technique["technique"],
                            "description": technique["description"],
                            "tactic": tactic,
                            "requirement": technique["requirement"],
                            "selfLoop": False,
                        }
                    ],
                    weight=1,
                )
    return G


def tmr_to_graph(tmr: dict):
    """
    Create a graph from the threat modeling rules (provided as a dictionary)
    """
    G = nx.DiGraph()
    for asset in tmr["assets"]:
        if asset == "Container":
            for category in tmr["assets"][asset]["categories"]:
                instance_list = tmr["assets"][asset]["categories"][category][
                    "instances"
                ]
                instances = [
                    {"name": instance["name"], "id": instance["id"]}
                    for instance in instance_list
                ]
                G.add_node(
                    category,
                    description=tmr["assets"][asset]["categories"][category][
                        "description"
                    ],
                    instances=instances,
                    type="Container",
                )
        else:
            instance_list = tmr["assets"][asset]["instances"]
            instances = [
                {"name": instance["name"], "id": instance["id"]}
                for instance in instance_list
            ]
            G.add_node(
                asset,
                description=tmr["assets"][asset]["description"],
                instances=instances,
                type=asset,
            )

    for asset in tmr["techniques"]:
        if asset == "Container":
            for sub_asset in tmr["techniques"][asset]:
                for tactic in tmr["techniques"][asset][sub_asset]:
                    for technique in tmr["techniques"][asset][sub_asset][tactic]:
                        G = add_outgoing_edges(G, sub_asset, technique, tactic)
        else:
            for tactic in tmr["techniques"][asset]:
                for technique in tmr["techniques"][asset][tactic]:
                    G = add_outgoing_edges(G, asset, technique, tactic)
    return G


def attack_paths(G):
    """
    Find all attack paths in the graph
    """
    count = 0
    for source in G.nodes():
        for target in G.nodes():
            if source != target:
                paths = nx.all_simple_edge_paths(G, source=source, target=target)
                for path in paths:
                    if len(path) > 1:
                        attributed_path = [
                            (u, v, G.get_edge_data(u, v)["technique"]) for u, v in path
                        ]
                        print(attributed_path)
                        count += 1
    print(f"Number of paths: {count}")


def draw_tm_graph(G, figure_path):
    # Define the position layout for the nodes
    pos = nx.shell_layout(G)  # Using shell layout for better visualization

    # Draw the graph
    plt.figure(
        figsize=(13, 10),
        tight_layout={"pad": 0, "h_pad": 0, "w_pad": 0.2, "rect": [0, 0, 1, 1]},
    )

    # Draw nodes with labels
    nx.draw_networkx_nodes(
        G, pos, node_color="skyblue", node_size=9000, margins=(0.03, 0.05)
    )
    node_labels = {
        node: str(node).replace(" ", "\n") for node in G.nodes()
    }  # Adding line breaks (adjust if needed)
    nx.draw_networkx_labels(
        G, pos, labels=node_labels, font_size=14, font_color="black"
    )

    # Draw edges with varying thickness based on weight
    for edge in G.edges(data=True):
        u, v, d = edge
        if u == v:
            nx.draw_networkx_edges(
                G,
                pos,
                edgelist=[(u, v)],
                node_size=500,
                width=d["weight"] / 2.3,
                edge_color="gray",
            )
        else:
            nx.draw_networkx_edges(
                G,
                pos,
                edgelist=[(u, v)],
                node_size=9000,
                width=d["weight"] / 2,
                edge_color="gray",
            )

    # Remove the black rim around the graphic
    plt.axis("off")

    plt.savefig(figure_path, bbox_inches="tight", pad_inches=0)


if __name__ == "__main__":
    threat_model_file = "path/to/threat/model"
    with open(f"{threat_model_file}.json") as f:
        tmr = json.load(f)
    G = tmr_to_graph(tmr)
    nx.write_gml(G, f"{threat_model_file}.gml", stringizer=custom_literal_stringizer)
    draw_tm_graph(G, "path/to/figure")
