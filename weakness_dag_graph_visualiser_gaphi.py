import xml.etree.ElementTree as ET
import networkx as nx

def convert_to_gexf(xml_file, output_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    G = nx.DiGraph()

    # Add nodes
    for node in root.findall(".//node"):
        node_id = node.get("id")
        label = node.find("label").text
        G.add_node(node_id, label=label)

    # Add edges
    for link in root.findall(".//link"):
        source = link.find("source").text
        target = link.find("target").text
        G.add_edge(source, target)

    nx.write_gexf(G, output_file)
    print(f"Graph saved to {output_file}")

if __name__ == "__main__":
    xml_file = 'Attack_1.xml'  # Replace with your XML file path
    output_file = 'attack_1.gexf'  # Replace with your desired output file path
    convert_to_gexf(xml_file, output_file)
