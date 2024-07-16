import xml.etree.ElementTree as ET
import networkx as nx
import matplotlib.pyplot as plt

def visualize_dag(xml_file):
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

    pos = nx.spring_layout(G)
    labels = nx.get_node_attributes(G, 'label')
    nx.draw(G, pos, with_labels=True, labels=labels, node_size=5000, node_color='skyblue', font_size=10, font_color='black', font_weight='bold', edge_color='gray')
    plt.title('DAG Visualization')
    plt.show()

if __name__ == "__main__":
    xml_file = 'Attack_1.xml'  # Replace with your XML file path
    visualize_dag(xml_file)
