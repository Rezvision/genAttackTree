import xml.etree.ElementTree as ET
from graphviz import Digraph

def visualize_dag(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    dot = Digraph(comment='DAG Visualization')

    # Add nodes
    for node in root.findall(".//node"):
        node_id = node.get("id")
        label = node.find("label").text
        dot.node(node_id, label)

    # Add edges
    for link in root.findall(".//link"):
        source = link.find("source").text
        target = link.find("target").text
        dot.edge(source, target)

    dot.render('output/dag_visualization', view=True, format='png')

if __name__ == "__main__":
    xml_file = 'Attack_1.xml'  # Replace with your XML file path
    visualize_dag(xml_file)
