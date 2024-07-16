import xml.etree.ElementTree as ET
from py2cytoscape.data.cyrest_client import CyRestClient

def parse_xml(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    return root

def extract_weaknesses_for_attack_pattern(root, attack_pattern_id, namespace):
    weaknesses = []
    attack_pattern_name = ""
    for attack_pattern in root.findall(".//capec:Attack_Pattern", namespace):
        if attack_pattern.get("ID") == attack_pattern_id:
            attack_pattern_name = attack_pattern.get("Name")
            for related_weakness in attack_pattern.findall("capec:Related_Weaknesses/capec:Related_Weakness", namespace):
                weaknesses.append(related_weakness.get("CWE_ID"))
    return attack_pattern_name, weaknesses

def create_dag(weaknesses, attack_pattern_id, attack_pattern_name):
    nodes = []
    edges = []

    # Add the attack pattern node
    attack_pattern_node = {'data': {'id': attack_pattern_id, 'name': attack_pattern_name}}
    nodes.append(attack_pattern_node)

    # Add weakness nodes and edges
    for weakness_id in weaknesses:
        weakness_node = {'data': {'id': weakness_id, 'name': f"Weakness ID: {weakness_id}"}}
        nodes.append(weakness_node)
        edges.append({'data': {'source': weakness_id, 'target': attack_pattern_id}})
    
    return nodes, edges

def visualize_dag(xml_file, attack_pattern_id):
    namespace = {'capec': 'http://capec.mitre.org/capec-3'}
    root = parse_xml(xml_file)
    
    attack_pattern_name, weaknesses = extract_weaknesses_for_attack_pattern(root, attack_pattern_id, namespace)
    
    if not attack_pattern_name:
        print(f"Attack Pattern ID {attack_pattern_id} not found in the file.")
        return
    
    if weaknesses:
        nodes, edges = create_dag(weaknesses, attack_pattern_id, attack_pattern_name)

        cy = CyRestClient()

        network = cy.network.create(name='DAG Network', collection='DAG Collection')
        
        network.add_nodes(nodes)
        
        # Adding edges requires a list of dictionaries where each dictionary represents an edge
        edge_data = [{'data': {'source': edge['data']['source'], 'target': edge['data']['target']}} for edge in edges]
        network.add_edges(edge_data)

        cy.layout.apply(name='force-directed', network=network.suid)
        cy.style.apply(style_name='default', network=network.suid)

        cy.network.view.update(network=network.suid)
        print("DAG visualization created in Cytoscape.")
    else:
        print(f"No related weaknesses found for Attack Pattern ID {attack_pattern_id}.")

if __name__ == "__main__":
    xml_file = 'attack_patterns.xml'  # Path to your XML file
    attack_pattern_id = '276'  # Replace with your desired attack pattern ID
    visualize_dag(xml_file, attack_pattern_id)
