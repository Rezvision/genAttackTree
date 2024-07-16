import xml.etree.ElementTree as ET

def build_parent_child_map(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    namespace = {'capec': 'http://capec.mitre.org/capec-3'}
    parent_child_map = {}
    id_name_map = {}

    # Build the mapping of ID to name
    for attack in root.findall('.//capec:Attack_Pattern', namespace):
        attack_id = attack.get('ID')
        attack_name = attack.get('Name')
        id_name_map[attack_id] = attack_name
        for related in attack.findall('.//capec:Related_Attack_Pattern', namespace):
            if related.get('Nature') == 'ChildOf':
                parent_id = related.get('CAPEC_ID')
                if parent_id not in parent_child_map:
                    parent_child_map[parent_id] = []
                parent_child_map[parent_id].append((attack_id, attack_name))

    return parent_child_map, id_name_map

def create_graph_xml(parent_id, parent_name, children, output_file):
    root = ET.Element('sandtree')
    node = ET.SubElement(root, 'node', refinement='disjunctive')
    label = ET.SubElement(node, 'label')
    label.text = f'{parent_name} (ID: {parent_id})'

    for child_id, child_name in children:
        child_node = ET.SubElement(node, 'node', refinement='disjunctive')
        child_label = ET.SubElement(child_node, 'label')
        child_label.text = f'{child_name} (ID: {child_id})'

    tree = ET.ElementTree(root)
    tree.write(output_file, encoding='utf-8', xml_declaration=True)
    print(f"Graph XML saved to {output_file}")

def main(input_file, parent_id):
    parent_child_map, id_name_map = build_parent_child_map(input_file)

    if parent_id in parent_child_map:
        parent_name = id_name_map.get(parent_id, "Unknown")
        output_file = f"{parent_id}_graph.xml"
        create_graph_xml(parent_id, parent_name, parent_child_map[parent_id], output_file)
    else:
        print(f"No child attack patterns found for ID {parent_id}")

if __name__ == "__main__":
    input_file = 'attack_patterns.xml'  # Path to your XML file
    parent_id = '153'  # Replace with the desired parent ID

    main(input_file, parent_id)
