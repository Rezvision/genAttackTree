import xml.etree.ElementTree as ET
import os

def parse_xml(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    return tree, root

def find_related_weaknesses(root, attack_pattern_id, namespace):
    related_weaknesses = []
    for attack_pattern in root.findall(".//capec:Attack_Pattern[@ID='" + attack_pattern_id + "']", namespace):
        for related_weakness in attack_pattern.findall(".//capec:Related_Weaknesses/capec:Related_Weakness", namespace):
            weakness_id = related_weakness.get("CWE_ID")
            if weakness_id:
                related_weaknesses.append(weakness_id)
    return related_weaknesses

def create_xml_tree(attack_pattern_id, attack_pattern_name, related_weaknesses):
    root = ET.Element("sandtree")
    
    for weakness_id in related_weaknesses:
        parent_node = ET.SubElement(root, "node", refinement="disjunctive")
        label = ET.SubElement(parent_node, "label")
        label.text = f"Weakness ID: {weakness_id}"
        
        attack_node = ET.SubElement(parent_node, "node", refinement="disjunctive")
        attack_label = ET.SubElement(attack_node, "label")
        attack_label.text = f"{attack_pattern_name} (ID: {attack_pattern_id})"

    return ET.ElementTree(root)

def save_xml_tree(tree, file_name):
    tree.write(file_name, encoding='utf-8', xml_declaration=True)
    print(f"File saved: {file_name}")

def main(input_file, attack_pattern_id):
    namespace = {'capec': 'http://capec.mitre.org/capec-3'}
    tree, root = parse_xml(input_file)
    
    attack_pattern_name = None
    attack_pattern = root.find(".//capec:Attack_Pattern[@ID='" + attack_pattern_id + "']", namespace)
    if attack_pattern is not None:
        attack_pattern_name = attack_pattern.get("Name")
    else:
        print(f"Attack Pattern ID {attack_pattern_id} not found in the file.")
        return
    
    related_weaknesses = find_related_weaknesses(root, attack_pattern_id, namespace)
    if related_weaknesses:
        new_tree = create_xml_tree(attack_pattern_id, attack_pattern_name, related_weaknesses)
        file_name = f"Attack_{attack_pattern_id}_weaknesses.xml"
        save_xml_tree(new_tree, file_name)
    else:
        print(f"No related weaknesses found for Attack Pattern ID {attack_pattern_id}.")

if __name__ == "__main__":
    input_file = 'attack_patterns.xml'  # Path to your XML file
    attack_pattern_id = '2'  # Replace with the desired attack pattern ID
    main(input_file, attack_pattern_id)
