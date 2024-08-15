import xml.etree.ElementTree as ET
import os

def parse_xml(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    return tree, root

def find_related_attack_patterns(root, weakness_id, namespace):
    related_patterns = []
    for attack_pattern in root.findall(".//capec:Attack_Pattern", namespace):
        for related_weakness in attack_pattern.findall(".//capec:Related_Weaknesses/capec:Related_Weakness", namespace):
            if related_weakness.get("CWE_ID") == weakness_id:
                attack_id = attack_pattern.get("ID")
                attack_name = attack_pattern.get("Name")
                related_patterns.append((attack_id, attack_name))
                break
    return related_patterns

def create_xml_tree(weakness_id, related_patterns):
    root = ET.Element("sandtree")
    parent_node = ET.SubElement(root, "node", refinement="disjunctive")
    label = ET.SubElement(parent_node, "label")
    label.text = f"Weakness ID: {weakness_id}"
    
    for attack_id, attack_name in related_patterns:
        attack_node = ET.SubElement(parent_node, "node", refinement="disjunctive")
        attack_label = ET.SubElement(attack_node, "label")
        attack_label.text = f"{attack_name} (ID: {attack_id})"

    return ET.ElementTree(root)

def save_xml_tree(tree, file_name):
    # Define the target subfolder within the current directory
    target_subfolder = "weakness_attack_templates_scan"  # Replace with your subfolder name
    target_dir = os.path.join(os.getcwd(), target_subfolder)
    
    # Ensure the target subfolder exists
    os.makedirs(target_dir, exist_ok=True)
    
    # Construct the full path for the output file
    file_path = os.path.join(target_dir, file_name)
    
    # Write the XML tree to the specified file
    tree.write(file_path, encoding='utf-8', xml_declaration=True)
    print(f"File saved: {file_path}")

def get_unique_weakness_ids(root, namespace):
    unique_ids = set()
    for weakness in root.findall(".//capec:Related_Weaknesses/capec:Related_Weakness", namespace):
        cwe_id = weakness.get("CWE_ID")
        if cwe_id:
            unique_ids.add(cwe_id)
    return unique_ids

def main(input_file):
    namespace = {'capec': 'http://capec.mitre.org/capec-3'}
    tree, root = parse_xml(input_file)
    
    unique_weakness_ids = get_unique_weakness_ids(root, namespace)
    
    for weakness_id in unique_weakness_ids:
        related_patterns = find_related_attack_patterns(root, weakness_id, namespace)
        if related_patterns:
            new_tree = create_xml_tree(weakness_id, related_patterns)
            file_name = f"{weakness_id}_weakness.xml"
            save_xml_tree(new_tree, file_name)
        else:
            print(f"No related attack patterns found for Weakness ID {weakness_id}.")

if __name__ == "__main__":
    input_file = 'attack_patterns.xml'  # Path to your XML file
    main(input_file)
