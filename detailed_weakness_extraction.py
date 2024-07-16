import xml.etree.ElementTree as ET
import os

def parse_xml(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    return tree, root

def find_related_attack_patterns(root, weakness_id, namespace):
    related_patterns = []
    for attack_pattern in root.findall(".//capec:Attack_Pattern", namespace):
        for related_weakness in attack_pattern.findall("capec:Related_Weaknesses/capec:Related_Weakness", namespace):
            if related_weakness.get("CWE_ID") == weakness_id:
                related_patterns.append(attack_pattern)
                break
    return related_patterns

def create_xml_tree(weakness_id, weakness_name, related_patterns, namespace):
    root = ET.Element("Weakness_Related_Attack_Patterns")
    root.set("Weakness_ID", weakness_id)
    root.set("Weakness_Name", weakness_name)
    
    for pattern in related_patterns:
        attack_pattern = ET.SubElement(root, "Attack_Pattern")
        attack_pattern.set("ID", pattern.get("ID"))
        attack_pattern.set("Name", pattern.get("Name"))
        description = pattern.find("capec:Description", namespace)
        if description is not None:
            attack_pattern_desc = ET.SubElement(attack_pattern, "Description")
            attack_pattern_desc.text = description.text

    return ET.ElementTree(root)

def save_xml_tree(tree, file_name):
    tree.write(file_name, encoding='utf-8', xml_declaration=True)
    print(f"File saved: {file_name}")

def main(input_file, weakness_id):
    namespace = {'capec': 'http://capec.mitre.org/capec-3'}
    tree, root = parse_xml(input_file)
    
    weakness_name = None
    for weakness in root.findall(".//capec:Related_Weaknesses/capec:Related_Weakness", namespace):
        if weakness.get("CWE_ID") == weakness_id:
            weakness_name = weakness.get("CWE_Name", "Unknown_Weakness")
            break
    
    if not weakness_name:
        print(f"Weakness ID {weakness_id} not found in the file.")
        return
    
    related_patterns = find_related_attack_patterns(root, weakness_id, namespace)
    if related_patterns:
        new_tree = create_xml_tree(weakness_id, weakness_name, related_patterns, namespace)
        file_name = f"Weakness_{weakness_id}_{weakness_name.replace(' ', '_')}.xml"
        save_xml_tree(new_tree, file_name)
    else:
        print(f"No related attack patterns found for Weakness ID {weakness_id}.")

if __name__ == "__main__":
    input_file = 'attack_patterns.xml'  # Path to your XML file
    weakness_id = '276'  # Replace with the desired weakness ID
    main(input_file, weakness_id)
