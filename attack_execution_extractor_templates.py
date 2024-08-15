import xml.etree.ElementTree as ET
import os

def build_parent_lookup(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    namespace = {'capec': 'http://capec.mitre.org/capec-3'}

    parent_lookup = {}
    for attack_pattern in root.findall(".//capec:Attack_Pattern", namespace):
        attack_id = attack_pattern.get('ID')
        for related in attack_pattern.findall(".//capec:Related_Attack_Pattern[@Nature='ChildOf']", namespace):
            parent_id = related.get('CAPEC_ID')
            if parent_id not in parent_lookup:
                parent_lookup[parent_id] = []
            parent_lookup[parent_id].append(attack_id)
    
    return parent_lookup, tree

def extract_attack_details(xml_file, attack_id, parent_lookup, tree):
    namespace = {'capec': 'http://capec.mitre.org/capec-3'}
    root = tree.getroot()

    attack_pattern = root.find(f".//capec:Attack_Pattern[@ID='{attack_id}']", namespace)
    if attack_pattern is None:
        print(f"Attack pattern with ID {attack_id} not found.")
        return None, None, None

    attack_name = attack_pattern.attrib.get('Name', 'Unknown')

    # Extract children of the given attack ID
    children = []
    if attack_id in parent_lookup:
        for child_id in parent_lookup[attack_id]:
            child_attack = root.find(f".//capec:Attack_Pattern[@ID='{child_id}']", namespace)
            if child_attack is not None:
                child_name = child_attack.attrib.get('Name', 'Unknown')
                children.append((child_id, child_name))

    # Extract execution flow
    execution_steps = []
    for step in attack_pattern.findall(".//capec:Attack_Step", namespace):
        step_number = step.find("capec:Step", namespace).text
        step_description = step.find("capec:Description", namespace).text
        short_description = step_description.split('[')[-1].split(']')[0]
        execution_steps.append((step_number, short_description))

    return attack_id, attack_name, children, execution_steps

def create_graph_xml(attack_id, attack_name, children, execution_steps, output_file):
    root = ET.Element('sandtree')
    main_node = ET.SubElement(root, 'node', refinement='disjunctive')
    main_label = ET.SubElement(main_node, 'label')
    main_label.text = f"{attack_name} (ID: {attack_id})"

    if execution_steps:
        execution_node = ET.SubElement(main_node, 'node', refinement='sequential')
        execution_label = ET.SubElement(execution_node, 'label')
        execution_label.text = "Execution Flow"
        for step_number, step_description in execution_steps:
            step_node = ET.SubElement(execution_node, 'node', refinement='conjunctive')
            step_label = ET.SubElement(step_node, 'label')
            step_label.text = f"Step {step_number}: {step_description}"

    for child_id, child_name in children:
        child_node = ET.SubElement(main_node, 'node', refinement='disjunctive')
        child_label = ET.SubElement(child_node, 'label')
        child_label.text = f"{child_name} (ID: {child_id})"

    tree = ET.ElementTree(root)
    tree.write(output_file, encoding='utf-8', xml_declaration=True)
    print(f"Graph XML saved to {output_file}")

def main(input_file, attack_id):
    parent_lookup, tree = build_parent_lookup(input_file)
    attack_id, attack_name, children, execution_steps = extract_attack_details(input_file, attack_id, parent_lookup, tree)

    if attack_id and attack_name:
        output_file = f"{attack_id}_Attacktree.xml"
        create_graph_xml(attack_id, attack_name, children, execution_steps, output_file)

if __name__ == "__main__":
    input_file = 'attack_patterns.xml'  # Path to your XML file
    attack_id = '17'  # Replace with the desired attack pattern ID

    main(input_file, attack_id)
