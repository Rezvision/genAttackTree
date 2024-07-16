import xml.etree.ElementTree as ET

def analyze_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    # Define the namespace
    namespace = {'capec': 'http://capec.mitre.org/capec-3'}

    # Printing meta information
    print("Root tag:", root.tag)
    print("Root attributes:", root.attrib)
    print("Number of children of the root:", len(root))

    # Print all children of the root
    for child in root:
        print(child.tag, child.attrib)
        for subchild in child:
            print(f"  {subchild.tag}: {subchild.attrib}")

    # Find all Attack_Pattern elements
    attack_patterns = root.findall('.//capec:Attack_Pattern', namespace)
    print(f"Total Attack Patterns: {len(attack_patterns)}")

    for pattern in attack_patterns:
        print(f"ID: {pattern.attrib['ID']}, Name: {pattern.attrib['Name']}, Status: {pattern.attrib['Status']}")

def get_child_info(root, child_tag, namespace):
    # Get more information about a specific child element
    child = root.find(child_tag, namespace)
    if child is not None:
        print(f"\nInformation about {child_tag}:")
        print(f"Tag: {child.tag}")
        print(f"Attributes: {child.attrib}")
        for subchild in child:
            print(f"  {subchild.tag}: {subchild.attrib}")
    else:
        print(f"\nChild with tag '{child_tag}' not found.")

def extract_attack_pattern(xml_file, pattern_id, namespace):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    attack_pattern = root.find(f".//capec:Attack_Pattern[@ID='{pattern_id}']", namespace)

    if attack_pattern is not None:
        new_tree = ET.ElementTree(attack_pattern)
        pattern_name = attack_pattern.attrib.get("Name", "Unknown").replace(" ", "_")
        new_file = f"{pattern_id}_{pattern_name}.xml"
        new_tree.write(new_file, encoding='utf-8', xml_declaration=True)
        print(f"Attack pattern saved to {new_file}")
    else:
        print(f"Attack pattern with ID {pattern_id} not found.")

if __name__ == "__main__":
    xml_file = 'attack_patterns.xml'  # Path to your XML file

    # Analyze the XML file and print meta information
    analyze_xml(xml_file)

    # Get more information about a specific child element
    tree = ET.parse(xml_file)
    root = tree.getroot()
    namespace = {'capec': 'http://capec.mitre.org/capec-3'}
    get_child_info(root, 'capec:Attack_Patterns', namespace)  # Replace 'capec:Attack_Patterns' with the desired child tag

    # Extract and save a specific attack pattern by ID
    pattern_id = '1'  # Replace with the desired ID
    extract_attack_pattern(xml_file, pattern_id, namespace)
