import xml.etree.ElementTree as ET

def extract_weaknesses(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    namespace = {
        '': 'http://telecom-paris.fr/TURTLE'
    }
    
    weaknesses = {}

    for component in root.findall(".//COMPONENT"):
        component_id = component.get('id')
        component_name = component.find('infoparam').get('value')
        weaknesses[component_name] = []

        for attribute in component.findall(".//Attribute"):
            weakness_id = attribute.get('id')
            value = attribute.get('value')
            weaknesses[component_name].append((weakness_id, value))

    return weaknesses

def main():
    xml_file = 'C:/dissertation/TTool/test/ECU connections_test0.xml'  # Replace with the path to your XML file
    weaknesses = extract_weaknesses(xml_file)
    
    for component_name, attrs in weaknesses.items():
        print(f"Component: {component_name}")
        for weakness_id, value in attrs:
            print(f"  Weakness name: {weakness_id}, Is it exploited: {value}")

if __name__ == "__main__":
    main()
