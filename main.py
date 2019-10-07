import parseTree
import parseModel
import genAT
import xml.etree.ElementTree as ET
import os

# two default examples
MINI = "mini"
FULL = "full"

def exportToXml(t, example):
    root = ET.Element("sandtree")
    root.append(t.toXml())
    ET.ElementTree(root).write(open("output-" + example + ".xml", "wb"))

def main(example):
    print("Loading input model ...")
    Model = parseModel.parseModel("model-" + example + ".inp")

    LibraryFolder = "treelib-" + example
    # XMLLibrary = ["Attack.xml", "Eavesdrop.xml", "EavesdropFrom.xml", "Compromise.xml", "CompromiseFromTo.xml"]
    XMLLibrary = [os.path.join(LibraryFolder, f) for f in os.listdir(LibraryFolder) if f.endswith(".xml") and os.path.isfile(os.path.join(LibraryFolder, f))]
    if example=="mini":
        XMLRoot = os.path.join(LibraryFolder, "CompromiseECM.xml")
    elif example=="full":
        XMLRoot = os.path.join(LibraryFolder, "Attack.xml")
    RootTree = 0
    Library = []

    print("Loading template library ...")

    for xml in XMLLibrary:
        print("Parsing file : " + xml + " ... ")
        r = parseTree.parseXmlTree(xml, Model)
        if xml == XMLRoot:
            RootTree = r
        Library.append(r)


    print("Generating attack tree ...")
    t = genAT.genAT(Library, RootTree, Model)

    print("Tree size: " + str(t.size()))
    print("Tree height: " + str(t.height()))

    exportToXml(t, example)

    print("Output exported")

#main(MINI)
#main(FULL)
import cProfile
#cProfile.run('main(MINI)' )
cProfile.run('main(FULL)' )

