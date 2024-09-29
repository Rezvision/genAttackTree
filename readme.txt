# Description
This repository contains scripts designed to transform system diagrams into attack trees by automatically extracting information, matching it with the CAPEC (Common Attack Pattern Enumeration and Classification) database, and identifying attack patterns, weaknesses, and execution flow steps. The resulting XML file can then be imported into ADTool to visualize the attack trees. This work was completed as part of a Masters project on enhancing human collaboration with data and autonomous systems at Swansea University's Computational Foundry, funded by EPSRC.

# File Overview
main.py: The main script to run the entire process.
treelib-mini: Template library for the mini example.
treelib-full: Template library for the full example.
treelib-sd: Template library for the StreetDrone example.
Dependencies
# Mandatory:
Python 3 (https://www.python.org)
# Optional:
ADTool2 (https://satoss.uni.lu/members/piotr/adtool/)
# Installation
Install all required dependencies:
If you want to visualize attack trees, you can use the optional ADTool2 for creating attack tree templates and viewing the output.

# Usage
Simply run the main.py script to start the process. The final output will generate an XML file that can be imported into ADTool for visualization.

