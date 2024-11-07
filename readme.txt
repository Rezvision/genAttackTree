# Attack Tree Generation from System Diagrams

This repository provides scripts to transform system diagrams into attack trees by extracting key information, aligning it with the [CAPEC (Common Attack Pattern Enumeration and Classification) database](https://capec.mitre.org/), and identifying relevant attack patterns, weaknesses, and execution flow steps. The resulting XML file can be imported into ADTool, enabling visualization of the generated attack trees.

This project was completed by **Reza Foratikashani** as part of a Master’s project on enhancing human collaboration with data and autonomous systems at Swansea University's Computational Foundry, funded by EPSRC. The research was supervised by **Dr Nga Hoang Nguyen**, **Dr Nicholas Micallef**, and **Professor Siraj Shaikh**.

## File Overview

- **`attack_execution_extractor.py`**: Main script to execute the search for relevant attacks for a specific weakness and extract execution flow for each attack.
- **`detailed_weakness_extraction.py`**: Full-detail extractor for each weakness.
- **`ttool_weakness_extractor.py`**: Script to extract weaknesses from system diagram XML files.

## Dependencies

### Required
- [Python 3](https://www.python.org)

### Optional
- [ADTool2](https://satoss.uni.lu/members/piotr/adtool/) for attack tree visualization.

## Installation

1. Install all required dependencies.
2. *(Optional)* Install ADTool2 to create and view attack tree templates.

## Usage

1. Run `ttool_weakness_extractor.py` to extract weaknesses from system diagram XML files.
2. The script will generate an XML file compatible with ADTool, which can be imported for attack tree visualization.
