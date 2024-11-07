<h2>Attack Tree Generation from System Diagrams</h2>

<p>This repository provides scripts to transform system diagrams into attack trees by extracting key information, aligning it with the <a href="https://capec.mitre.org/">CAPEC (Common Attack Pattern Enumeration and Classification) database</a>, and identifying relevant attack patterns, weaknesses, and execution flow steps. The resulting XML file can be imported into ADTool, enabling visualization of the generated attack trees.</p>

<p>This project was completed by <strong>Reza Foratikashani</strong> as part of a Master’s project on enhancing human collaboration with data and autonomous systems at Swansea University's Computational Foundry, funded by EPSRC. The research was supervised by <strong>Dr Nga Hoang Nguyen</strong>, <strong>Dr Nicholas Micallef</strong>, and <strong>Professor Siraj Shaikh</strong>.</p>

<h2>File Overview</h2>

<ul>
    <li><strong><code>attack_execution_extractor.py</code></strong>: Main script to execute the search for relevant attacks for a specific weakness and extract execution flow for each attack.</li>
    <li><strong><code>detailed_weakness_extraction.py</code></strong>: Full-detail extractor for each weakness.</li>
    <li><strong><code>ttool_weakness_extractor.py</code></strong>: Script to extract weaknesses from system diagram XML files.</li>
</ul>

<h2>Dependencies</h2>

<h3>Required</h3>
<ul>
    <li><a href="https://www.python.org">Python 3</a></li>
</ul>

<h3>Optional</h3>
<ul>
    <li><a href="https://satoss.uni.lu/members/piotr/adtool/">ADTool2</a> for attack tree visualization.</li>
</ul>

<h2>Installation</h2>

<ol>
    <li>Install all required dependencies.</li>
    <li><em>(Optional)</em> Install ADTool2 to create and view attack tree templates.</li>
</ol>

<h2>Usage</h2>

<ol>
    <li>Run <code>ttool_weakness_extractor.py</code> to extract weaknesses from system diagram XML files.</li>
    <li>The script will generate an XML file compatible with ADTool, which can be imported for attack tree visualization.</li>
</ol>
