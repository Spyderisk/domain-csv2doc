# Development

This document attempts to describe, in broad strokes, how the program
functions. This should be treated as an aide to understanding the function of
the code, or to find bugs, but is not user documentation. 
User documentation is in the [README.md](./README.md).

## Directory Structure

### Initial Folder Structure

Before being run, the tool is initially structured as follows.

```
+ - - running
|      + - - graphviz_styles
|      |      + - - colour_basic.py
|      |      + - - node_positioning.py
|      + - - freeze_flask.py
|      + - - generate_patterns.py
+ - - templates
|      + - - navigation
|      |      + - - asset_list.html
|      |      + - - construction_by_priority.html
|      |      + - - construction_list.html
|      |      + - - control_list.html
|      |      + - - csg_list.html
|      |      + - - home.html
|      |      + - - matching_list.html
|      |      + - - misbehaviour_list.html
|      |      + - - package_list.html
|      |      + - - root_list.html
|      |      + - - threat_list.html
|      + - - pattern
|      |      + - - asset.html
|      |      + - - construction.html
|      |      + - - control.html
|      |      + - - csg.html
|      |      + - - matching.html
|      |      + - - misbehaviour.html
|      |      + - - package.html
|      |      + - - root.html
|      |      + - - threat.html
|      + - - base.html
|      + - - custom.css
|      + - - home.html
+ - - configuration.txt
+ - - create_html.py
+ - - generate_and_show.py
+ - - README.md
+ - - requirements.txt
```

Whilst being run for the first time, the directories ‘static’ and ‘build’ will
be added to the main directory. Static will contain the generated patterns and
info files. Build will contain the static . Once completed, the tool will also
add a ‘report.txt’ to the directory, which contains information on each time
the tool has been run.

## Code Structure

### generate_and_show.py

The part of the code that the user calls. Checks the user’s input and uses it
to call the rest of the code. Calls on generate_patterns.py and create_html.py.

### generate_patterns.py

Does the actual generation of images and extraction of information from the csv
files. Also responsible for the folder structure that houses those images and
info files. Calls on colour_basic.py and node_positioning.py.

### colour_basic.py

Contains the functions responsible for adding styled nodes and styled relations
to the graph. This includes adding labels by using intermediate nodes, as well
as adding tooltips.

### node_positioning.py

Manages the positioning of nodes for the forced positioning graphs.

### create_html.py

Creates the foundation for a server that acts as a user interface to display
the generated patterns. Calls on all each of the html templates in the
templates directory.

### freeze_flask.py

Converts the flask server into a series of static html files. Calls on create_html.py.

### templates

A series of html documents to either manage navigation or present the full
information of specific patterns. They use jinja2 to display the specific
information.

## Step by step code walkthrough

### generate_and_show.py

The user’s input is checked. It looks to check that the directory exists, and
that it contains at least the root pattern csv.

If the input is invalid, the program will print an error, and then terminate.
Otherwise, it will then make a call to generate_patterns.py to generate the
patterns, and then to freeze_flask.py to create the static html.

### generate_patterns.py

The configuration file is checked. Whether to generate a reduced list, what
patterns are requested, and whether to create a new directory is all extracted
to variables. If no patterns are requested to be generated, pattern generation
is skipped entirely.

The target folder structure is deleted if requested, and created if required.

A new info file is created for each misbehaviour, control, and control
strategy, containing its own description, as taken from the csv files. These
are added to with other information relevant to that entry.

The root csv is loaded into a pandas dataframe. For each pattern, two new
graphs are created. One is a dot graph, and one is an fdp graph. All nodes and
relations are added to both, and both are then added to the dictionaries
‘root_graphs_setup’ and ‘root_graphs_final’ respectively. The dot graph is
generated and added to the target directory. An info file is created for the
pattern here.

The matching pattern csv is loaded into a pandas data frame. For each pattern,
the associated dot and fdp root patterns are called from the dictionaries and
copies are made. All nodes and relations are added to both copies. The fdp
graph is added to the dictionary ‘matching_graphs_final’. The dot graph is
generated and added to the target directory. A command is called to create a
node position file for the Matching Pattern. An info file is created for the
pattern here.

For each pattern in the matching graphs dictionary, the node position is
extracted from the node position file and added to the graph. The fdp graph is
then generated and added to the target directory, replacing the previously
generated dot graph.

For each construction pattern, the associated matching pattern is copied from
the dictionary. All nodes and relations are added to the fdp graph. The fdp
graph is then generated and added to the target directory. An info file is
created for the pattern here. This is repeated for Threat Patterns.

Throughout the process, errors and issues are added to list variables. These
are then added to a report.txt file along with the completion time of the
pattern generation.

### create_html.py

The required csv files are loaded into dataframes and saved to variables.

The descriptions of each of the patterns listed in the csvs are added to a dictionary of descriptions.

The priority of each of the construction patterns is extracted from the
construction pattern dataframe and added to a dictionary of priorities.

The description of each package is extracted from the packages dataframe and added to a dictionary.

The functions tagged with '@app.route’ add to the ‘app’ function which can be
used to run the server. It is not used here but is provided to freeze_flask.py.

### freeze_flask.py

The ‘custom.css’ file is copied from the ‘templates’ directory to the ‘static’
directory, so that it is available even if the folder was deleted for a fresh
setup.

The ‘app’ function is imported from create_html.py, and added to a Freezer object.

A call is made to create_html.py to set up the app function in preparation for
freezing. The ‘build’ folder is created in the main directory, holding all of
the created html files.

The functions tagged with ‘freezer.register_generator’ add to the freezer item.
Each gives a set of addresses that need to be frozen in the static html.
