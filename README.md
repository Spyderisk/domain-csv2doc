# csv2doc

csv2dec is a tool to automatically generate documentation for a given Spyderisk
domain model. It takes the domain model in csv format, creates a folder
containing the generated data, and then runs a locally accessible user interface for
that documentation.

A detailed breakdown of the code can be found in [DEVELOPMENT.md](./DEVELOPMENT.md).
It is recommended that you review this in full, before making any major changes to the tool.

# Running the tool

## graphviz

Graphviz must be installed on the device for the tool to run. To check if it is
installed, run the following command in the console.

```shell
dot -v
```

If it gives a response starting with

```shell
dot - graphviz version X.XX.X
```

Then graphviz is already installed.

### graphviz installation

If graphviz is not installed, follow the installation instructions for your system.
They can be found at the following url: <https://graphviz.org/download/>

## configuration

Amend the configuration.txt document to make the following changes to the
tool's behaviour.

### toggling reduced pattern generation

By default, the tool will generate a vizual representation for all patterns
present in the csvs provided. To reduce this to a preselected list, edit the
following lines in configuration.txt, leaving no spaces or empty lines.

- [n, no, f, false] indicate that all patterns will be  generated.
- [y, yes, t, true] indicate that only the selected patterns will be generated.
- Selections are not case-sensitive.

```
# Toggle whether to generate reduced number of patterns (y/n)
[Reduced]
reduced = yes
```

### listing specific patterns to generate

If the reduced pattern generation has been toggled on, then a list of which
patterns to generate must be provided. This should be a list of the uri of
each pattern to be generated. Edit the following lines in configuration.txt,
leaving no spaces or empty lines.

In any case where a construction pattern or threat pattern are requested,
the associated matching patterns must also be requested.

```
# List all packages you wish to generate
# In addition, list the full name of any specific Patterns you wish to generate
# Put each item on a separate line, with at least one space from the left
# Including the prefix package# for packages, and domain# on specific patterns.
# If you have specifically selected Construction Pattern(s) or Threat Pattern(s),
#   and the associated Matching Pattern(s) are not generated currently or previously,
#   then the node positioning will be uncontrolled.
reduced_list =
    package#ProcessComms
    domain#CCSCtSg+tSg
    domain#CCSCVC+ch
    domain#CCSCvI+vI
    domain#CCSCvLS+vLS
    domain#CDPDPS+DP
```

### toggling previous folder deletion

By default, the tool will overwrite any DomainModelDocumentation folder present
in the target directory. To avoid this, and only overwrite generated patterns,
edit the following lines in configuration.txt, leaving no spaces or empty lines.

- [n, no, f, false] indicate that any previous folder will be updated.
- [y, yes, t, true] indicate that any previous folder will be deleted and refreshed.
- Selections are not case-sensitive.

```
# Toggle whether to delete previous folder (y/n)
# Doing so removes any obsolete patterns
---
y
---
```

### recommended configurations

When running the tool for the first time, a full generation is recommended.

When doing a full generation, use folder deletion to prevent clashes.

When only generating specific packages or patterns, for example due to an
error generating those patterns, deactivate folder deletion so that other
previously generated patterns are kept.


## Setup python virtual environment

Although the csv2doc tool can be installed globally, the preferred way to run
it, is via python virtual environment. A global installation might expose
various python libraries API incompatibilities.

```shell
python3 -m venv env
```

If you choose to install it

### activate venv (optional)

```
source ./env/bin/activate
```

On Windows use `.\env\Scripts\activate.bat` instead.

### install required libs

```shell
pip install -r requirements.txt
```

## Tool setup:

Before running the tool, the full domain model csvs must be in one folder
on the local computer. You will need to get the relative or absolute filepath
for that folder to use as input.

Run the tool with:

```shell
python3 generate_and_show.py csvs_location
```

## deactivate virtual env (optional)

```shell
deactivate
```

## check the report

After completing its run, the tool will update the report.txt document.
The lowest entry on this document is the most recent.
Check this entry for information on any errors noticed by the tool.

# Using the Output

## accessing html

After the tool has been run completely at least once, a new directory will be added to the
csv2doc directory named 'build'.
If that folder is not there, the tool may not have completed a full run.
Navigate to the 'build' directory inside the csv2doc main directory.
Ignoring the other directories, open the 'index.html' file using a browser.

### navigation by links

Immediately after opening the above html, you will be on the home screen.
From here, the list of links are named after each group of object types.
For example, to see a Misbehaviour, click on the link named 'Misbehaviours'.
This leads to a list of all objects of that type.
These objects are grouped by their packages.

For Root, Matching, Construction and Threat patterns, there is a list of preview
images for each pattern.
For the others, there is a list of the names of each item.
Either way, it can be clicked to follow through to the information page on that item.

### navigation bar

At the top of the window, the navigation bar can be used to quickly navigate to any of the
view lists from any screen.

In addition, there is a search box on the right of the navigation bar.
This can be used to immediately go to a page based on certain information.

To go to a specific known page, enter the full name of the page and press enter.
To find a page based on parts of its description, list as many words from the description as
you can, seperated by spaces, and then press enter.
The search box also allows the use of `*` as a wildcard. You can use `*` in place of known text.
For example, if you know that a pattern ends with `Training`, you can put `*Training`` and press enter.

### navigation by url

To view a specific object by url, cut the filepath in the url bar back to ".../build/".
Then, append the type of item you wish to view, a forward slash, and the exact name
of the item.
If you wish to see the list of items, put the word "list" in place of the item name.
For example, if you wished to see the threat pattern H.M.HAC.4,
you would put the following into the URL bar:

```
.../csv2doc/build/threat/H.M.HAC.4
```

The exact names of each type are:

```
root, matching, construction, threat, misbehaviour, csg, control, asset, package
```

### see item

A view page for an item contains a set of information about itself.
Each has at least a description about itself.
They also have a series of links to the view page of other relevant groups and patterns.
Whilst viewing a pattern with a main image, you can hover the cursor over nodes and
relations in that image to summon a tooltip for more information.

## output folders

If you will be directly viewing the output folders, rather than the interactive
html files, you should ensure the program has completed before continuing.
Please be aware that this method of viewing the outputs is not advised for casual use,
and should primarily be used for development use.

### navigate

Navigate to the folder in which you have installed csv2doc. Enter the folder "static".
Select a directory based on the type of information you are looking to find.
For example, if looking for a Matching Pattern, open the 'Matching' folder.
The generated patterns of this type are listed here.

### see pattern

Root Patterns, Matching Patterns, Construction Patterns and Threat Patterns generate
with a visual representation. These are svg files labelled with the pattern's name.
Whilst viewing an svg, each node and relation has a tooltip which you can hover over
to learn more.

### see information

Each object also has an info file.
This is a kind of text file which lists other patterns that are related to it.
For example, the info file for a misbehaviour has a list of the threats that cause it.