########################################################################
#
# (c) University of Southampton IT Innovation Centre, 2022
#
# Copyright in this software belongs to University of Southampton
# IT Innovation Centre of University Road, Southampton, SO17 1BJ, UK.
#
# This software may not be used, sold, licensed, transferred, copied
# or reproduced in whole or in part in any manner or form or in or
# on any media by any person other than in accordance with the terms
# of the Licence Agreement supplied with the software, or otherwise
# without the prior written consent of the copyright owners.
#
# This software is distributed WITHOUT ANY WARRANTY, without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
# PURPOSE, except where stated in the Licence Agreement supplied with
# the software.
#
#      Created By :            Phill Rucci
#      Created Date :          2022-08-08
#      Created for Project :   FogProtect
#
########################################################################

import shutil
import copy
import configparser
from datetime import datetime

from running.graphviz_styles.node_positioning import *
from running.graphviz_styles.colour_basic import *
import pandas as pd
from graphviz import Digraph
import sys
import os
import shutil

# Running Values
csvs_location = ''
icons_location = ''
target_location = os.path.join(os.path.dirname(__file__), '..', 'static')
root_graphs_setup = {}
root_graphs_final = {}
matching_graphs_final = {}

# Configuration
config = configparser.ConfigParser()
config.read("config.ini")

try:
    generate_reduced = config['Reduced']['reduced'].startswith(('y', 'Y', 't', 'T'))
    folder_deletion_toggle = True
    reduced_list = config['Reduced']['reduced_list'].split('\n')
except Exception as config_key_error:
    try:
        config.read("../config.ini")
        generate_reduced = config['Reduced']['reduced'].startswith(('y', 'Y', 't', 'T'))
        folder_deletion_toggle = True
        reduced_list = config['Reduced']['reduced_list'].split('\n')
    except Exception as config_read_error:
        print("Error reading config.ini")
        print("config.ini needs to exist within root folder.")
        print("Ensure structure is ")
        exit()


# List of generation errors
error_list = []
unassigned_list = []
blank_list = []


def set_csv_location(user_input):
    global csvs_location
    csvs_location = os.path.join(user_input, 'csv')

def set_images_location(user_input):
    global icons_location
    icons_location = os.path.join(user_input, 'icons')


def check_configuration():
    # Access global values
    global folder_deletion_toggle

    # Check generate reduced toggle
    if generate_reduced:
        # If reduced pattern, but no reduced list return false (meaning, generate no patterns)
        if len(reduced_list) == 1 and reduced_list[0] == '':
            print('No patterns requested to generate.')
            print('Going immediately to UI representation.')
            return False

        if reduced_list[0] == '':
            reduced_list.remove('')

        print('Generating Reduced List')
        folder_deletion_toggle = False  # Prevent folder deletion to allow
    return True


def setup_folder_structure():
    # If folder already exists, and delete toggle is active, delete it
    try:
        if os.path.isdir(target_location) and folder_deletion_toggle:
            shutil.rmtree(target_location, ignore_errors=False, onerror=None)
    except Exception as folder_check_error:
        print('Error: ' + str(folder_check_error))
        exit()

    # If folder does not exist (including if it has been deleted), create structure
    if not os.path.isdir(target_location):
        os.mkdir(target_location)

        os.mkdir(os.path.join(target_location, 'Images'))

        os.mkdir(os.path.join(target_location, 'Root'))
        os.mkdir(os.path.join(target_location, 'Matching'))
        os.mkdir(os.path.join(target_location, 'Construction'))
        os.mkdir(os.path.join(target_location, 'Threat'))
        os.mkdir(os.path.join(target_location, 'Misbehaviour'))
        os.mkdir(os.path.join(target_location, 'Control Strategy'))
        os.mkdir(os.path.join(target_location, 'Controls'))
        os.mkdir(os.path.join(target_location, 'Role'))
        os.mkdir(os.path.join(target_location, 'TWA'))
        os.mkdir(os.path.join(target_location, 'Asset'))
    
    # Copy images into static folder
    files = os.listdir(icons_location)
    for file in files:
        shutil.copy2(os.path.join(icons_location, file), os.path.join(target_location, 'Images'))


def create_info_file(file, string):
    with open(file + '.info', 'w') as f:
        f.write(string)


def add_to_info_file(type_in, uri, string):
    file = os.path.join(target_location, type_in, uri)

    with open(file + '.info', 'a') as f:
        f.write(string)


def extract_role_info():
    # Frame of all roles
    rdf = pd.read_csv(os.path.join(csvs_location, 'Role.csv'))

    # If example line present, remove
    if 'domain#000000' in rdf['URI'].tolist():
        rdf.drop(0, axis=0, inplace=True)

    # For each role, create an info page
    for index, row in rdf.iterrows():
        # Check package
        package = row['package']
        if package == 'package#Unassigned':
            unassigned_list.append('Role ' + row['URI'])
        elif package != package:
            blank_list.append('Role ' + row['URI'])

        create_info_file(os.path.join(target_location, 'Role', row['URI'][7:]), '')


def extract_misbehaviour_info():
    # Frame of all misbehaviour
    mbf = pd.read_csv(os.path.join(csvs_location, 'Misbehaviour.csv'))
    twis = pd.read_csv(os.path.join(csvs_location, 'TWIS.csv'))
    misbehaviour_locations = pd.read_csv(os.path.join(csvs_location, 'MisbehaviourLocations.csv'))
    threat_sec = pd.read_csv(os.path.join(csvs_location, 'ThreatSEC.csv'))
    twas = pd.read_csv(os.path.join(csvs_location, 'TWAS.csv'))
    threat_entry_points = pd.read_csv(os.path.join(csvs_location, 'ThreatEntryPoints.csv'))

    # If example line present, remove
    if 'domain#000000' in mbf['URI'].tolist():
        mbf.drop(0, axis=0, inplace=True)

    # Create dictionary to hold info until creating info files
    misbehaviours = {}

    # Create info file for each misbehaviour
    for index, row in mbf.iterrows():
        # Check package
        package = row['package']
        if package == 'package#Unassigned':
            unassigned_list.append('Misbehaviour ' + row['URI'])
        elif package != package:
            blank_list.append('Misbehaviour ' + row['URI'])

        misbehaviours[row['URI']] = []
    
    # Add twa to each misbehaviour if they have one
    for index, row in twis.iterrows():
        #TODO: remove this if statement (makes the code work with old version of domain model)
        if row['affectedBy'] in misbehaviours:
            misbehaviours[row['affectedBy']].append('TWA:' + row['affects'][7:] + '\n')
    
    # Create dataframe connecting misbehaviours to threats via associated trustworthiness attribute
    twas = twas.drop(columns=['locatedAt', 'package'])
    twaThreats = pd.merge(threat_entry_points, twas, left_on='hasEntryPoint', right_on='URI')
    twaThreats = twaThreats.drop(columns=['hasEntryPoint', 'URI_y'])
    twaMisbehaviour = twis.drop(columns=['URI', 'label'])
    twaThreats = pd.merge(twaThreats, twaMisbehaviour, left_on='hasTrustworthinessAttribute', right_on='affects')
    twaThreats = twaThreats.drop(columns=['affects', 'hasTrustworthinessAttribute'])
    twaThreats = twaThreats.drop_duplicates()
    twaThreats = twaThreats.rename(columns={"URI_x": "threat", "affectedBy": "misbehaviour"})
    # Add threats caused by twa
    for index, row in twaThreats.iterrows():
        misbehaviours[row['misbehaviour']].append('twaThreat:' + row['threat'][7:] + '\n')

    # Add misbehaviour set to each misbehaviour
    for index, row in misbehaviour_locations.iterrows():
        # Add asset to misbehaviour
        misbehaviours[row['URI']].append('Asset:' + row['metaLocatedAt'][7:] + '\n')
    
    # Add caused threats to misbehaviour
    for index, row in threat_sec.iterrows():
        misbehaviour = 'domain#' + row['hasSecondaryEffectCondition'].split('-')[1]
        # Add threat to misbehaviour
        misbehaviours[misbehaviour].append('ThreatCaused:' + row['URI'][7:] + '\n')

    # Create info files
    for item in misbehaviours:
        create_info_file(os.path.join(target_location, 'Misbehaviour', item[7:]), ''.join(misbehaviours[item]))


def extract_controls_info():
    # Frame of all controls
    csf = pd.read_csv(os.path.join(csvs_location, 'Control.csv'))
    control_sets = pd.read_csv(os.path.join(csvs_location, 'ControlSet.csv'))
    control_locations = pd.read_csv(os.path.join(csvs_location, 'ControlLocations.csv'))

    # If example line present, remove
    if 'domain#000000' in csf['URI'].tolist():
        csf.drop(0, axis=0, inplace=True)

    controls = {}

    # Create info file for each control
    for index, row in csf.iterrows():
        # Check package
        package = row['package']
        if package == 'package#Unassigned':
            unassigned_list.append('Control ' + row['URI'])
        elif package != package:
            blank_list.append('Control ' + row['URI'])
        
        controls[row['URI']] = []

    # # Add assets to controls
    for index, row in control_locations.iterrows():
        controls[row['URI']].append('Asset:' + row['metaLocatedAt'][7:] + '\n')

    # Add controls to each role
    for index, row in control_sets.iterrows():
        add_to_info_file('Role', row['locatedAt'][7:], 'Control:' + row['hasControl'][7:] + '\n')
    
    # Create info files
    for item in controls:
        create_info_file(os.path.join(target_location, 'Controls', item[7:]), ''.join(controls[item]))


def extract_control_strategy_info():
    # Frame of all Control Strategies
    csf = pd.read_csv(os.path.join(csvs_location, 'ControlStrategy.csv'))

    # Frame of all Controlled Threats
    control_block = pd.read_csv(os.path.join(csvs_location, 'ControlStrategyBlocks.csv'))
    control_mitigate = pd.read_csv(os.path.join(csvs_location, 'ControlStrategyMitigates.csv'))

    # Frame of all Control Sets
    controls = pd.read_csv(os.path.join(csvs_location, 'ControlStrategyControls.csv'))

    # Frame of all Triggered Threats
    control_triggers = pd.read_csv(os.path.join(csvs_location, 'ControlStrategyTriggers.csv'))

    # If example line present, remove
    if 'domain#000000' in csf['URI'].tolist():
        csf.drop(0, axis=0, inplace=True)

    # Create info file & add description for each strategy
    for index, row in csf.iterrows():
        strategy_info = []
        uri = row['URI']

        # Check package
        package = row['package']
        if package == 'package#Unassigned':
            unassigned_list.append('Control ' + uri)
        elif package != package:
            blank_list.append('Control ' + uri)

        # Get related frames
        related_blocks = control_block.loc[control_block['URI'] == uri]
        related_mitigates = control_mitigate.loc[control_mitigate['URI'] == uri]
        related_controls = controls.loc[controls['URI'] == uri]
        related_triggers = control_triggers.loc[control_triggers['URI'] == uri]

        # Add all blocked threats
        for ind in related_blocks.index:
            strategy_info.append('Blocked:' + related_blocks['blocks'][ind][7:] + '\n')

        # Add all mitigated threats
        for ind in related_mitigates.index:
            strategy_info.append('Mitigates:' + related_mitigates['mitigates'][ind][7:] + '\n')

        # Add list of used control sets, and the control for each set
        for ind in related_controls.index:
            optional = '-False'
            if "optional" in related_controls and related_controls['optional'][ind]:
                optional = '-True'

            strategy_info.append('ControlSet:' + related_controls['hasControlSet'][ind][7:] + optional + '\n')
            # Add control strategy to control's info
            add_to_info_file('Controls', related_controls['hasControlSet'][ind][10:].split('-')[0],
                             "ControlStrategy:" + row['URI'][7:] + optional + '\n')

        # Add list of triggered threats
        for ind in related_triggers.index:
            strategy_info.append('Triggers:' + related_triggers['triggers'][ind][7:] + '\n')

        # Create info file
        create_info_file(os.path.join(target_location, 'Control Strategy', uri[7:]), ''.join(strategy_info))


def needs_generation(uri, package):
    # Check if given uri or package needs to be generated
    if generate_reduced and not ((uri in reduced_list) or (package in reduced_list)):
        # If generate reduced toggle active, and neither uri nor package appear in reduced list, return false
        return False
    else:
        # Else return true
        return True


def generate_graph_if_required(file, graph, package):
    # Check if graph requires generating
    if needs_generation('domain#' + file.split('\\')[-1], package):
        write_graph_to_file(file, graph)


def write_graph_to_file(file, graph):
    try:
        # Create and save render to file
        graph.render(file, format='svg')
    except Exception as e:
        if str(e).startswith("failed to execute WindowsPath('dot'), make sure"):
            print('!!!___________________!!!')
            print('Check that graphviz has been installed on the local machine.')
            print('Run \'dot -v\' to check the installation.')
            print('If not installed, on Ubuntu run \'sudo apt install graphviz\'.')
            print('On windows run \'choco install graphviz\' on powershell as an administrator.')
            print('Other distributions of linux may have other install commands.')
            print('!!!___________________!!!')
            exit()

        # If rendering fails, add to error list
        uri = file.split('\\')[-1]
        error_list.append(uri + '   :   ' + str(e))


def extract_node_positions(file):
    # Create dictionary for node positions
    node_coordinates = {}

    # If file exists
    if os.path.exists(file):
        # Open given pos file, and read in all nodes & edges
        with open(file, 'r') as f:
            pos_contents = f.read()[10:-3].replace('\t', '').replace('\n', '').split(';')[2:]

            for item in pos_contents:
                # Filter out edges
                if not ('->' in item or 'pos="e' in item) and ('pos="' in item):
                    name = item.split('[')[0]  # Get name
                    position = item.split('pos="')[1].split('"')[0].split(',')  # Get position
                    node_coordinates[name] = [float(position[0]), float(position[1])]  # Add name & position to dict

    return node_coordinates


def generate_root_patterns():
    # Frame of all Root patterns
    rpf = pd.read_csv(os.path.join(csvs_location, 'RootPattern.csv'))

    # Frame of all nodes
    root_nodes = pd.read_csv(os.path.join(csvs_location, 'RootPatternNodes.csv'))
    all_nodes = pd.read_csv(os.path.join(csvs_location, 'Node.csv'))
    nodes = pd.merge(root_nodes, all_nodes, left_on='hasNode', right_on='URI')

    # Frame of all links
    root_links = pd.read_csv(os.path.join(csvs_location, 'RootPatternLinks.csv'))
    role_links = pd.read_csv(os.path.join(csvs_location, 'RoleLink.csv'))
    links = pd.merge(root_links, role_links, left_on='hasLink', right_on='URI')

    # Target folder
    target = os.path.join(target_location, 'Root')

    # If example line present, remove
    if 'domain#000000' in rpf['URI'].tolist():
        rpf.drop(0, axis=0, inplace=True)

    # Create all
    for index, row in rpf.iterrows():
        # Get URI
        uri = row['URI']

        # Check package
        package = row['package']
        if package == 'package#Unassigned':
            unassigned_list.append('Root ' + uri)
        elif package != package:
            blank_list.append('Root ' + uri)

        # Create setup_graph
        setup_graph = Digraph('Diagram')
        setup_graph.attr(nodesep='1', ranksep='1', rankdir='LR')  # , size='25.7,8.3!')

        # Create final_graph
        final_graph = Digraph('Diagram', engine='fdp')
        final_graph.attr(splines='polyline', overlap='scale')  # , size='25.7,8.3!')

        # Select frames
        related_nodes = nodes.loc[nodes['URI_x'] == uri]
        related_links = links.loc[links['URI_x'] == uri]

        # Add all nodes
        for ind in related_nodes.index:
            root_n(setup_graph, related_nodes['hasRole'][ind], related_nodes['metaHasAsset'][ind])
            root_n(final_graph, related_nodes['hasRole'][ind], related_nodes['metaHasAsset'][ind])

        # Add all relations
        for ind in related_links.index:
            stan_e(setup_graph, related_links['linksFrom'][ind], related_links['linksTo'][ind],
                   related_links['linkType'][ind])
            stan_e(final_graph, related_links['linksFrom'][ind], related_links['linksTo'][ind],
                   related_links['linkType'][ind])

        # Render setup_graph to folder
        file_location = os.path.join(target, uri[7:])
        generate_graph_if_required(file_location, setup_graph, package)
        root_graphs_setup[uri] = setup_graph

        # Save final graph to dictionary
        root_graphs_final[uri] = final_graph

        # Write info to info file
        create_info_file(file_location, '')


def generate_initial_matching_patterns():
    # Frame of all matching patterns
    mpf = pd.read_csv(os.path.join(csvs_location, 'MatchingPattern.csv'))

    # Frame of the roots
    roots = pd.read_csv(os.path.join(csvs_location, 'RootPattern.csv'))

    # Frame of all nodes
    matching_nodes = pd.read_csv(os.path.join(csvs_location, 'MatchingPatternNodes.csv'))
    all_nodes = pd.read_csv(os.path.join(csvs_location, 'Node.csv'))
    nodes = pd.merge(matching_nodes, all_nodes, left_on='hasNode', right_on='URI')

    # Frame of all distinct nodes
    matching_dng = pd.read_csv(os.path.join(csvs_location, 'MatchingPatternDNG.csv'))
    distinct = pd.read_csv(os.path.join(csvs_location, 'DistinctNodeGroupNodes.csv'))

    # Frame of all links
    matching_links = pd.read_csv(os.path.join(csvs_location, 'MatchingPatternLinks.csv'))
    role_links = pd.read_csv(os.path.join(csvs_location, 'RoleLink.csv'))
    links = pd.merge(matching_links, role_links, left_on='hasLink', right_on='URI')

    # Target folder
    target = os.path.join(target_location, 'Matching')

    # If example line present, remove
    if 'domain#000000' in mpf['URI'].tolist():
        mpf.drop(0, axis=0, inplace=True)

    if "sufficientNode" in matching_nodes:
        population = True
    else:
        population = False

    for index, row in mpf.iterrows():
        # Get URI
        uri = row['URI']
        package = roots.loc[roots['URI'] == row['hasRootPattern']].iloc[0]['package']

        # Check package
        if package == 'package#Unassigned':
            unassigned_list.append('Matching ' + uri)
        elif package != package:
            blank_list.append('Matching ' + uri)

        # Get setup_graph
        setup_graph = copy.deepcopy(root_graphs_setup[row['hasRootPattern']])
        final_graph = copy.deepcopy(root_graphs_final[row['hasRootPattern']])

        # Add pattern info
        add_to_info_file('Root', row['hasRootPattern'][7:], uri[7:] + '\n')
        pattern_info = row['hasRootPattern'][7:] + '\n'

        # Select Frames
        related_nodes = nodes.loc[nodes['URI_x'] == uri]
        related_links = links.loc[links['URI_x'] == uri]
        related_dng = matching_dng.loc[matching_dng['URI'] == uri]

        # Add matching Nodes depending on population
        if population:
            for ind in related_nodes.index:
                # Name node
                name_node(setup_graph, related_nodes['hasRole'][ind], related_nodes['metaHasAsset'][ind])
                name_node(final_graph, related_nodes['hasRole'][ind], related_nodes['metaHasAsset'][ind])

                # Style node
                if related_nodes['mandatoryNode'][ind] and related_nodes['sufficientNode'][ind]:
                    suf_n(setup_graph, related_nodes['hasRole'][ind])
                    suf_n(final_graph, related_nodes['hasRole'][ind])
                elif related_nodes['mandatoryNode'][ind]:
                    nec_n(setup_graph, related_nodes['hasRole'][ind])
                    nec_n(final_graph, related_nodes['hasRole'][ind])
                elif related_nodes['prohibitedNode'][ind]:
                    prohibited_n(setup_graph, related_nodes['hasRole'][ind])
                    prohibited_n(final_graph, related_nodes['hasRole'][ind])
                else:
                    opt_n(setup_graph, related_nodes['hasRole'][ind])
                    opt_n(final_graph, related_nodes['hasRole'][ind])
        else:
            for ind in related_nodes.index:
                # Name node
                name_node(setup_graph, related_nodes['hasRole'][ind], related_nodes['metaHasAsset'][ind])
                name_node(final_graph, related_nodes['hasRole'][ind], related_nodes['metaHasAsset'][ind])

                # Style node
                if related_nodes['mandatoryNode'][ind]:
                    man_n(setup_graph, related_nodes['hasRole'][ind])
                    man_n(final_graph, related_nodes['hasRole'][ind])
                elif related_nodes['prohibitedNode'][ind]:
                    prohibited_n(setup_graph, related_nodes['hasRole'][ind])
                    prohibited_n(final_graph, related_nodes['hasRole'][ind])
                else:
                    opt_n(setup_graph, related_nodes['hasRole'][ind])
                    opt_n(final_graph, related_nodes['hasRole'][ind])

        # Add distinct relations
        for ind in related_dng.index:
            # get related distinct node groups
            related_distinct = distinct.loc[distinct['URI'] == related_dng['hasDistinctNodeGroup'][ind]]
            dist_e(setup_graph, related_distinct.iloc[0]['hasNode'], related_distinct.iloc[1]['hasNode'])
            dist_e(final_graph, related_distinct.iloc[0]['hasNode'], related_distinct.iloc[1]['hasNode'])

        # Add matching Relations
        for ind in related_links.index:
            if related_links['prohibited'][ind]:
                prohibited_e(setup_graph, related_links['linksFrom'][ind], related_links['linksTo'][ind],
                             related_links['linkType'][ind])
                prohibited_e(final_graph, related_links['linksFrom'][ind], related_links['linksTo'][ind],
                             related_links['linkType'][ind])
            else:
                stan_e(setup_graph, related_links['linksFrom'][ind], related_links['linksTo'][ind],
                       related_links['linkType'][ind])
                stan_e(final_graph, related_links['linksFrom'][ind], related_links['linksTo'][ind],
                       related_links['linkType'][ind])

        # Render setup_graph to folder
        file_location = os.path.join(target, uri[7:])
        generate_graph_if_required(file_location, setup_graph, package)

        # Save to graph dictionary
        matching_graphs_final[uri] = final_graph

        # If graph needs generation, create pos documents and save to graph directory
        if needs_generation(uri, package):
            os.popen('dot "' + file_location + '" > "' + file_location + '.pos"')

        # Save info to file
        create_info_file(os.path.join(target_location, 'Matching', uri[7:]), pattern_info)


def generate_final_matching_patterns():
    # Get frame of all matching patterns
    mpf = pd.read_csv(os.path.join(csvs_location, 'MatchingPattern.csv'))

    # Target folder
    target = os.path.join(target_location, 'Matching')

    # If example line present, remove
    if 'domain#000000' in matching_graphs_final:
        matching_graphs_final.pop('domain#000000')

    # Create all
    for uri in matching_graphs_final:
        # Determine package
        package = mpf.loc[mpf['URI'] == uri].iloc[0]['package']

        # Create graph & select frames
        graph = matching_graphs_final[uri]

        # Position Nodes
        position_doc = os.path.join(target_location, 'Matching', uri[7:] + '.pos')
        node_positions = extract_node_positions(position_doc)
        pos_nodes(graph, node_positions)

        # Render graph to folder
        file_location = os.path.join(target, uri[7:])
        generate_graph_if_required(file_location, graph, package)
        matching_graphs_final[uri] = graph


def generate_construction_patterns():
    # Frame of all Construction Patterns
    cpf = pd.read_csv(os.path.join(csvs_location, 'ConstructionPattern.csv'))

    # Frame of all Construction Nodes
    constructed_nodes = pd.read_csv(os.path.join(csvs_location, 'InferredNodeSetting.csv'))
    all_nodes = pd.read_csv(os.path.join(csvs_location, 'Node.csv'))
    nodes = pd.merge(constructed_nodes, all_nodes, left_on='hasNode', right_on='URI')

    # Frame of all Construction Relations
    constructed_relations = pd.read_csv(os.path.join(csvs_location, 'ConstructionPatternLinks.csv'))
    role_links = pd.read_csv(os.path.join(csvs_location, 'RoleLink.csv'))
    links = pd.merge(constructed_relations, role_links, left_on='hasInferredLink', right_on='URI')

    # Target folder
    target = os.path.join(target_location, 'Construction')

    # If example line present, remove
    if 'domain#000000' in cpf['URI'].tolist():
        cpf.drop(0, axis=0, inplace=True)

    # Create all
    for index, row in cpf.iterrows():
        # Get URI
        uri = row['URI']

        # Check package
        package = row['package']
        if package == 'package#Unassigned':
            unassigned_list.append('Construction ' + uri)
        elif package != package:
            blank_list.append('Construction ' + uri)

        # Get graph & select frames
        graph = copy.deepcopy(matching_graphs_final[row['hasMatchingPattern']])
        related_nodes = nodes.loc[nodes['inPattern'] == uri]
        related_links = links.loc[links['URI_x'] == uri]

        # Add pattern info
        add_to_info_file('Matching', row['hasMatchingPattern'][7:], 'Construction:' + uri[7:] + '\n')
        pattern_info = row['hasMatchingPattern'][7:] + '\n' + str(row['iterate']) + '\n'

        # Add constructed Nodes
        for ind in related_nodes.index:
            name_node(graph, related_nodes['hasRole'][ind], related_nodes['metaHasAsset'][ind])
            cons_n(graph, related_nodes['hasRole'][ind])

        # Add constructed Relations
        for ind in related_links.index:
            cons_e(graph, related_links['linksFrom'][ind], related_links['linksTo'][ind],
                   related_links['linkType'][ind])

        # Render graph to folder
        file_location = os.path.join(target, uri[7:])
        generate_graph_if_required(file_location, graph, package)

        # Save info to file
        create_info_file(file_location, pattern_info)


def generate_threat_patterns():
    # Frame of all Threat Patterns
    tpf = pd.read_csv(os.path.join(csvs_location, 'Threat.csv'))

    # List of all compliance packages
    compliance = []
    for index, row in pd.read_csv(os.path.join(csvs_location, 'ComplianceSet.csv')).iterrows():
        compliance.append(row['package'])

    # Frame of all triggering effects
    threat_sec = pd.read_csv(os.path.join(csvs_location, 'ThreatSEC.csv'))
    threat_effects = pd.read_csv(os.path.join(csvs_location, 'ThreatEffects.csv'))
    threat_triggers = pd.merge(threat_sec, threat_effects, left_on='hasSecondaryEffectCondition',
                               right_on='causesMisbehaviour')

    # Frame of all Misbehaviour
    misbehaviour_set = pd.read_csv(os.path.join(csvs_location, 'MisbehaviourSet.csv'))
    misbehaviour = pd.merge(threat_effects, misbehaviour_set, left_on='causesMisbehaviour', right_on='URI')

    # Frame of all Entry Points
    entry_points = pd.read_csv(os.path.join(csvs_location, 'ThreatEntryPoints.csv'))
    trustworthiness = pd.read_csv(os.path.join(csvs_location, 'TWAS.csv'))
    entries = pd.merge(entry_points, trustworthiness, left_on='hasEntryPoint', right_on='URI')

    # Frame of all Control Strategies
    control_block = pd.read_csv(os.path.join(csvs_location, 'ControlStrategyBlocks.csv'))
    control_mitigate = pd.read_csv(os.path.join(csvs_location, 'ControlStrategyMitigates.csv')).rename(
        columns={'mitigates': 'blocks'})
    control_strategies = pd.concat([control_block, control_mitigate])

    # Target folder
    target = os.path.join(target_location, 'Threat')

    # If example line present, remove
    if 'domain#000000' in tpf['URI'].tolist():
        tpf.drop(0, axis=0, inplace=True)

    for index, row in tpf.iterrows():
        # Get URI
        uri = row['URI']

        # Check package
        package = row['package']
        if package == 'package#Unassigned':
            unassigned_list.append('Threat ' + uri)
        elif package != package:
            blank_list.append('Threat ' + uri)

        # Get graph & select frames
        graph = copy.deepcopy(matching_graphs_final[row['appliesTo']])
        related_threat_sec = threat_sec.loc[threat_sec['URI'] == uri]
        related_threat_triggers = threat_triggers.loc[threat_triggers['URI_x'] == uri]
        related_triggered_threats = threat_triggers.loc[threat_triggers['URI_y'] == uri]
        related_misbehaviour = misbehaviour.loc[misbehaviour['URI_x'] == uri]
        related_entries = entries.loc[entries['URI_x'] == uri]
        related_control_strategies = control_strategies.loc[control_strategies['blocks'] == uri]

        # Add pattern info
        add_to_info_file('Matching', row['appliesTo'][7:], 'Threat:' + uri[7:] + '\n')
        pattern_info = [row['appliesTo'][7:] + '\n']

        # Gather Triggering Effects
        for ind in related_threat_triggers.index:
            pattern_info.append('TriggeredBy:' + related_threat_triggers['URI_y'][ind][7:] + '\n')

        # Gather Triggered Effects
        for ind in related_triggered_threats.index:
            pattern_info.append('Triggers:' + related_triggered_threats['URI_x'][ind][7:] + '\n')

        # Check if compliance threat
        if not row['package'] in compliance:
            # Uniqueness counter
            i = 0

            # Add Secondary Effect Causes
            for ind in related_threat_sec.index:
                sec_threat = related_threat_sec['hasSecondaryEffectCondition'][ind].split('-')[1]
                acts_on = related_threat_sec['hasSecondaryEffectCondition'][ind].split('-')[2]

                threat_sec_n(graph, sec_threat, i)
                threat_sec_e(graph, sec_threat + '%$#' + str(i), acts_on)
                i = i + 1

            # Add Misbehaviour
            for ind in related_misbehaviour.index:
                misbehaviour_name = related_misbehaviour['hasMisbehaviour'][ind]
                mis_n(graph, misbehaviour_name, i)
                mis_e(graph, related_misbehaviour['locatedAt'][ind], misbehaviour_name + '%$#' + str(i))
                pattern_info.append('Misbehaviour_Set:' + related_misbehaviour['hasMisbehaviour'][ind][7:] + '@' + related_misbehaviour['locatedAt'][ind][7:] + '\n')
                add_to_info_file('Misbehaviour', misbehaviour_name[7:], 'CausingThreat:' + uri[7:] + '\n')
                i = i + 1

            # Add Entry Points
            for ind in related_entries.index:
                cause_n(graph, related_entries['hasTrustworthinessAttribute'][ind], i)
                cause_e(graph, related_entries['hasTrustworthinessAttribute'][ind] + '%$#' + str(i),
                        related_entries['locatedAt'][ind])
                i = i + 1

        # Add Control Strategy info
        for ind in related_control_strategies.index:
            pattern_info.append('CSG:' + related_control_strategies['URI'][ind][7:] + '\n')

        # Save graph to folder
        file_location = os.path.join(target, uri[7:])
        generate_graph_if_required(file_location, graph, package)

        # Save info to file
        create_info_file(file_location, ''.join(pattern_info))


def extract_additional_control_strategy_info():
    # Needs to be done AFTER threat .info files have been generated, or info is lost
    control_triggers = pd.read_csv(os.path.join(csvs_location, 'ControlStrategyTriggers.csv'))

    # Add triggers to threat patterns
    for index, row in control_triggers.iterrows():
        add_to_info_file('Threat', row['triggers'][7:], 'TriggeredByCSG:' + row['URI'][7:] + '\n')

def extract_twa_info():
    # Frame of all twa
    twaf = pd.read_csv(os.path.join(csvs_location, 'TrustworthinessAttribute.csv'))
    mbf = pd.read_csv(os.path.join(csvs_location, 'TWIS.csv'))
    assets = pd.read_csv(os.path.join(csvs_location, 'TWALocations.csv'))
    threatEntryPoints = pd.read_csv(os.path.join(csvs_location, 'ThreatEntryPoints.csv'))

    # If example line present, remove
    if 'domain#000000' in twaf['URI'].tolist():
        twaf.drop(0, axis=0, inplace=True)
    if 'domain#000000' in assets['URI'].tolist():
        assets.drop(0, axis=0, inplace=True)

    # Create dictionary to hold info until creating info files
    tws = {}

    # Create info file for each twa
    for index, row in twaf.iterrows():
        # Check package
        package = row['package']
        if package == 'package#Unassigned':
            unassigned_list.append('TWA ' + row['URI'])
        elif package != package:
            blank_list.append('TWA ' + row['URI'])

        tws[row['URI']] = []

    # Add misbehaviour to each twa
    for index, row in mbf.iterrows():
        #TODO: remove this if statement (makes the code work with old version of domain model)
        if row['affects'] in tws:
            tws[row['affects']].append('Misbehaviour:' + row['affectedBy'][7:] + '\n')

    # Add assets to each twa
    for index, row in assets.iterrows():
        tws[row['URI']].append('Asset:' + row['metaLocatedAt'][7:] + '\n')

    # Add threats caused by each twa
    for index, row in threatEntryPoints.iterrows():
        threatURI = row['URI']
        twasURI = row['hasEntryPoint']
        twaURI = 'domain#' + twasURI.split('-', 1)[1].rsplit('-', 1)[0]
        tws[twaURI].append('ThreatCaused:' + threatURI[7:] + '\n')

    # Create info files
    for item in tws:
        create_info_file(os.path.join(target_location, 'TWA', item[7:]), ''.join(tws[item]))

def extract_asset_info():
    # Frame of all twa
    assetf = pd.read_csv(os.path.join(csvs_location, 'DomainAsset.csv'))

    # If example line present, remove
    if 'domain#000000' in assetf['URI'].tolist():
        assetf.drop(0, axis=0, inplace=True)

    # Create dictionary to hold info until creating info files
    assets = {}

    # Create info file for each asset
    for index, row in assetf.iterrows():
        # Check package
        package = row['package']
        if package == 'package#Unassigned':
            unassigned_list.append('Asset ' + row['URI'])
        elif package != package:
            blank_list.append('Asset ' + row['URI'])

        assets[row['URI']] = []

    # Add icon name to each asset
    for index, row in assetf.iterrows():
        assets[row['URI']].append('Icon:' + str(row['icon']) + '\n')

    # Create info files
    for item in assets:
        create_info_file(os.path.join(target_location, 'Asset', item[7:]), ''.join(assets[item]))

def create_report():
    # Create report string including current date & time
    report = ['\n' + 'Program completed at:' + '\n     ', str(datetime.now(tz=None)), '\n']

    # Check for errors
    if len(error_list) > 0 or len(unassigned_list) > 0 or len(blank_list) > 0:
        print('     WARNING: Some errors encountered. Check the report for more information')

        if len(error_list) > 0:
            report.append('Errors while rendering the following patterns:\n')
            for item in error_list:
                report.append('     ' + item + '\n')

        if len(unassigned_list) > 0:
            report.append('The following patterns are in package \'unassigned\':\n')
            for item in unassigned_list:
                report.append('     ' + item + '\n')

        if len(blank_list) > 0:
            report.append('The following patterns have no package:\n')
            for item in blank_list:
                report.append('     ' + item + '\n')

    # Generate report
    with open('report.txt', 'a+') as f:
        f.write(''.join(report))


def generate_all_patterns(user_input):
    set_csv_location(user_input)
    set_images_location(user_input)

    if not check_configuration():
        return

    setup_folder_structure()
    # print('Extracting CSV Info...')
    # extract_role_info()
    # extract_misbehaviour_info()
    # extract_controls_info()
    # extract_control_strategy_info()
    extract_twa_info()
    extract_asset_info()

    # print('Generating Root Patterns...')
    # generate_root_patterns()
    # print('Generating Matching Pattern Setup...')
    # generate_initial_matching_patterns()

    # print('Generating Forced Position Matching Patterns...')
    # generate_final_matching_patterns()
    # print('Generating Construction Patterns...')
    # generate_construction_patterns()
    # print('Generating Threat Patterns...')
    # generate_threat_patterns()
    # extract_additional_control_strategy_info()

    create_report()


if __name__ == '__main__':
    generate_all_patterns(sys.argv[1])
