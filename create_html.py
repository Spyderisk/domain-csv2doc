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
#      Created Date :          2022-08-25
#      Created for Project :   FogProtect
#
########################################################################

import os
import sys
import shutil

from flask import Flask, render_template
import pandas as pd
import json

app = Flask(__name__, template_folder=os.path.join('', 'templates'))

target_location = os.path.join('', 'static')
labels = {}
descriptions = {}
packages = {}
construction_priorities = {}
search_index = []
model_version = 'error'
categories = {}
proceeded_by = {'role': {}, 'const_pattern': {}, 'const_priority': {}, 'csg': {}, 'controls': {},
                'matching': {}, 'misbehaviour': {}, 'root': {}, 'threat': {}, 'twa': {}, 'asset': {}}
followed_by = {'role': {}, 'const_pattern': {}, 'const_priority': {}, 'csg': {}, 'controls': {},
               'matching': {}, 'misbehaviour': {}, 'root': {}, 'threat': {}, 'twa': {}, 'asset': {}}

# Data Frames
root_df = pd
matching_df = pd
construction_df = pd
threat_df = pd
misbehaviour_df = pd
control_strategy_df = pd
controls_df = pd
role_df = pd
package_df = pd
twa_df = pd
asset_df = pd


def get_lines(file_path, needs_svg):
    # If no info file, or if no svg when svg is required, return failure
    if (not os.path.exists(file_path + '.info')) or (needs_svg and not os.path.exists(file_path + '.svg')):
        return False

    # Read info from file
    with open(file_path + '.info') as f:
        lines = list(dict.fromkeys(f.read().split('\n')))

    return lines


@app.route('/root/<uri>/')
def see_root(uri):
    file_path = os.path.join(target_location, 'Root', uri)

    # Get lines from file
    lines = get_lines(file_path, True)

    # Get matching patterns
    matchings = lines[0:-1]

    return render_template('pattern/root.html', uri=uri, matchings=matchings, descriptions=descriptions, labels=labels,
                           package=packages[uri], search_index=json.dumps(search_index), model_version=model_version,
                           prev_uri=proceeded_by['root'][uri], next_uri=followed_by['root'][uri], active_page='root')


@app.route('/matching/<uri>/')
def see_matching(uri):
    file_path = os.path.join(target_location, 'Matching', uri)

    # Get lines from file
    lines = get_lines(file_path, True)

    # Get Root used
    root = lines[0]

    # Get list of construction patterns & matching patterns
    constructions = []
    threats = []
    for line in lines[1:-1]:
        if line.startswith('Threat:'):
            threats.append(line.split(':')[1])
        elif line.startswith('Construction:'):
            constructions.append(line.split(':')[1])

    return render_template('pattern/matching.html', uri=uri, root=root, constructions=constructions, threats=threats,
                           descriptions=descriptions, labels=labels, package=packages[uri],
                           search_index=json.dumps(search_index), model_version=model_version,
                           prev_uri=proceeded_by['matching'][uri], next_uri=followed_by['matching'][uri], active_page='matching')


@app.route('/construction/<uri>/')
def see_construction(uri):
    file_path = os.path.join(target_location, 'Construction', uri)

    # Get lines from file
    lines = get_lines(file_path, True)

    # Get matching used
    matching = lines[0]
    iterate = lines[1]
    priority = construction_priorities[uri]

    return render_template('pattern/construction.html', uri=uri, matching=matching, priority=priority, iterate=iterate,
                           descriptions=descriptions, labels=labels, package=packages[uri],
                           search_index=json.dumps(search_index), model_version=model_version,
                           prev_pa=proceeded_by['const_pattern'][uri], next_pa=followed_by['const_pattern'][uri],
                           prev_pr=proceeded_by['const_priority'][uri], next_pr=followed_by['const_priority'][uri], active_page='construction')


@app.route('/threat/<uri>/')
def see_threat(uri):
    file_path = os.path.join(target_location, 'Threat', uri)

    # Get lines from file
    lines = get_lines(file_path, True)

    # Get matching used
    matching = lines[0]

    # Get list of triggers, misbehaviour and control strategies
    triggered_by = []
    triggers = []
    csg_triggers = []
    misbehaviour = []
    roles = []
    csgs = []
    for line in lines[1:-1]:
        if line.startswith('TriggeredBy:'):
            triggered_by.append(line.split(':')[1])
        elif line.startswith('Triggers:'):
            triggers.append(line.split(':')[1])
        elif line.startswith('TriggeredByCSG:'):
            csg_triggers.append(line.split(':')[1])
        elif line.startswith('Misbehaviour_Set:'):
            m_set = line.split(':')[1].split('@')
            misbehaviour.append(m_set[0])
            roles.append(m_set[1])
        elif line.startswith('CSG:'):
            csgs.append(line.split(':')[1])

    return render_template('pattern/threat.html', uri=uri, matching=matching, triggered_by=triggered_by,
                           triggers=triggers, csg_triggers=csg_triggers, misbehaviour=misbehaviour, roles=roles,
                           csgs=csgs, descriptions=descriptions, labels=labels, package=packages[uri],
                           search_index=json.dumps(search_index), model_version=model_version,
                           prev_uri=proceeded_by['threat'][uri], next_uri=followed_by['threat'][uri], active_page='threat')


@app.route('/misbehaviour/<uri>/')
def see_misbehaviour(uri):
    file_path = os.path.join(target_location, 'Misbehaviour', uri)

    # Get lines from file
    lines = get_lines(file_path, False)

    assets = []
    causing_threats = []
    threats_caused = []
    twa = None
    twaThreats = []

    # Get list of threats and roles
    for line in lines[0:-1]:
        if line.startswith('Asset:'):
            assets.append(line.split(':')[1])
        elif line.startswith('CausingThreat:'):
            causing_threats.append(line.split(':')[1])
        elif line.startswith('ThreatCaused:'):
            threats_caused.append(line.split(':')[1])
        elif line.startswith('TWA:'):
            twa = line.split(':')[1]
        elif line.startswith('twaThreat:'):
            twaThreats.append(line.split(':')[1])

    return render_template('pattern/misbehaviour.html', uri=uri, descriptions=descriptions, labels=labels,
                           package=packages[uri], assets=assets, causing_threats=causing_threats, threats_caused=threats_caused, 
                           twa=twa, twaThreats=twaThreats, search_index=json.dumps(search_index),
                           model_version=model_version, prev_uri=proceeded_by['misbehaviour'][uri],
                           next_uri=followed_by['misbehaviour'][uri], active_page='misbehaviour')


@app.route('/csg/<uri>/')
def see_csg(uri):
    file_path = os.path.join(target_location, 'Control Strategy', uri)

    # Get lines from file
    lines = get_lines(file_path, False)

    # Get mitigated & blocked threats, and controls
    optional = False
    mitigated = []
    blocked = []
    triggers = []
    controls = []
    roles = []
    optionals = []
    for line in lines[0:-1]:
        if line.startswith('Mitigates:'):
            mitigated.append(line.split(':')[1])
        elif line.startswith('Blocked:'):
            blocked.append(line.split(':')[1])
        elif line.startswith('Triggers:'):
            triggers.append(line.split(':')[1])
        elif line.startswith('ControlSet:'):
            c_set = line.split(':')[1].split('-')
            controls.append(c_set[1])
            roles.append('Role_' + c_set[2])
            optionals.append(c_set[3] == 'True')

    return render_template('pattern/csg.html', uri=uri, mitigated=mitigated, blocked=blocked, triggers=triggers,
                           controls=controls, roles=roles, optionals=optionals, descriptions=descriptions,
                           labels=labels, package=packages[uri], search_index=json.dumps(search_index),
                           model_version=model_version, prev_uri=proceeded_by['csg'][uri],
                           next_uri=followed_by['csg'][uri], active_page='csg')


@app.route('/control/<uri>/')
def see_control(uri):
    file_path = os.path.join(target_location, 'Controls', uri)

    # Get lines from file
    lines = get_lines(file_path, False)

    # Get control strategies
    csgs = []
    optionals = []

    for line in lines[0:-1]:
        csgs.append(line.rsplit('-', 1)[0])
        optionals.append(line.rsplit('-', 1)[1] == 'True')

    return render_template('pattern/control.html', uri=uri, descriptions=descriptions, labels=labels, csgs=csgs,
                           optionals=optionals, package=packages[uri], search_index=json.dumps(search_index),
                           model_version=model_version, prev_uri=proceeded_by['controls'][uri],
                           next_uri=followed_by['controls'][uri], active_page='control')


@app.route('/role/<uri>/')
def see_role(uri):
    file_path = os.path.join(target_location, 'Role', uri)

    # Get lines from file
    lines = get_lines(file_path, False)

    controls = []
    misbehaviour = []

    # Get list of Controls and Misbehaviour
    for line in lines[0:-1]:
        if line.startswith('Control:'):
            controls.append(line.split(':')[1])
        elif line.startswith('Misbehaviour:'):
            misbehaviour.append(line.split(':')[1])

    return render_template('pattern/role.html', uri=uri, descriptions=descriptions, labels=labels, controls=controls,
                           misbehaviour=misbehaviour, search_index=json.dumps(search_index), package=packages[uri],
                           model_version=model_version, prev_uri=proceeded_by['role'][uri],
                           next_uri=followed_by['role'][uri], active_page='role')


def get_from_package(df, package):
    item_list = []

    df_package = df.loc[df['package'] == 'package#' + package]

    for index, row in df_package.iterrows():
        item_list.append(row['URI'][7:])

    return item_list


@app.route('/package/<uri>/')
def see_package(uri):
    # Prepare matching df with packages
    df = pd.merge(matching_df, root_df, left_on='hasRootPattern', right_on='URI')
    matching_df_packages = df.rename(columns={'URI_x': 'URI'})

    # Prepare lists of items in package
    root = get_from_package(root_df, uri)
    matching = get_from_package(matching_df_packages, uri)
    construction = get_from_package(construction_df, uri)
    threats = get_from_package(threat_df, uri)
    misbehaviour = get_from_package(misbehaviour_df, uri)
    csg = get_from_package(control_strategy_df, uri)
    control = get_from_package(controls_df, uri)
    role = get_from_package(role_df, uri)
    twa = get_from_package(twa_df, uri)
    asset = get_from_package(asset_df, uri)

    return render_template('pattern/package.html', uri=uri, root=root, matching=matching, construction=construction,
                           threats=threats, misbehaviour=misbehaviour, csg=csg, control=control, role=role, twa=twa,
                           asset=asset, descriptions=descriptions, labels=labels, search_index=json.dumps(search_index),
                           model_version=model_version, active_page='package')

@app.route('/twa/<uri>/')
def see_twa(uri):
    file_path = os.path.join(target_location, 'TWA', uri)

    # Get lines from file
    lines = get_lines(file_path, False)

    assets = []
    threats = []

    # Get misbehaviour and assets
    for line in lines[0:-1]:
        if line.startswith('Misbehaviour:'):
            misbehaviour = line.split(':')[1]
        elif line.startswith('Asset:'):
            assets.append(line.split(':')[1])
        elif line.startswith('ThreatCaused:'):
            threats.append(line.split(':')[1])

    return render_template('pattern/twa.html', uri=uri, descriptions=descriptions, labels=labels,
                           package=packages[uri], misbehaviour=misbehaviour, assets=assets, threats=threats, search_index=json.dumps(search_index),
                           model_version=model_version, prev_uri=proceeded_by['twa'][uri],
                           next_uri=followed_by['twa'][uri], active_page='twa')

@app.route('/asset/<uri>/')
def see_asset(uri):
    file_path = os.path.join(target_location, 'Asset', uri)

    # Get lines from file
    lines = get_lines(file_path, False)

    # Get asset icon
    for line in lines[0:-1]:
        if line.startswith('Icon:'):
            icon = line.split(':')[1]

    return render_template('pattern/asset.html', uri=uri, descriptions=descriptions, labels=labels,
                           package=packages[uri], icon=icon, search_index=json.dumps(search_index),
                           model_version=model_version, prev_uri=proceeded_by['asset'][uri],
                           next_uri=followed_by['asset'][uri], active_page='asset')

@app.route('/')
def from_start():
    return render_template('home.html', search_index=json.dumps(search_index), model_version=model_version, active_page='home')


@app.route('/root/list/')
def root_list():
    return render_template('navigation/root_list.html', categories=categories['root'], descriptions=descriptions,
                           labels=labels, search_index=json.dumps(search_index), model_version=model_version, active_page='root')


@app.route('/matching/list/')
def matching_list():
    return render_template('navigation/matching_list.html', categories=categories['matching'],
                           descriptions=descriptions, labels=labels, search_index=json.dumps(search_index),
                           model_version=model_version, active_page='matching')


@app.route('/construction/list/')
def construction_list():
    return render_template('navigation/construction_list.html', categories=categories['const_pattern'],
                           cons_pri=construction_priorities, descriptions=descriptions, labels=labels,
                           search_index=json.dumps(search_index), model_version=model_version, active_page='construction')


@app.route('/construction/priority/')
def construction_priority():
    priorities = [[], [], [], [], [], [], [], [], [], [], [], []]

    # For each pattern, add to list based on priority
    for index, row in construction_df.iterrows():
        priority = row['hasPriority']

        if priority < 1000:
            priorities[0].append(row['URI'][7:])
        elif priority < 2000:
            priorities[1].append(row['URI'][7:])
        elif priority < 3000:
            priorities[2].append(row['URI'][7:])
        elif priority < 4000:
            priorities[3].append(row['URI'][7:])
        elif priority < 5000:
            priorities[4].append(row['URI'][7:])
        elif priority < 6000:
            priorities[5].append(row['URI'][7:])
        elif priority < 7000:
            priorities[6].append(row['URI'][7:])
        elif priority < 8000:
            priorities[7].append(row['URI'][7:])
        elif priority < 9000:
            priorities[8].append(row['URI'][7:])
        elif priority < 10000:
            priorities[9].append(row['URI'][7:])
        elif priority < 11000:
            priorities[10].append(row['URI'][7:])
        else:
            priorities[11].append(row['URI'][7:])

    return render_template('navigation/construction_by_priority.html', priorities=priorities,
                           cons_pri=construction_priorities, descriptions=descriptions, labels=labels,
                           search_index=json.dumps(search_index), model_version=model_version, active_page='construction')


@app.route('/threat/list/')
def threat_list():
    return render_template('navigation/threat_list.html', categories=categories['threat'],
                           descriptions=descriptions, labels=labels, search_index=json.dumps(search_index),
                           model_version=model_version, active_page='threat')


@app.route('/misbehaviour/list/')
def misbehaviour_list():
    return render_template('navigation/misbehaviour_list.html', categories=categories['misbehaviour'],
                           descriptions=descriptions, labels=labels, search_index=json.dumps(search_index),
                           model_version=model_version, active_page='misbehaviour')


@app.route('/csg/list/')
def csg_list():
    return render_template('navigation/csg_list.html', categories=categories['csg'], descriptions=descriptions,
                           labels=labels, search_index=json.dumps(search_index), model_version=model_version, active_page='csg')


@app.route('/control/list/')
def control_list():
    return render_template('navigation/control_list.html', categories=categories['controls'], descriptions=descriptions,
                           labels=labels, search_index=json.dumps(search_index), model_version=model_version, active_page='control')


@app.route('/role/list/')
def role_list():
    return render_template('navigation/role_list.html', categories=categories['role'], descriptions=descriptions,
                           labels=labels, search_index=json.dumps(search_index), model_version=model_version, active_page='role')


@app.route('/package/list/')
def package_list():
    all_packages = []
    for index, row in package_df.iterrows():
        # Make list of all packages other than Unassigned
        if row['URI'] != 'package#Unassigned':
            all_packages.append(row['URI'][8:])

    return render_template('navigation/package_list.html', packages=all_packages, descriptions=descriptions,
                           labels=labels, search_index=json.dumps(search_index), model_version=model_version, active_page='package')

@app.route('/twa/list/')
def twa_list():
    return render_template('navigation/twa_list.html', categories=categories['twa'],
                           descriptions=descriptions, labels=labels, search_index=json.dumps(search_index),
                           model_version=model_version, active_page='twa')

@app.route('/asset/list/')
def asset_list():
    return render_template('navigation/asset_list.html', categories=categories['asset'],
                           descriptions=descriptions, labels=labels, search_index=json.dumps(search_index),
                           model_version=model_version, active_page='asset')

def prepare_css():
    # Puts a copy of the css into the static file
    shutil.copy(os.path.join('templates', 'custom.css'), 'static')


def get_csv(csvs_location, csv_name):
    df = pd.read_csv(os.path.join(csvs_location, csv_name))

    # Remove example line where present
    if 'domain#000000' in df['URI'].tolist():
        df.drop(0, axis=0, inplace=True)

    return df


def set_domain_model_version(df):
    global model_version
    model_version = df.iloc[0]['versionInfo']


def prepare_data_frames(csvs_location):
    global root_df
    global matching_df
    global construction_df
    global threat_df
    global misbehaviour_df
    global control_strategy_df
    global controls_df
    global role_df
    global package_df
    global twa_df
    global asset_df

    # Collect data frame from csv
    root_df = get_csv(csvs_location, 'RootPattern.csv')
    matching_df = get_csv(csvs_location, 'MatchingPattern.csv')
    construction_df = get_csv(csvs_location, 'ConstructionPattern.csv').sort_values(['package', 'hasPriority'],
                                                                                    inplace=False)
    threat_df = get_csv(csvs_location, 'Threat.csv')
    misbehaviour_df = get_csv(csvs_location, 'Misbehaviour.csv')
    control_strategy_df = get_csv(csvs_location, 'ControlStrategy.csv')
    controls_df = get_csv(csvs_location, 'Control.csv')
    role_df = get_csv(csvs_location, 'Role.csv')
    package_df = get_csv(csvs_location, 'Packages.csv').rename(columns={'Package': 'label', 'Description': 'comment'})
    twa_df = get_csv(csvs_location, 'TrustworthinessAttribute.csv')
    asset_df = get_csv(csvs_location, 'DomainAsset.csv')
    set_domain_model_version(get_csv(csvs_location, 'DomainModel.csv'))


def add_descriptions(df, n=7):
    global descriptions

    for index, row in df.iterrows():
        description = str(row['comment']).replace(' _', ' <b><i>').replace('_', '</i></b>')

        if ': ' in description:
            description = "<span class=\"bigger\">" + description.replace(':', ':</span>')

        descriptions[row['URI'][n:]] = description


def prepare_descriptions():
    add_descriptions(root_df)
    add_descriptions(matching_df)
    add_descriptions(construction_df)
    add_descriptions(threat_df)
    add_descriptions(misbehaviour_df)
    add_descriptions(control_strategy_df)
    add_descriptions(controls_df)
    add_descriptions(role_df)
    add_descriptions(twa_df)
    add_descriptions(asset_df)
    add_descriptions(package_df, 8)


def add_package(df):
    global packages

    for index, row in df.iterrows():
        package = row['package']
        name = row['URI'][7:]
        if package != package:
            packages[name] = 'Unassigned'
        else:
            packages[name] = package[8:]


def prepare_packages():
    add_package(root_df)

    # Prepare matching df with packages
    mat_df = pd.merge(matching_df, root_df, left_on='hasRootPattern', right_on='URI')
    mat_df_packages = mat_df.rename(columns={'URI_x': 'URI'})
    add_package(mat_df_packages)
    add_package(construction_df)
    add_package(threat_df)
    add_package(misbehaviour_df)
    add_package(control_strategy_df)
    add_package(controls_df)
    add_package(role_df)
    add_package(twa_df)
    add_package(asset_df)


def add_search_index(item_type, item_name, df, n=7):
    global search_index

    for index, row in df.iterrows():
        html_file = os.path.join(item_type, row['URI'][n:], 'index.html')
        search_text = row['URI'][n:] + ' ' + item_type + ' ' + item_name + ' ' + str(row['comment'])
        search_index.append({"name": html_file, "text": search_text})


def prepare_search_index():
    add_search_index('root', 'roots pattern', root_df)
    add_search_index('matching', 'pattern', matching_df)
    add_search_index('construction', 'pattern', construction_df)
    add_search_index('threat', 'threats pattern', threat_df)
    add_search_index('misbehaviour', 'misbehaviours', misbehaviour_df)
    add_search_index('csg', 'control strategy strategies', control_strategy_df)
    add_search_index('control', 'controls', controls_df)
    add_search_index('role', 'roles', role_df)
    add_search_index('package', 'packages category categories', package_df, 8)


def prepare_construction_priorities():
    for index, row in construction_df.iterrows():
        construction_priorities[row['URI'][7:]] = row['hasPriority']


def add_labels(df, n=7):
    global labels

    for index, row in df.iterrows():
        labels[row['URI'][n:]] = row['label']


def prepare_labels():
    add_labels(root_df)
    add_labels(matching_df)
    add_labels(construction_df)
    add_labels(threat_df)
    add_labels(misbehaviour_df)
    add_labels(control_strategy_df)
    add_labels(controls_df)
    add_labels(role_df)
    add_labels(twa_df)
    add_labels(asset_df)
    add_labels(package_df, 8)


def add_prev_next_index(pattern_type, df):
    current_uri = False
    next_uri = False
    first = True

    for index, row in df.iterrows():
        prev_uri = current_uri
        current_uri = next_uri
        next_uri = row['URI'][7:]

        if not first:
            proceeded_by[pattern_type][current_uri] = prev_uri
            followed_by[pattern_type][current_uri] = next_uri
        else:
            first = False
    proceeded_by[pattern_type][next_uri] = current_uri
    followed_by[pattern_type][next_uri] = False


def get_categories(df):
    # Add 'Unassigned' list first, to ensure place at top of the display despite alphabetical sort
    df_categories = {'Unassigned': []}
    # For each pattern, add to list
    for index, row in df.iterrows():
        package = row['package']
        # If package is blank, add to 'Unassigned' List
        if package != package:
            package = 'Unassigned'
        else:
            package = row['package'][8:]

        # If list exists, add item, else make list & add item
        if package in df_categories.keys():
            df_categories[package].append(row['URI'][7:])
        else:
            df_categories[package] = [row['URI'][7:]]

    # If unassigned list is empty, remove it
    if len(df_categories['Unassigned']) == 0:
        df_categories.pop('Unassigned')

    return df_categories


def set_category_prev_next(pattern_type, df):
    global categories
    categories[pattern_type] = get_categories(df.sort_values(by=['package'], inplace=False))

    current_uri = False
    next_uri = False

    for package in categories[pattern_type]:
        for pattern_uri in categories[pattern_type][package]:

            prev_uri = current_uri
            current_uri = next_uri
            next_uri = pattern_uri

            if current_uri:
                proceeded_by[pattern_type][current_uri] = prev_uri
                followed_by[pattern_type][current_uri] = next_uri

    proceeded_by[pattern_type][next_uri] = current_uri
    followed_by[pattern_type][next_uri] = False


def prepare_prev_next_indexing():
    set_category_prev_next('root', root_df)
    mat_df = pd.merge(matching_df, root_df, left_on='hasRootPattern', right_on='URI')
    mat_df = mat_df.rename(columns={'URI_x': 'URI'})
    set_category_prev_next('matching', mat_df)
    set_category_prev_next('const_pattern', construction_df)
    set_category_prev_next('threat', threat_df)
    set_category_prev_next('misbehaviour', misbehaviour_df)
    set_category_prev_next('csg', control_strategy_df)
    set_category_prev_next('controls', controls_df)
    set_category_prev_next('role', role_df)
    set_category_prev_next('twa', twa_df)
    set_category_prev_next('asset', asset_df)

    sorted_by_priority = construction_df.sort_values(by=['hasPriority'], inplace=False)
    add_prev_next_index('const_priority', sorted_by_priority)


def generate_html(csvs_directory):
    prepare_css()
    prepare_data_frames(csvs_directory)
    prepare_descriptions()
    prepare_packages()
    prepare_search_index()
    prepare_construction_priorities()
    prepare_labels()
    prepare_prev_next_indexing()


if __name__ == '__main__':
    # If running directly by testing, prepare_css() will throw an error due to relative pathing
    generate_html(sys.argv[1])
    app.run()
