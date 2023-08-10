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
#      Created Date :          2022-08-31
#      Created for Project :   FogProtect
#
########################################################################

import os
import sys

from jinja2 import Environment, FileSystemLoader
import pandas as pd
from flask_frozen import Freezer
from create_html import app, generate_html


csvs_location = ''
freezer = Freezer(app)


@freezer.register_generator
def see_root():
    print('Creating pages for root patterns', end=', ')
    # Get csv
    df = pd.read_csv(os.path.join(csvs_location, 'RootPattern.csv'))

    # Remove example line where present
    if 'domain#000000' in df['URI'].tolist():
        df.drop(0, axis=0, inplace=True)

    # Generate html for each root pattern
    for index, row in df.iterrows():
        yield {'uri': row['URI'][7:]}


@freezer.register_generator
def see_matching():
    print('matching patterns', end=', ')
    # Get csv
    df = pd.read_csv(os.path.join(csvs_location, 'MatchingPattern.csv'))

    # Remove example line where present
    if 'domain#000000' in df['URI'].tolist():
        df.drop(0, axis=0, inplace=True)

    # Generate html for each matching pattern
    for index, row in df.iterrows():
        yield {'uri': row['URI'][7:]}


@freezer.register_generator
def see_construction():
    print('construction patterns', end=', ')
    # Get csv
    df = pd.read_csv(os.path.join(csvs_location, 'ConstructionPattern.csv'))

    # Remove example line where present
    if 'domain#000000' in df['URI'].tolist():
        df.drop(0, axis=0, inplace=True)

    # Generate html for each construction pattern
    for index, row in df.iterrows():
        yield {'uri': row['URI'][7:]}


@freezer.register_generator
def see_threat():
    print('threats', end=', ')
    # Get csv
    df = pd.read_csv(os.path.join(csvs_location, 'Threat.csv'))

    # Remove example line where present
    if 'domain#000000' in df['URI'].tolist():
        df.drop(0, axis=0, inplace=True)

    # Generate html for each threat pattern
    for index, row in df.iterrows():
        yield {'uri': row['URI'][7:]}


@freezer.register_generator
def see_misbehaviour():
    print('misbehaviours', end=', ')
    # Get csv
    df = pd.read_csv(os.path.join(csvs_location, 'Misbehaviour.csv'))

    # Remove example line where present
    if 'domain#000000' in df['URI'].tolist():
        df.drop(0, axis=0, inplace=True)

    # Generate html for each misbehaviour
    for index, row in df.iterrows():
        yield {'uri': row['URI'][7:]}


@freezer.register_generator
def see_csg():
    print('control strategies', end=', ')
    # Get csv
    df = pd.read_csv(os.path.join(csvs_location, 'ControlStrategy.csv'))

    # Remove example line where present
    if 'domain#000000' in df['URI'].tolist():
        df.drop(0, axis=0, inplace=True)

    # Generate html for each control strategy
    for index, row in df.iterrows():
        yield {'uri': row['URI'][7:]}


@freezer.register_generator
def see_control():
    print('controls', end=', ')
    # Get csv
    df = pd.read_csv(os.path.join(csvs_location, 'Control.csv'))

    # Remove example line where present
    if 'domain#000000' in df['URI'].tolist():
        df.drop(0, axis=0, inplace=True)

    # Generate html for each control
    for index, row in df.iterrows():
        yield {'uri': row['URI'][7:]}


@freezer.register_generator
def see_role():
    print('roles', end=' ')
    # Get csv
    df = pd.read_csv(os.path.join(csvs_location, 'Role.csv'))

    # Remove example line where present
    if 'domain#000000' in df['URI'].tolist():
        df.drop(0, axis=0, inplace=True)

    # Generate html for each role
    for index, row in df.iterrows():
        yield {'uri': row['URI'][7:]}


@freezer.register_generator
def see_package():
    print('and packages!')
    # Get csv
    df = pd.read_csv(os.path.join(csvs_location, 'Packages.csv'))

    # Remove example line where present
    if 'domain#000000' in df['URI'].tolist():
        df.drop(0, axis=0, inplace=True)

    # Generate html for each package
    for index, row in df.iterrows():
        yield {'uri': row['URI'][8:]}

@freezer.register_generator
def see_twa():
    print('twa', end=', ')
    # Get csv
    df = pd.read_csv(os.path.join(csvs_location, 'TWA.csv'))

    # Remove example line where present
    if 'domain#000000' in df['URI'].tolist():
        df.drop(0, axis=0, inplace=True)

    # Generate html for each twa
    for index, row in df.iterrows():
        yield {'uri': row['URI'][7:]}

@freezer.register_generator
def see_asset():
    print('asset', end=', ')
    # Get csv
    df = pd.read_csv(os.path.join(csvs_location, 'DomainAsset.csv'))

    # Remove example line where present
    if 'domain#000000' in df['URI'].tolist():
        df.drop(0, axis=0, inplace=True)

    # Generate html for each twa
    for index, row in df.iterrows():
        yield {'uri': row['URI'][7:]}


def freeze_html(domain_model_location_in):
    global csvs_location
    csvs_location = os.path.join(domain_model_location_in, 'csv')

    print('Preparing faux server...')
    generate_html(csvs_location)
    print('Generating html...')
    freezer.freeze()
    print('     PROGRAM COMPLETE: The Home html file is in the following location:')
    print(os.path.join('csv2doc', 'build', 'index.html'))


if __name__ == '__main__':
    freeze_html(sys.argv[1])
