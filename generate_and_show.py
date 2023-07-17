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
#      Created Date :          2022-08-03
#      Created for Project :   FogProtect
#
########################################################################

import os
import sys

from running.generate_patterns import generate_all_patterns
from running.freeze_flask import freeze_html


def check_inputs(user_input):
    # Fail if incorrect number of inputs
    if len(user_input) < 2:
        print('Program requires the directory of the csvs as input.')
        return False

    csv_directory = user_input[1]

    # Fail if csvs directory doesn't exist
    if not os.path.isdir(csv_directory):
        print('Directory "' + csv_directory + '" does not exist')
        return False

    # Fail if csvs directory doesn't contain csvs
    if not os.path.exists(os.path.join(csv_directory, 'RootPattern.csv')):
        print('Directory "' + csv_directory + '" does not contain the required csv files.')
        return False

    # Otherwise, go ahead
    return csv_directory


def run_all(user_inputs):
    # Check user inputs for validity
    csvs_location = check_inputs(user_inputs)
    if not csvs_location:
        exit()

    # Generate Patterns & graphs
    generate_all_patterns(csvs_location)
    # Create static html
    freeze_html(csvs_location)


if __name__ == '__main__':
    run_all(sys.argv)
