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

# Node positioning
def pos_adjustments(x_in, y_in):
    # Reduce graph scale by 0.01
    x = str(x_in * 0.010)
    y = str(y_in * 0.010)
    # Maximum of 8 significant figures is required
    return x[:8] + ',' + y[:8] + '!'


def pos_nodes(gra, node_positions):
    for asset, position in node_positions.items():
        gra.node(asset, pos=(pos_adjustments(position[0], position[1])))
