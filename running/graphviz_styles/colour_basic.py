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

# Width and height attributes for box sizes
w = '1.8'
h = '0.7'


# Node Styles
def name_node(gra, role_in, asset_in):  # Un-styled node
    role = role_in[12:]
    asset = asset_in[7:]

    if role == asset:
        gra.node(role, label=asset)
    else:
        gra.node(role, label=asset + ': \n' + role)


def root_n(gra, role_in, asset_in):  # Root nodes
    role = role_in[12:]
    asset = asset_in[7:]

    if role == asset:
        gra.node(role, label=asset, shape='rect', width=w, height=h, peripheries='2',
                 tooltip=asset + '\nRoot Node\n(Mandatory, Unique)')
    else:
        gra.node(role, label=asset + ': \n' + role, shape='rect', width=w, height=h, peripheries='2',
                 tooltip=asset + '\nRoot Node\n(Mandatory, Unique)')


def man_n(gra, role_in):  # Mandatory nodes
    role = role_in[12:]
    gra.node(role, shape='rect', width=w, height=h, tooltip=role + '\nMandatory Node\n(Mandatory, One or Many)')


def suf_n(gra, role_in):  # Sufficient nodes
    role = role_in[12:]
    gra.node(role, shape='rect', width=w, height=h, xlabel='s',
             tooltip=role + '\nSufficient Node\n(One is sufficient for threat)')


def nec_n(gra, role_in):  # Necessary nodes
    role = role_in[12:]
    gra.node(role, shape='rect', width=w, height=h, xlabel='n',
             tooltip=role + '\nNecessary Node\n(At least this population\nis necessary for threat)')


def prohibited_n(gra, role_in):  # Prohibited nodes
    role = role_in[12:]
    gra.node(role, shape='rect', width=w, height=h, style='dashed', color='red', tooltip=role + '\nProhibited Node')


def opt_n(gra, role_in):  # Optional nodes
    role = role_in[12:]
    gra.node(role, shape='rect', width=w, height=h, color='darkgrey', style='filled', linestyle='invis',
             tooltip=role + '\nOptional Node\n(None, One or Many)')


def cons_n(gra, role_in):  # Constructed nodes
    role = role_in[12:]
    gra.node(role, shape='rect', width=w, height=h, color='blue', fillcolor='darkslategray1', style='filled',
             tooltip=role + '\nConstructed Node')


def cause_n(gra, role_in, i):  # Causal nodes
    role = role_in[7:]
    gra.node(role + '%$#' + str(i), role, shape='rect', width=w, height=h, style='rounded,filled', color='steelblue1',
             tooltip=role + '\nConstructed Node')


def threat_sec_n(gra, role_in, i):  # Secondary Effect Conditions
    role = role_in
    gra.node(role + '%$#' + str(i), role, shape='rect', width=w, height=h, style='rounded,filled', color='tomato',
             tooltip=role + '\nSecondary Effect Cause')


def mis_n(gra, role_in, i):  # Misbehaviour nodes
    role = role_in[7:]
    gra.node(role + '%$#' + str(i), label=role, width=w, height=h, color='tomato', style='filled',
             tooltip=role + '\nMisbehaviour Caused')


def text_n(gra, ref, label, tip):
    gra.node(ref, label=label, width='0.1', height='0.05', shape='plaintext', tooltip=tip, fontsize='12')


# Edge Styles
def stan_e(gra, fro_in, to_in, link_type_in):  # Standard Edge
    fro = fro_in[12:]
    to = to_in[12:]
    label = link_type_in[7:]
    label_name = fro+to+label+'standard'
    tooltip = 'Standard connection from\n' + fro + ' to ' + to + '\nOf type "' + label + '"'

    gra.edge(fro, label_name, arrowhead='none', labeltooltip=tooltip, tooltip=tooltip)
    text_n(gra, label_name, label, tooltip)
    gra.edge(label_name, to, labeltooltip=tooltip, tooltip=tooltip)


def prohibited_e(gra, fro_in, to_in, link_type_in):  # Prohibited Edge
    fro = fro_in[12:]
    to = to_in[12:]
    label = link_type_in[7:]
    label_name = fro+to+label+'prohibited'
    tooltip = 'Prohibited connection from\n' + fro + ' to ' + to + '\nOf type "' + label + '"'

    gra.edge(fro, label_name, arrowhead='none', color='red', style='dashed', labeltooltip=tooltip, tooltip=tooltip)
    text_n(gra, label_name, label, tooltip)
    gra.edge(label_name, to, arrowhead='vee', color='red', style='dashed', labeltooltip=tooltip, tooltip=tooltip)


def dist_e(gra, fro_in, to_in):  # Distinct Edge
    fro = fro_in[12:].split('-')[0]
    to = to_in[12:].split('-')[0]
    tooltip = fro + ' is distinct\nfrom ' + to

    gra.edge(fro, to, dir='both', xlabel='  distinct  ', style='dotted', arrowhead='inv', arrowtail='inv',
             labeltooltip=tooltip, tooltip=tooltip, constraint='false')


def cons_e(gra, fro_in, to_in, link_type_in):  # Constructed Edge
    fro = fro_in[12:]
    to = to_in[12:]
    label = link_type_in[7:]
    label_name = fro + to + label + 'constructed'
    tooltip = 'Constructed connection from \n' + fro + ' to ' + to + '\nOf type "' + label + '"'

    gra.edge(fro, label_name, arrowhead='none', color='blue', labeltooltip=tooltip, tooltip=tooltip)
    text_n(gra, label_name, label, tooltip)
    gra.edge(label_name, to, color='blue', arrowhead='veevee', labeltooltip=tooltip, tooltip=tooltip)


def cause_e(gra, fro_in, to_in):  # Causal Edge
    fro = fro_in[7:]
    to = to_in[12:]
    tooltip = fro.split('%$#')[0] + ' in ' + to + ' causes,\nor contributes to, the threat'

    gra.edge(fro, to, color='steelblue1', constraint='false', tooltip=tooltip)


def threat_sec_e(gra, fro_in, to_in):  # Secondary effect nodes
    tooltip = fro_in.split('%$#')[0] + ' is a \nsecondary effect cause \nacting on ' + to_in

    gra.edge(fro_in, to_in, color='tomato', constraint='false', tooltip=tooltip)


def mis_e(gra, fro_in, to_in):  # Misbehaviour Edge
    fro = fro_in[12:]
    to = to_in[7:]
    tooltip = fro.split('%$#')[0] + ' begins\nmisbehaviour ' + to

    gra.edge(fro, to, color='tomato', constraint='false', tooltip=tooltip)
