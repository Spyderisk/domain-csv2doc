##///////////////////////////////////////////////////////////////////////
##
## (c) University of Southampton IT Innovation Centre, 2024
##
## Copyright in this software belongs to University of Southampton
## IT Innovation Centre, Southampton, SO17 1BJ, UK.
##
## This software may not be used, sold, licensed, transferred, copied
## or reproduced in whole or in part in any manner or form or in or
## on any media by any person other than in accordance with the terms
## of the Licence Agreement supplied with the software, or otherwise
## without the prior written consent of the copyright owners.
##
## This software is distributed WITHOUT ANY WARRANTY, without even the
## implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
## PURPOSE, except where stated in the Licence Agreement supplied with
## the software.
##
##      Created By :            Panos Melas
##      Created Date :          2024-10-25
##      Created for Project :   Telemetry
##
##///////////////////////////////////////////////////////////////////////

FROM ubuntu:22.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends apt-utils locales \
               python3-pip python3-dev python3-setuptools \
               build-essential libffi-dev graphviz \
               cron git \
    && rm -rf /var/lib/apt/lists/*

RUN locale-gen en_US.UTF-8

RUN mkdir /code

WORKDIR /code

# Copy code
COPY requirements.txt /code/requirements.txt

RUN pip3 install -r requirements.txt

# Copy the script into the image
COPY scripts/build-domain-docs.sh /root/build-domain-docs.sh
RUN chmod 0744 /root/build-domain-docs.sh

# Copy the cron job file into the cron.d directory
COPY scripts/cronjob /etc/cron.d/domain_docs
RUN chmod 0644 /etc/cron.d/domain_docs

# Create the log file to be able to run tail
RUN touch /var/log/cron.log

## Set up the needed ENV variable
#ENV PYTHONPATH=$PYTHONPATH:/code/app

# cleanup
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Apply cron job
RUN crontab /etc/cron.d/domain_docs

# Run the command on container startup
CMD cron && tail -f /var/log/cron.log
