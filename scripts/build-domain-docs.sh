#!/bin/bash

## 
## Copyright 2024 The Spyderisk Licensors
##
##   Licensed under the Apache License, Version 2.0 (the "License");
##   you may not use this file except in compliance with the License.
##   You may obtain a copy of the License at:
##
##       http://www.apache.org/licenses/LICENSE-2.0
##
##   Unless required by applicable law or agreed to in writing, software
##   distributed under the License is distributed on an "AS IS" BASIS,
##   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
##   See the License for the specific language governing permissions and
##   limitations under the License.
##
## <!-- SPDX-License-Identifier: Apache 2.0 -->
## <!-- SPDX-FileCopyrightText: 2024 The Spyderisk Licensors -->
## <!-- SPDX-ArtifactOfProjectName: Spyderisk -->
## <!-- SPDX-FileType: Source code -->
## <!-- SPDX-FileComment: Original by Panos Melas, Dan Shearer July 2024 -->

# The purpose of this script is to do an anonymous git pull of Spyderisk docs,
# and then for each branch tagged in the form "v3.5.0" to indicate a release, 
# run mkdocs from https://mkdocs.org to regenerate the docs for that release. 
# Regenerating each time means that new configurations or versions of mkdocs
# are used, and pulling freshly from git each time means that there is less 
# chance of a versioning/tagging mixup or corruption. It would be possible to
# optimise for less processing but at higher risk of errors, so we don't do that.
#
# This script is intended to run from systemd/cron at regular intervals.
#
# Don't run this script as root, there is absolutely no need.
#
# Algorithm summary:
#
#   clone to $REPO_DIR/$REPO_NAME
#   for each release version in $TAG
#      generate mkdocs tree in $REPO_DIR/$OUTPUT_DIR/$TAG
#   move $REPO_DIR/$OUTPUT_DIR to wherever the webserver expects to find trees

echo "Start Spyderisk domain docs build script $(date +"%Y-%m-%d %H:%M:%S")"

GIT=/usr/bin/git
# Directory of the Git repository
REPO_DIR="/code/domain-docs-repo"
REPO_NAME="domain-network"
OUTPUT_DIR="/code/www/html"
INDEX_HTML="${OUTPUT_DIR}/index.html"

ErrorExit() {
	echo "`basename $0`:  Error exit: $1"
	exit 1
}

# Function to update the latest link
update_latest_link() {
    local version="$1"
    cd "$OUTPUT_DIR" || exit 1
    [ -L latest ] && rm latest
    ln -s "$version" latest
    echo "Updated latest link to version $version"
}

# Function to add the new item to the documentation index
add_to_index() {
    local version="$1"
    local new_item="<a href=\"/${version}/\">Domain model docs ${version}</a>"
    echo "add to index for $version"
    echo "new item: $new_item"
    sed -i "/<!-- Add more links to specific versions if needed -->/a\\
      <li>${new_item}</li>" "$INDEX_HTML"
    echo "Updated the documentation versions list with version $version"
}

# Function to generate docs for a specific tag
generate_docs() {
    local version="$1"
    cd /code || exit 1
    python3 generate_and_show.py "$REPO_DIR/$REPO_NAME" "$version"
    mv build "$OUTPUT_DIR/$version"
    rm -rf static
    echo "Built Spyderisk network docs for version $version"
}

if [[ ! -d $REPO_DIR ]]; then
    mkdir -p $REPO_DIR
    #ErrorExit "Top level $REPO_DIR does not exist: did you set it correctly in the script?"
else
	echo "write test" > $REPO_DIR/write_test
	if [[ ! $? ]]; then
		ErrorExit "Top level $REPO_DIR exists but is not writable"
        else
                rm $REPO_DIR/write_test
	fi
fi

cd $REPO_DIR

if [ -d "$REPO_DIR/$REPO_NAME" ]; then
    rm -rf $REPO_NAME
fi

$GIT clone https://github.com/Spyderisk/$REPO_NAME.git || ErrorExit "Git clone failed"
$GIT config --global --add safe.directory $REPO_DIR/$REPO_NAME

cd $REPO_NAME
TAGS=$($GIT tag 2>&1)

# Compare the tags and detect new ones
for i in $TAGS; do

    #if [[ $i =~ ^v[0-9]+[a-z].[0-9]+-[0-9]+-[0-9]+$ ]]; then
    if [[ $i =~ ^v6a6-[0-9]+-[0-9]+$ ]]; then
        if [[ ! -d "$OUTPUT_DIR/$i" ]]; then

            echo "preparing docs for release $i"

            git checkout "$i" || { echo "Failed to checkout $i"; continue; }

            generate_docs "$i"

            update_latest_link "$i"

            add_to_index "$i"

            cd $REPO_DIR/$REPO_NAME
        else
            echo "release $i is already done"
        fi
    else
        echo "skipping release $i"
    fi

done

echo "End Spyderisk domain docs build script"
