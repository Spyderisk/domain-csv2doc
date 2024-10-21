#!/usr/bin/env python3

import cgi
import urllib.parse

def main():
    # Get the query parameters
    form = cgi.FieldStorage()
    domain = form.getvalue('domain')
    version = form.getvalue('version')
    entity_type_encoded_uri = form.getvalue('type')
    entity_encoded_uri = form.getvalue('entity')

    # Decode the URL-encoded parameters
    entity_type_uri = urllib.parse.urlparse(entity_type_encoded_uri)
    entity_type_frag = urllib.parse.unquote(entity_type_uri.fragment)
    entity_uri = urllib.parse.urlparse(entity_encoded_uri)
    entity_frag = urllib.parse.unquote(entity_uri.fragment)

    # Get specific folder for giveen entity type
    type_folder = get_type_folder(entity_type_frag)

    # Construct the documantation URL. TODO: configure this
    doc_url = f"https://spyderisk.org/documentation/knowledgebase/{domain}/{version}/{type_folder}/{entity_frag}"

    # Redirect to the new URL
    print("Status: 302 Found")
    print(f"Location: {doc_url}")
    print()

def get_type_folder(type_frag):
    if type_frag == "Class":
        folder = "asset"
    elif type_frag == "ControlStrategy":
        folder = "csg"
    elif type_frag == "TrustworthinessAttribute":
        folder = "twa"
    else:
        folder = type_frag.replace("Pattern", "").lower()

    return folder

if __name__ == "__main__":
    main()

