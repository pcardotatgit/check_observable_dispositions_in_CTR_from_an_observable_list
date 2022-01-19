#!/usr/bin/env python
'''
Copyright (c) 2022 Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.

What is this :
This script reads the text file sha256_observables.txt that contains a list of sha256 and queries AMP4E in order to output hostnames of infected hosts
'''
import requests
import time
from datetime import datetime
import json
import sys
from pathlib import Path
from crayons import blue, green, yellow, white, red,cyan
from requests.packages.urllib3.exceptions import InsecureRequestWarning

import environment_api_keys as env

client_id=env.AMP_CLIENT_ID
api_key=env.AMP_API_KEY

debug=0
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def get_hostname_from_sha(query_params="",
    host=env.AMP.get("host"),
    client_id=env.AMP_CLIENT_ID,
    api_key=env.AMP_API_KEY,
):
    """Get a list of recent events from Cisco AMP."""
    print("\n==> Getting events from AMP") 
    url = f"https://{client_id}:{api_key}@{host}/v1/events"
    response = requests.get(url, params=query_params, verify=False)
    if debug:
        print(cyan(env.get_line(),bold=True))
        print(cyan(response.json()))      
    # Consider any status other than 2xx an error
    response.raise_for_status()
    events_list = response.json()
    if debug:    
        events_list = response.json()
        print(green((events_list)))
        for events in events_list:
            #hostname=event['computer']['hostname'] 
            print(red(events))
    hostname=""
    if response.json()['data']:   
        hostname=response.json()['data'][0]['computer']['hostname']
        print(hostname)
    else:
        print(red('NO RESULT',bold=True))                
    return hostname     

    events_list = response.json()['data']
    return events_list

def go():
    line_content = []
    with open('sha256_observables.txt') as inputfile:
        for line in inputfile:
            if line[0] == "#" or line.strip() == "something to skip":
                pass
            else:
                ligne=line.strip()
                #ligne=ligne.split('":"')[1]
                #ligne=ligne.replace('"}}','')
                line_content.append(ligne)            
    # loop through all content
    with open('resultat_amp_events.txt','w') as file:
        for sha256 in line_content:
            print (sha256)
            amp_query_params = f"detection_sha256={sha256}"  
            hostname=get_hostname_from_sha(query_params=amp_query_params)            
            file.write(sha256)
            file.write('\n')
            file.write('\n')
    
if __name__ == "__main__":
    go()