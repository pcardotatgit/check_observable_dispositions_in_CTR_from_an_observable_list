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
This script reads the text file named log.txt located in the same folder, and check the disposition of every SHA256 that it contains
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

CLIENT_ID=env.CTR_CLIENT_ID
CLIENT_PASSWORD=env.CTR_API_KEY

SESSION = requests.session()

debug=0

def generate_token():
    ''' Generate a new access token and write it to disk
    '''
    url = 'https://visibility.eu.amp.cisco.com/iroh/oauth2/token'

    headers = {'Content-Type':'application/x-www-form-urlencoded',
               'Accept':'application/json'}

    payload = {'grant_type':'client_credentials'}

    response = requests.post(url, headers=headers, auth=(CLIENT_ID, CLIENT_PASSWORD), data=payload)

    if unauthorized(response):
        sys.exit('Unable to generate new token!\nCheck your CLIENT_ID and CLIENT_PASSWORD')

    response_json = response.json()
    access_token = response_json['access_token']
    print(green('OK we got a new token',bold=True))

    with open('threat_response_token', 'w') as token_file:
        token_file.write(access_token)

def get_token():
    ''' Get the access token from disk if it's not there generate a new one
    '''
    for i in range(2):
        while True:
            try:
                with open('threat_response_token', 'r') as token_file:
                    access_token = token_file.read()
                    return access_token
            except FileNotFoundError:
                print(red('threat_response_token file not found, generating new token.',bold=True))
                generate_token()
            break

def inspect(observable):
    '''Inspect the provided obsrevable and determine it's type
    '''
    inspect_url = 'https://visibility.amp.cisco.com/iroh/iroh-inspect/inspect'

    access_token = get_token()

    headers = {'Authorization':'Bearer {}'.format(access_token),
               'Content-Type':'application/json',
               'Accept':'application/json'}

    inspect_payload = {'content':observable}
    inspect_payload = json.dumps(inspect_payload)

    response = SESSION.post(inspect_url, headers=headers, data=inspect_payload)
    return response

def enrich(observable):
    ''' Query the API for a observable
    '''
    enrich_url = 'https://visibility.amp.cisco.com/iroh/iroh-enrich/deliberate/observables'

    access_token = get_token()

    headers = {'Authorization':'Bearer {}'.format(access_token),
               'Content-Type':'application/json',
               'Accept':'application/json'}

    response = SESSION.post(enrich_url, headers=headers, data=observable)

    return response

def unauthorized(response):
    ''' Check the status code of the response
    '''
    if response.status_code == 401 or response.status_code == 400:
        return True
    return False

def check_auth(function, param):
    ''' Query the API and validate authentication was successful
        If authentication fails, generate a new token and try again
    '''
    response = function(param)
    if unauthorized(response):
        print(red('Auth failed, generating new token.',bold=True))
        generate_token()
        return function(param)
    return response

def query(observable):
    ''' Pass the functions and parameters to check_auth to query the API
        Return the final response
    '''
    response = check_auth(inspect, observable)
    inspect_output = response.text
    print(cyan(inspect_output,bold=True))
    if response.json()[0]['type']=='sha256':
        with open('sha256_observables.txt','a+') as file2:
            file2.write(response.json()[0]['value'])
            file2.write('\n')
    #inspect_output = observable
    response = check_auth(enrich, inspect_output)
    return response
    

def go():
    line_content = []
    # here under let's open the file to analyse
    with open('logs.txt') as inputfile:  # modify this part if you prefer to read the source file to analyse from another location
        for line in inputfile:
            if line[0] == "#" or line.strip() == "something to skip":
                pass
            else:
                ligne=line.strip()
                #ligne=ligne.split('":"')[1]
                #ligne=ligne.replace('"}}','')
                line_content.append(ligne)            
            # loop through all content
        with open('result.txt','w') as file:
            for observable in line_content:
                print (observable)
                response = query(observable)
                response_json = response.json()
                
                print(response_json)

                for module in response_json['data']:
                    module_name = module['module']
                    if 'verdicts' in module['data'] and module['data']['verdicts']['count'] > 0:
                        docs = module['data']['verdicts']['docs']
                        for doc in docs:
                            observable_value = doc['observable']['value']
                            disposition = doc.get('disposition', 'None')
                            disposition_name = doc.get('disposition_name', 'None')
                            ligne_out='{};{:<23};{:<5};{:<13}'.format(observable_value,module_name,
                                                               disposition,
                                                               disposition_name
                                                               )
                            print(yellow(ligne_out,bold=True))
                            file.write(ligne_out)
                            file.write('\n')
                    else:
                        print(green('Good News : No Verdict for this one',bold=True))
                        ligne_out='{};No Verdict;Good News;'.format(observable)                        
                        file.write(ligne_out)
                        file.write('\n')
        
if __name__ == "__main__":
    file=open('sha256_observables.txt','w')
    file.close()
    go()