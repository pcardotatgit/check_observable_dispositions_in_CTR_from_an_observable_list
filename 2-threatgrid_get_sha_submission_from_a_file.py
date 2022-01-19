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
This script reads the text file sha256_observables.txt that contains a list of sha256 and queries ThreatGrid in order to check for existing submissions for every sha256 
'''
import requests
import time
from datetime import datetime
import json
import sys
from pathlib import Path
from crayons import blue, green, yellow, white, red,cyan
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from environment_api_keys import THREATGRID  # noqa
from environment_api_keys import THREATGRID_API_KEY  # noqa


debug=0

def search_threatgrid_submissions(
    sha256,
    host=THREATGRID.get("host"),
    api_key=THREATGRID_API_KEY,
):
    """Search TreatGrid Submissions, by sha256.

    Args:
        sha256(str): Lookup this hash in ThreatGrid Submissions.
        host(str): The ThreatGrid host.
        api_key(str): Your ThreatGrid API key.
    """
    print(blue(f"\n==> Searching the ThreatGrid Submissions for: {sha256}"))

    query_parameters = {
        "q": sha256,
        "api_key": api_key,
    }
    
    response = requests.get(
        f"https://{host}/api/v2/search/submissions",
        params=query_parameters,
    )
    response.raise_for_status()

    submission_info = response.json()["data"]["items"]
    print(submission_info)

    if submission_info:
        print(green("Successfully retrieved data on the sha256 submission"))
    else:
        print(red("No data on the sha256 submission"))
    return submission_info  

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
	with open('resultat_TG.txt','w') as file:
		for sha256 in line_content:
			print (sha256)
			file.write(sha256)
			file.write('\n')
			file.write('\n')
			amp_query_params = f"detection_sha256={sha256}" 
			info=search_threatgrid_submissions(sha256,host=THREATGRID.get("host"),api_key=THREATGRID_API_KEY)
			for item in info:	
				out=json.dumps(item)
				print(out)
				file.write(out)
				file.write('\n')
				file.write('\n')
				file.write('\n')
			file.write('============================================================')
			file.write('\n')
			file.write('\n')
			file.write('\n')
if __name__ == "__main__":
	go()