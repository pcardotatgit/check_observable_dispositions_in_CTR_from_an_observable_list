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
aims to store Security Backends API keys that will be used in others scripts
'''

from crayons import blue, green, red
from inspect import currentframe
import requests
import json

# Constants

AMP = {"host": "api.eu.amp.cisco.com"}
#AMP = {"host": "api.amp.cisco.com"}
#AMP = {"host": "localhost:4000"}

# User Input

# Your Webex Teams TOKEN
WEBEX_TEAMS_ACCESS_TOKEN = ""

# Cisco AMP
AMP_API_KEY = "xxxxxxxxxxxxxxxxxxxxxxxxxxx"
AMP_CLIENT_ID = "yyyyyyyyyyyyyyyyyyyy"

THREATGRID = {"host": "panacea.threatgrid.com"}

THREATGRID_API_KEY='xxxxxxxxxxxxxxxxxxxxxx'

CTR_CLIENT_ID='client-xxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
CTR_API_KEY='xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'

# Helper functions
def get_line():
    currentfram=currentframe()
    return currentfram.f_back.f_lineno