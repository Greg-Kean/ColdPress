#!/usr/bin/env python3
#

import json
import requests
import vt
from ..modules import NativeModule

'''
#Module accepts URLs as input and returns a URL analysis using VirusTotal
'''

def tempRun(urlIn):
    apikey = None
    with open('config/apikeys.json', 'r') as fp:
        apiconf = json.load(fp)
    apikey = apiconf.get('vt_apikey', None)

    if apikey == None:
        print("vt api key not found. Did you put it in apikeys.conf in the same directory as run.py?")
        
    #Getting analysis identifier
    url = "https://www.virustotal.com/api/v3/urls"
    
    payload = { "url" : urlIn }
    headers = { "accept": "application/json",
        "x-apikey": apikey,
        "content-type": "application/x-www-form-urlencoded"
    }
        
    response = requests.post(url, data=payload, headers=headers)
    if not response.ok:
        print("Error getting response")
        exit(1)
    jsonResponse = response.json()
        
    #Use identifier to get actual analysis results
    url = jsonResponse["data"]["links"]["self"]
        
    headers = { "accept": "application/json",
        "x-apikey": apikey,
    }
        
    response = requests.get(url, headers=headers)
    output= response.json()
    return output

#Class name has to be capitalized module name
class Url(NativeModule): #Native vs external module to be investigated

    speedType = "slow"
    threaded = False
    
    #include author
    __author__ = "Greg Kean"
    __email__ = "gregorykean@outlook.com"
    __description__ = "Query info about URL using VirusTotal. Need API key"
    
    
    def setup(self, sample_path, start_path, output_path):
        self.setup_done = False
        
        self.sample_path = sample_path
        self.start_path = start_path
        self.output_path = output_path
        
        apikey = None
        with open('config/apikeys.json', 'r') as fp:
            apiconf = json.load(fp)
        apikey = apiconf.get('vt_apikey', None)

        if apikey == None:
            print(
                "vt api key not found. Did you put it in apikeys.conf in the same directory as run.py?")

        self.client = vt.Client(apikey)
        self.setup_done = True
        print('[virustotal] module setup done!')
    
    
    def run(self, urlIn):
        '''
        setup needs to run before this
        '''
        
        if not self.setup_done:
            print("setup not done, cannot run.")
            return

        self.output = {}
        
        #Getting analysis identifier
        url = "https://www.virustotal.com/api/v3/urls"
    
        payload = { "url" : urlIn }
        headers = { "accept": "application/json",
            "x-apikey": apikey,
            "content-type": "application/x-www-form-urlencoded"
        }
        
        response = requests.post(url, data=payload, headers=headers)
        if not response.ok:
            print("Error getting response")
            exit(1)
        jsonResponse = response.json()
        
        #Use identifier to get actual analysis results
        url = "https://www.virustotal.com/api/v3/analyses"
        url += jsonResponse["id"]
        
        headers = { "accept": "application/json",
            "x-apikey": apikey,
        }
        
        response = requests.get(url, headers=headers)
        
        self.output= response
    
    def get_output(self):
        return self.output
