'''
in the FMC you can perform a hit count analysis for a policy against a singe FTD appliance.  to see if a rule is taking hits on any device
you need to manually run the hit count for each FTD.  this script will perform hitcount analysis for a policy against all devices in inventory
and then offer multiple options on how to report in the output.

Detailed Report: One line item for every device that hits on a rule.  this can become big quickly for large policies and device inventories
Most Recent Hit Only: One line item per rule, listing only the device/timestamp with the most recent hit
Zero Hits Only: List only rules that have no hits across all devices
'''

# BASE_URL needs to be updated with IP of your FMC

# Developed and tested with the following environment
# - OS: windows
# - Python: version 3.11.5
# - Target platform:  FMC 7.0.4
# - Limitations: functions to get policies, devices and policy hits lazily assume paging is not required.  
#               updates to implement paging will be required if the query excedes a single page in your environment
# - Other comments:  code coule be updated to only perform check against devices actually assigned the policy rather than all devices in inventory.  
#                   this wasn't required for the environment this code was written for

import requests
from requests.auth import HTTPBasicAuth
import json
import sys


# Disable SSL warnings
import urllib3
urllib3.disable_warnings()

# FMC URL/IP
BASE_URL = 'https://192.168.1.1'

# login to FMC and return the value of auth tokens and domain UUID from the response headers
# exit with an error message if a valid response is not received
def login():
    print('\n\nEnter FMC Credentials')
    user = input("USERNAME: ").strip()
    passwd = input("PASSWORD: ").strip()
    response = requests.post(
       BASE_URL + '/api/fmc_platform/v1/auth/generatetoken',
       auth=HTTPBasicAuth(username=user, password=passwd),
       headers={'content-type': 'application/json'},
       verify=False,
    )
    if response:
        return {'X-auth-access-token': response.headers['X-auth-access-token'], 
        'X-auth-refresh-token':response.headers['X-auth-refresh-token'],
        'DOMAIN_UUID':response.headers['DOMAIN_UUID']}
    else:
        sys.exit('Unable to connect to ' + BASE_URL + ' using supplied credentials')

#retrieve the list of access control policies in FMC
def get_policies(token, DUUID):
    response = requests.get(
       BASE_URL + '/api/fmc_config/v1/domain/' + DUUID + '/policy/accesspolicies',
       headers={'X-auth-access-token':token},
       verify=False,
    )
    raw = response.json()
    return raw

#for a given acess control policy ID, get all the rules using 'expanded' for full detail
#limit is set to 1000.  if your ACP has more than 1000 rules this will need to be update
#to deal with paging
def getRules(token, DUUID, acpID):
    response = requests.get(
       BASE_URL + '/api/fmc_config/v1/domain/' + DUUID + '/policy/accesspolicies/' + acpID + '/accessrules?limit=1000&expanded=true',
       headers={'X-auth-access-token':token},
       verify=False,
    )
    data = response.json()
    return data['items']

#get a list of all devices in inventory
def get_devicerecords(token, DUUID):

    #query paramaters to control results limit and offset. 1000 is max limit
    limit = str(1000)
    offset = str(0)
    querystring = {'offset':offset,'limit':limit}
    
    #perform the query
    response = requests.get(
       BASE_URL + '/api/fmc_config/v1/domain/' + DUUID + '/devices/devicerecords?expanded=true',
       headers={'X-auth-access-token':token},
       params=querystring,
       verify=False,
    )
    
    data = response.json()
    return data['items']

#get the rule hitcount information for a given policy and device
def get_policy_hits(token, DUUID, policy_id, device_id):

    #query paramaters to control results
    limit = str(1000)
    offset = str(0)
    #cisco documentation shows filter should be in format "deviceID:{id}" but it does not work with the {} braces
    querystring = {'offset':offset,
                   'limit':limit,
                   'filter':'"deviceId:' + device_id + '"',
                   'expanded':'true'}
    
    #perform the query
    response = requests.get(
        BASE_URL + '/api/fmc_config/v1/domain/' + DUUID + '/policy/accesspolicies/' + policy_id + '/operational/hitcounts',
       headers={'X-auth-access-token':token},
       params=querystring,
       verify=False,
    )

    data = response.json()
    return data['items']

def main():

    #login and retrieve token and DUUID
    result = login()
    token = result.get('X-auth-access-token')
    DUUID = result.get('DOMAIN_UUID')

    #get the list of access control policies in FMC
    policies = get_policies(token, DUUID)
    
    #prompt for input on which policy to examine
    counter = 0
    print('Policies found')
    for item in policies['items']:
        counter = counter +1
        print('[',counter,']',item['name'])
    entry = int(input('Enter the number of the policy you want to export: '))
    policy_id = policies['items'][entry -1]['id']

    #get the rules associated with the policy
    print('Gathering policy rules.....')
    rules = getRules(token, DUUID, policy_id)
    
    #get device list
    print('Getting device list....')
    devices = get_devicerecords(token, DUUID)

    #populate rule list dicts with new fields
    print('Initializing objects with new keys....')
    for rule in rules:
        rule['devices'] = [] #list of all devices that hit on a rule
        rule['lastHit'] = '' #timestamp of most recent hit from any device
        rule['lastDevice'] = '' #device name of the most recent hit

    
    #update rules items with hitcount information
    print('Analyzing hit counts....')
    for device in devices:
        print('Inspecting device ' + device['name'])
        hits = get_policy_hits(token, DUUID, policy_id, device['id'])
        for rule in rules:
            for hit in hits:
                if rule['id'] == hit['rule']['id']:
                    if hit['hitCount'] > 0:
                        device_hit = (device['name'], hit['lastHitTimeStamp'], hit['hitCount'])
                        rule['devices'].append(device_hit)
                        if hit['lastHitTimeStamp'] > rule['lastHit']:
                            rule['lastHit'] = hit['lastHitTimeStamp']
                            rule['lastDevice'] = device['name']
                    break

    #write the output file header
    # with open('fmc-policy-hits.csv', 'w') as file:
    #     file.write('Rule ID,Rule Name,Device,Last Hit,Hits\n')

    #get user report type selection
    print('Enter the option number for the report you would like')
    print('WARNING: The detailed report can be very large for environments with many appliances and large rule count policies')
    print('1) Detailed Report: One line item for every device that hits on a rule')
    print('2) Most Recent Hit Only: One line item per rule, listing only the device with the most recent hit')
    print('3) Zero Hits Only: List only rules that have no hits across all devices')
    selection = int(input(': '))
    while selection < 1 or selection > 3:
        print('Invalid option')
        print('Enter the option number')
        print('1) Detailed Report')
        print('2) Most Recent Hit Only')
        print('3) Zero Hits Only')
        selection = int(input(': '))
        
    #create the report output.  writing raw comma separated data seemed easier/lazier than using dict writer
    #considering the nested tuple in the dictionary objects
    
    #detailed report
    if selection == 1:
        with open('fmc-policy-hits.csv', 'w') as file:
            file.write('Rule ID,Rule Name,Device,Last Hit,Hits\n')
        with open('fmc-policy-hits.csv', 'a') as file:
            for rule in rules:
                if len(rule['devices']) == 0:
                    file.write(str(rule['metadata']['ruleIndex']) + ',' + rule['name'] + ',NO HITS FOUND,------,---\n')
                else:
                    for device in rule['devices']:
                        file.write(str(rule['metadata']['ruleIndex']) + ',' + rule['name'] + ',' + device[0] + ',' + device[1] + ',' + str(device[2]) + '\n')
    #most recent hits only
    elif selection == 2:
        with open('fmc-policy-hits.csv', 'w') as file:
            file.write('Rule ID,Rule Name,Most Recent Device,Last Hit\n')
        with open('fmc-policy-hits.csv', 'a') as file:
            for rule in rules:
                if rule['lastDevice'] == '':
                    file.write(str(rule['metadata']['ruleIndex']) + ',' + rule['name'] + ',NO HITS FOUND,------\n')
                else:
                    file.write(str(rule['metadata']['ruleIndex']) + ',' + rule['name'] + ',' + rule['lastDevice'] + ',' + rule['lastHit'] + '\n')
    #zero hits only
    elif selection == 3:
        with open('fmc-policy-hits.csv', 'w') as file:
            file.write('Rule ID,Rule Name,Device,Last Hit,Hits\n')
        with open('fmc-policy-hits.csv', 'a') as file:
            found = False
            for rule in rules:
                if len(rule['devices']) == 0:
                    found = True
                    file.write(str(rule['metadata']['ruleIndex']) + ',' + rule['name'] + ',NO HITS FOUND,------,---\n')
            if found == False:
                file.write('There were no rules found with 0 hits')


if __name__ == "__main__":
    main()
