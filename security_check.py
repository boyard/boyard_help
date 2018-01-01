#!/usr/bin/python

import requests
from datetime import datetime as dtg
import json
import logging
import requests
import argparse
import sys
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('security_checker')
logger.debug(str(dtg.now()) + ': check started')


def get_cmdb_data(device_type):
    """
    Get data from observium database based on the device_type

    Should return dictionary of:
    ID, Hostname, OS_Version

    :return: dict
    """
    pass


def psirt_get_token():
    """
    get an access token

    TODO: Need to add a tracking file for timeframe of the token
          This will keep the app from calling a new token if the
          current token is still valid

    TODO: Add exception handling

    :return:
    """
    creds = json.load(open('creds.json'))
    psirt_headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    psirt_payload = {
        'client_id': creds['CLIENT_ID'],
        'client_secret': creds['CLIENT_SECRET'],
        'grant_type': 'client_credentials'
    }
    url = 'https://cloudsso.cisco.com/as/token.oauth2'
    response = requests.post(url=url, data=psirt_payload, headers=psirt_headers).json()
    logger.debug('access_token_check = ' + response['access_token'])
    return response['access_token']

def psirt_query(token):
    """
    Send required information to PSIRT API and return true if vulnerable?

    {"access_token":"blablablablabla","token_type":"Bearer","expires_in":3599}

    TODO: Add exception handling

    :return: bool
    """
    url = 'https://api.cisco.com/security/advisories/cvrf/latest/10'
    headers = {
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token,
    }
    last_10_vulns = requests.get(url, headers=headers)
    logger.info('query response code = ' + str(last_10_vulns.status_code))
    logger.debug(last_10_vulns)

    
# Search the CVE service offered by CircLU (https://www.circl.lu/services/cve-search/)
# https://github.com/znb/Scripts/blob/7f22a727073ba1185e06b9ef42475f33279c645e/Security/cve-search.py

def search_cve(_cve):
    """Simple CVE search"""
    print "Searching: " + _cve
    SEARCHURL = "http://cve.circl.lu/api/cve/" + _cve
    r = requests.get(SEARCHURL)
    if r.status_code != 200:
        sys.exit("Something has gone horribly wrong.")
    else:
        data = json.loads(r.text)
        print "Summary: " + data['summary']
        print "CVSS Score: " + str(data['cvss'])


def show_vendor_product(_vendor, _product):
    """Show a specific product for a vendor"""
    print "Searching: " + _product + " from " + _vendor
    SEARCHURL =  "http://cve.circl.lu/api/search/" + _vendor + "/" + _product
    r = requests.get(SEARCHURL)
    if r.status_code != 200:
        sys.exit("Something has gone horribly wrong.")
    else:
        jdata = json.loads(r.text)
        for item in jdata:
            print "\nSummary: " + item['summary']
            print "CVE: " + item['id']
            print "CVSS: " + str(item['cvss'])


def list_vendor_products(_vendor):
    """Search for a vendor"""
    print "Vendor Search: " + _vendor,
    SEARCHURL = "http://cve.circl.lu/api/browse/" + _vendor
    r = requests.get(SEARCHURL)
    if r.status_code != 200:
        sys.exit("Something has gone horribly wrong.")
    else:
        print " ... " + str(r.status_code)
        try:
            data = json.loads(r.text)['product']
            print "Available products from " + _vendor
            for item in data:
                print item
        except:
            sys.exit("[!!] Vendor not in list")


def list_vendors():
    """List all the available vendors in the API"""
    print "Listing Vendors",
    SEARCHURL = "http://cve.circl.lu/api/browse"
    r = requests.get(SEARCHURL)
    if r.status_code != 200:
        sys.exit("Something has gone horribly wrong.")
    else:
        print " ... " + str(r.status_code)
        data = json.loads(r.text)['vendor']
        print "Available Vendors: "
        for item in data:
            print item


def __main__():
    """Get this party started"""
    parser = argparse.ArgumentParser(description='CIRCL CVE API Search')
    parser.add_argument('--list-vendors', '-l', dest='listvendors', action='store_true', help='List the available vendors')
    parser.add_argument('--product', '-p', dest='product', help='Search for a product')
    parser.add_argument('--vendors', '-v', dest='vendor', help='Search for a vendor')
    parser.add_argument('--cve', '-c', dest='cve', help='Search for this CVE')
    parser.add_argument('--version', '-V', action='version', version='%(prog)s 0.1')
    args = parser.parse_args()
    _cve = args.cve
    _product = args.product
    _vendor = args.vendor
    _listvendors = args.listvendors

    # TODO: This needs to be improved
    if (args.vendor and args.product):
        show_vendor_product(_vendor, _product)
    else:
        if args.cve:
            search_cve(_cve)
        elif (args.vendor and not args.product):
            list_vendor_products(_vendor)
        elif args.listvendors:
            list_vendors()

if __name__ == '__main__':
    __main__()

    
def update_vluln_table():
    """
    Do you want to track this in another DB or just have a report?

    add Date, CMDB_ID, Hostname, is_vuln=True
    :return:
    """

def create_vuln_report():
    """
    Create Vulnerability report based on data pulled from APIs

    :return html
    """

psirt_query(psirt_get_token())
