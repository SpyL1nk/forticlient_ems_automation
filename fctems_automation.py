#!/usr/bin/env python3

# Copyright 2022 Alexandre Moreau <a.moreau@spyl1nk.net>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import requests
import json
import configparser
import logging
import os
import re
import sys
import csv
from optparse import OptionParser

requests.packages.urllib3.disable_warnings()

def init_logging(logpath):
    """Initialize and return an Logger object.

    Returns
    -------
        logger: logger
            The logger object.
    """
    global logger

    prog = os.path.basename(logpath)

    # create logger
    logger = logging.getLogger(prog)
    logger.setLevel(logging.DEBUG)

    # create console handler and set level to debug
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    # create formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # add formatter to ch
    ch.setFormatter(formatter)

    # add ch to logger
    logger.addHandler(ch)

    return logger

def init_fctems(file=".fctems"):
    """Retrieve FortiClient EMS API credentials from the configuration file.
    Parameters
    ----------
    file: str
        The config file in INI format (default to .fctems)

    Returns
    -------
    fctems_url: str
        The FortiCare URL.
    fctems_username: str
        The FortiClient EMS username.
    fctems_password: str
        The FortiClient EMS password.
    """
    config = configparser.ConfigParser()
    config.read(file)
    section = "fctems"

    try:
        fctems_url           = config[section]["fctems_url"]
        fctems_username      = config[section]["fctems_username"]
        fctems_password      = config[section]["fctems_password"]
    except KeyError as k:
        logger.error('Missing key {} in configuration file "{}"'.format(k, file))
        quit()

    logger.debug(f"FortiClient EMS URL: {fctems_url}, FortiClient EMS username: {fctems_username}, \
        FortiClient EMS password: {fctems_password}")

    return fctems_url, fctems_username, fctems_password

def fctems_login(session, headers, fctems_url, fctems_username, fctems_password):
    """Login to the FortiClient EMS API

    Parameters
    ----------
    session: requests.Session
        A shared requests session object.
    session: dict
        Headers to be used in the requests
    fctems_url: str
        The FortiCare URL.
    fctems_username: str
        The FortiClient EMS username.
    fctems_password: str
        The FortiClient EMS password.

    Returns
    -------
    fctems_x-csrftoken: str
        The FortiClient EMS session CSRF token.
    """

    json_payload = {
        "name": fctems_username,
        "password": fctems_password
    }

    logger.debug("Payload to post is:")
    logger.debug(json.dumps(json_payload, indent=4))

    url = fctems_url + "api/v1/auth/signin"
    r = session.post(url=url, json=json_payload, headers=headers, verify=False, timeout=10)

    logger.debug('FortiClient EMS login operation terminated with "%s"' % r.json()['result']['message'])
    logger.debug("JSON output is:")
    logger.debug(json.dumps(r.json(), indent=4))

    try:
        return session.cookies.get_dict()['csrftoken']
    except KeyError as k:
        logger.error('Missing cookie "csrftoken" in the response. Failed to login.')


def fctems_list_endpoint(session, headers, fctems_url):
    """Retrieve endpoints from FortiClient EMS API

    Parameters
    ----------
    session: requests.Session
        A shared requests session object.
    session: dict
        Headers to be used in the requests
    fctems_url: str
        The FortiClient EMS URL.

    Returns
    -------
    endpoint_list: list
        A list containing endpoints.
    """

    url = fctems_url + "api/v1/endpoints/index"
    r = session.get(url=url, headers=headers, verify=False, timeout=10)

    logger.debug('FortiClient EMS endpoint list operation terminated with "%s"' % r.json()['result']['message'])
    logger.debug("JSON output is:")
    logger.debug(json.dumps(r.json(), indent=4))

    return r.json()['data']['endpoints']

def fctems_delete_endpoint(session, headers, fctems_url, device_id):
    """Delete endpoint from FortiClient EMS API

    Parameters
    ----------
    session: requests.Session
        A shared requests session object.
    session: dict
        Headers to be used in the requests
    fctems_url: str
        The FortiClient EMS URL.
    device_id: str
        Device ID to delete from the FortiClient EMS.

    Returns
    -------

    """

    url = fctems_url + "api/v1/devices/delete"
    params = {'ids[]': device_id}
    r = session.delete(url=url, headers=headers, params=params, verify=False, timeout=10)

    logger.debug('FortiClient EMS delete endpoint operation terminated with "%s"' % r.json()['result']['message'])
    logger.debug("JSON output is:")
    logger.debug(json.dumps(r.json(), indent=4))

    return

def csv_parser(csv_file):
    """Login to the FortiClient EMS API

    Parameters
    ----------
    csv_file: str
        File path to CSV.

    Returns
    -------
    endpoint_list: list
        List of endpoints to work with
    """
    endpoint_list = []
    try:
        with open(csv_file, newline='', encoding='utf-8-sig') as csvfile:
            csv_reader = csv.reader(csvfile, delimiter=';')
            line_count = 0
            for row in csv_reader:
                endpoint_list.append({'device_id': str(row[0]), 'device_name': str(row[1])})
                print(row[0])
                print(row[1])
                line_count += 1


    except EnvironmentError: # parent of IOError, OSError *and* WindowsError where available
        logger.error('Failed to open the CSV file provided. Please check if the filepath is correct.')
        print('Failed to open the CSV file provided. Please check if the filepath is correct.')

    logger.info('Parsed %d endpoints for the CSV file %s' % (line_count, csv_file))
    print('Parsed %d endpoints for the CSV file %s' % (line_count, csv_file))
    print(endpoint_list)
    return endpoint_list

if __name__ == "__main__":

    parser = OptionParser()

    parser.add_option("-f", "--file",
                  dest = "filename",
                  help = "import CSV file",
                  metavar = "FILE")
    parser.add_option("-l", "--logfile",
                  dest = "logfile",
                  help = "log filename",
                  metavar = "FILE")
    #TODO: Add action (list, delete, etc.)

    (options, args) = parser.parse_args()

    if (options.filename == None):
            print (parser.usage)
            exit(0)
    else:
            csv_file = options.filename

    if (options.logfile == None):
            logfilename = './fctems_automation.log'
    else:
            logfilename = options.logfile

    init_logging(logfilename)

    fctems_url, fctems_username, fctems_password = init_fctems()

    endpoint_list = csv_parser(csv_file)

    # Shared Requests session for cookie and header persistence
    s = requests.Session()

    headers = {
        'Ems-Call-Type': '2'
    }

    fctems_x_csrftoken = fctems_login(s, headers, fctems_url, fctems_username, fctems_password)

    headers['Referer']      = fctems_url
    headers['X-CSRFToken']  = fctems_x_csrftoken

    for endpoint in endpoint_list:
        logger.debug('Deleting device %s (ID: %s)...' % (endpoint['device_name'], endpoint['device_id']))
        fctems_delete_endpoint(s, headers, fctems_url, endpoint['device_id'])
        logger.info('Deleted device %s (ID: %s) successfully!' % (endpoint['device_name'], endpoint['device_id']))
        print('Deleted device %s (ID: %s) successfully!' % (endpoint['device_name'], endpoint['device_id']))
