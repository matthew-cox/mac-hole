#!/usr/bin/env python
'''
Download and merge host black lists
'''
import argparse
import logging
import json
import os
import re
import tempfile
import warnings
import yaml

import requests
#
##############################################################################
#
# Global Variables
#
# default sources file
CONFIG = './sources.yml'

DEFAULT_LOG_LEVEL = 'info'

DEFAULT_RISK_LEVEL = 'low'

RISK_LEVELS = {'low': 1, 'medium': 2, 'high': 3}

# global temp directory
THE_TEMP_DIR = tempfile.mkdtemp()
#
##############################################################################
#
# hosts_reduce()
#
def hosts_reduce(hosts={}, lines=None):
    '''
    hosts_reduce(hosts={}, lines=None):

    Take input lines and merge them into the current hash of hosts
    '''
    for line in lines.split('\n'):
        host_name = None
        if re.match('#', line) or re.match('\[', line) or line == '':
            continue
        elif re.search(' ', line):
            logging.debug("Compound line found. Processing '%s'...", line)
            line_parts = line.lower().split(' ')
            for part in line_parts:
                if re.match('#', part) or re.match('\[', part) or part == '':
                    continue
                elif re.search('\.[a-z]', part):
                    host_name = part
        else:
            host_name = line.lower()

        if host_name:
            logging.debug("Processing '%s'...", host_name)
            if host_name in hosts:
                hosts[host_name] += 1
            else:
                hosts[host_name] = 1

    return hosts
#
##############################################################################
#
# http_get()
#
def http_get(url=None, headers={}):
    '''
    http_get(url=None):

    Make an HTTP GET against the provided URL 
    '''
    req_body = None

    if None in [url]:
        logging.warn("Missing url")
        return req_body

    errors = 0

    logging.debug("Making the HTTP request...")
    import requests.exceptions
    try:
        req = requests.get(url, headers=headers, timeout=16)
        req_body = req.text.encode('utf-8').strip()

        # on the off chance the call actually returns an error code
        if req.status_code != 200:
            logging.warn("Request failed: '%s'", req_body)
            errors += 1
    except Exception as err:
        logging.warn("Request failed: '%s'", err)
        errors += 1

    if errors > 0:
        raise RuntimeError("Request failed. Encountered "
                           "'{}' error(s)".format(errors))

    return req_body
#
##############################################################################
#
# load_config_file()
#
def load_config_file(config_dir='.', config_path=None,
                     config_file_name='sources', config_file_type='yml'):
    '''
    Load the config information from the config file
    '''
    results = {}
    the_file = None
    if config_path:
        the_file = config_path
    else:
        the_path = os.sep.join([config_dir, config_file_name])
        the_file = '.'.join([the_path, config_file_type])

    if os.path.isfile(the_file):
        try:
            config_file = open(the_file, 'rb')
        # pylint: disable=broad-except
        except Exception, err:
            logging.warn("Unable to read config file: '%s'", err)
    else:
        warnings.warn('Unable to find config file', RuntimeWarning)

    if config_file_type == 'json':
        try:
            results = json.load(config_file)
        # pylint: disable=broad-except
        except Exception, err:
            logging.warn("Unable to load config file: '%s'", err)
        finally:
            config_file.close()
    elif config_file_type == 'yml':
        try:
            results = yaml.load(config_file)
        # pylint: disable=broad-except
        except Exception, err:
            logging.warn("Unable to load config file: '%s'", err)
        finally:
            config_file.close()
    return results
#
##############################################################################
#
# write_output()
#
def write_output(content=None, destination=None):
    '''
    write_output(content=None, destination=None)

    Take a string and write it to a local file path
    '''

    if None in [content, destination]:
        logging.warn("Missing content or destination file")
        return None

    out_file = None
    try:
        logging.debug("Writing output to '%s'", destination)
        out_file = open(destination, 'w')
        print >> out_file, content
    # pylint: disable=broad-except
    except Exception, err:
        raise RuntimeError("Unable to write output file: '%s'", err)
    finally:
        if out_file:
            out_file.close()
#
##############################################################################
#
# main()
#
def main():
    '''
    main()

    Handle the arguments and do all the work
    '''
    #
    # Handle CLI args
    #
    parser = argparse.ArgumentParser(description='Download blacklist sources '
                                                 'and combine them for DNSmasq')

    parser.add_argument('-c', '--config', default=CONFIG, action='store',
                        metavar='./path/to/the/config.yml',
                        help=('Which config file to use. Default: '
                              "'{}'".format(CONFIG)))

    parser.add_argument('-d', '--debug', default=False, action='store_true',
                        help='Enable additional output')

    parser.add_argument('-f', '--fake', default=False, action='store_true',
                        help='Fake it. Print what would be run, do not do it.')

    parser.add_argument('-l', '--log-level', action='store', required=False,
                        choices=["debug", "info", "warning", "error", "critical"],
                        default=DEFAULT_LOG_LEVEL,
                        help='Logging verbosity. Default: {}'.format(DEFAULT_LOG_LEVEL))

    parser.add_argument('-n', '--no-load', default=False, action='store_true',
                        help='Do not load the data to Redshift. Default: false')

    parser.add_argument('-r', '--risk', action='store', required=False,
                        choices=["low", "medium", "high"],
                        default=DEFAULT_RISK_LEVEL,
                        help='Which level of risk for false positives')

    args = parser.parse_args()

    # Enable the debug level logging when in debug mode
    if args.debug:
        args.log_level = 'debug'

    # Configure logging
    logging.basicConfig(format='%(levelname)s : %(module)s.%(funcName)s : %(message)s',
                        level=getattr(logging, args.log_level.upper()))

    #
    # Get our sources config
    #
    config = load_config_file()

    # handle the sources
    hosts = {}
    for name, source in config.iteritems():

        source_risk = source['risk'] or "high"
        if RISK_LEVELS[source_risk] <= RISK_LEVELS[args.risk]:
            try:
                logging.info("Downloading '%s'", name)
                content = http_get(source['url'])
                logging.info("Adding hosts from '%s'", name)
                hosts = hosts_reduce(hosts, content)
            except RuntimeError as err:
                logging.warn("Failed to download: '%s'", err)
                pass

    logging.info("Creating host file...")
    results = '\n'.join(sorted(hosts.keys()))
    write_output(results, "./host_file")

if __name__ == '__main__':
    main()
