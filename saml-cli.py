#!/usr/bin/python
import saml_request
import os
import logging
import requests
import argparse
import json
import subprocess
import getpass

from logging.handlers import RotatingFileHandler

logger = logging.getLogger('saml')
logger.addHandler(RotatingFileHandler(filename='/var/tmp/jenkins-saml', maxBytes=5120, backupCount=2))
logger.setLevel(logging.DEBUG)


def main(username, role, password=None, subrole=None, export_variables=False):
    try:
        if not password:
            password = getpass.getpass()

        if not username or not password:
            raise Exception('Missing username or password')
        logger.info('User "{}" is trying to authenticate with "{}" role '.format(username, role))
        response = saml_request.main(username, password, role, subrole)

        if response and export_variables:
            key = response['aws_access_key_id']
            secret = response['aws_secret_access_key']
            token = response['aws_session_token']

            with open(os.path.expanduser("~/.envvars"), "w") as outfile:
                outfile.write("export AWS_ACCESS_KEY_ID={}\n".format(key))
                outfile.write("export AWS_SECRET_ACCESS_KEY={}\n".format(secret))
                outfile.write("export AWS_SESSION_TOKEN={}\n".format(token))

        logger.info('User "{}" was authenticated against SAML'.format(username))

        if not export_variables:
            parser.exit(0, json.dumps(response, sort_keys=True, indent=4, separators=(',', ': ')) + "\n")
        else:
            print "Use \"source ~/.envvars\" to set environment variables"
    except Exception as e:
        logger.error('User "{}" FAILED to authenticated against SAML, message: {}'.format(username, str(e)))
        exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SAML authentication')
    parser.add_argument('--username', help='AD username', required=True)
    parser.add_argument('--role', help='Role ARN', required=True)
    parser.add_argument('--password', help='AD password', default=None)
    parser.add_argument('--subrole', help='Sub Role ARN to assume', dest='subrole', default=None)
    parser.add_argument('--export', help='Export to environment variables', action='store_true', dest='export_variables', default=False)

    args = parser.parse_args()

    main(**args.__dict__)
