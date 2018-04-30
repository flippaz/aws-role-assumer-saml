import boto3
import requests
import base64
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
import logging
import re
from urlparse import urlparse, urlunparse

SAML_URL = 'https://location.to.adfs/idpinitiatedsignon.aspx?LoginToRP=urn:amazon:webservices'

logger = logging.getLogger('saml')

def send_saml_request(username, password, role_to_assume, subrole_to_assume):
    assertion = None

    session = requests.Session()
    formresponse = session.get(SAML_URL, verify=True)
    idpauthformsubmiturl = formresponse.url

    formsoup = BeautifulSoup(formresponse.text.decode('utf8'), "html.parser")
    payload = {}

    for inputtag in formsoup.find_all(re.compile('(INPUT|input)')):
        name = inputtag.get('name','')
        value = inputtag.get('value','')
        if "user" in name.lower():
            #Make an educated guess that this is the right field for the username
            payload[name] = username
        elif "email" in name.lower():
            #Some IdPs also label the username field as 'email'
            payload[name] = username
        elif "pass" in name.lower():
            #Make an educated guess that this is the right field for the password
            payload[name] = password
        else:
            #Simply populate the parameter with the existing value (picks up hidden fields in the login form)
            payload[name] = value

    for inputtag in formsoup.find_all(re.compile('(FORM|form)')):
        action = inputtag.get('action')
        loginid = inputtag.get('id')
        if (action and loginid == "loginForm"):
            parsedurl = urlparse(SAML_URL)
            idpauthformsubmiturl = parsedurl.scheme + "://" + parsedurl.netloc + action

    response = session.post(
        idpauthformsubmiturl,
        data=payload,
        verify=True
    )

    try:
        # Decode the response and extract the SAML assertion
        soup = BeautifulSoup(response.text.decode('utf8'), "html.parser")

        for inputtag in soup.find_all('input'):
            if (inputtag.get('name') == 'SAMLResponse'):
                assertion = inputtag.get('value')

        if (assertion == ''):
            raise Exception()

        awsroles = []
        root = ET.fromstring(base64.b64decode(assertion))

        for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
            if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
                for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                    awsroles.append(saml2attributevalue.text)

        if not len(awsroles):
            raise Exception()

    except Exception as e:
        raise Exception('Invalid login/password combination or the user is missing in SAML')

    sts = boto3.client('sts')

    try:
        logger.info('Available roles for the user "{}" are "{}"'.format(username, " ".join(awsroles)))
        has_role = False
        assumed_role_arn = None
        assumed_principal_arn = None

        for awsrole in awsroles:
            chunks = awsrole.split(',')
            if'saml-provider' in chunks[0]:
                newawsrole = chunks[1] + ',' + chunks[0]
                index = awsroles.index(awsrole)
                awsroles.insert(index, newawsrole)
                awsroles.remove(awsrole)

        if len(awsroles) > 0:
            i = 0
            # print "Available roles for user {}".format(username)
            for awsrole in awsroles:
                # print '[', i, ']: ', awsrole.split(',')[0]
                i += 1
                role_arn = awsrole.split(',')[0]
                principal_arn = awsrole.split(',')[1]

                if role_to_assume == role_arn:
                    logger.info('Role to assume "{}"'.format(role_to_assume))
                    has_role = True
                    assumed_role_arn = role_arn
                    assumed_principal_arn = principal_arn

        if not has_role:
            raise Exception()

        # print ""
        # print "Role to assume {}".format(assumed_role_arn)

        primary_role = sts.assume_role_with_saml(RoleArn=assumed_role_arn, PrincipalArn=assumed_principal_arn, SAMLAssertion=assertion)

    except Exception as e:
        raise Exception('The role "{}" is not available for "{}" user'.format(role_to_assume, username))

    try:
        if subrole_to_assume:
            logger.info('Attempting to assume sub role "{}" from primary role "{}"'.format(subrole_to_assume, assumed_role_arn))

            subrole_client = boto3.client(
                    "sts",
                    aws_access_key_id=primary_role['Credentials']['AccessKeyId'],
                    aws_secret_access_key=primary_role['Credentials']['SecretAccessKey'],
                    aws_session_token=primary_role['Credentials']['SessionToken']
                )

            return subrole_client.assume_role(RoleArn=subrole_to_assume, RoleSessionName='subrole_assume')

        return primary_role

    except Exception as e:
        raise Exception('The subrole "{}" is not available for "{}"'.format(subrole_to_assume, assumed_role_arn))


def main(username, password, role, subrole):

    token = send_saml_request(username, password, role, subrole)

    return {
        'aws_access_key_id': token['Credentials']['AccessKeyId'],
        'aws_secret_access_key': token['Credentials']['SecretAccessKey'],
        'aws_session_token': token['Credentials']['SessionToken']
    }
