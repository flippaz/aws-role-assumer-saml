# AWS Role Assumer via SAML Authentication

A CLI to authenticate logins through SAML and assume a role available to the authenticated user.

## Prerequisites

1. Python 2.7
2. sudo pip install boto
3. sudo pip install requests
4. sudo pip install bs4
5. sudo apt-get install jq

## Usage
Edit SAML_URL in the saml_request.py file to the location of your organisation's ADFS Identity Provider.

Execute `./saml-cli.py --username <UserName> --role <RoleArn> [--password <Password>] [--subrole <SubRoleArn>] [--export]`.

1. Username - login username in the form of email address, ie. username@email.com
2. RoleArn - ARN of the Role to be assumed by the user
3. Password (optional) - password of the login username. If not specified, a password prompt will appear for user to enter password
4. SubRoleArn (optional) - ARN of the subsequent role to be assumed by the previous role (Given that the primary role has access to assume the sub role)
5. --export (optional) - Export the AWS access keys to a file instead. Use `source ~/.envvars` to import as environment variables

If authenticated and role is available to the account, the following JSON response will be returned:
```
{
    "aws_access_key_id": "XXXXXXXXXXXXXXXXXXXX",
    "aws_secret_access_key": "xxxx...",
    "aws_session_token": "xxxx..."
}
```
