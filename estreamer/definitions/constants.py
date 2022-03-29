
#********************************************************************
#      File:    constants.py
#      Author:  Sam Strachan
#
#      Description:
#       Constants
#
#      Copyright (c) 2017 by Cisco Systems, Inc.
#
#       ALL RIGHTS RESERVED. THESE SOURCE FILES ARE THE SOLE PROPERTY
#       OF CISCO SYSTEMS, Inc. AND CONTAIN CONFIDENTIAL  AND PROPRIETARY
#       INFORMATION.  REPRODUCTION OR DUPLICATION BY ANY MEANS OF ANY
#       PORTION OF THIS SOFTWARE WITHOUT PRIOR WRITTEN CONSENT OF
#       CISCO SYSTEMS, Inc. IS STRICTLY PROHIBITED.
#
#*********************************************************************/

#pylint: disable=C0301

EXIT_ERROR_CODE = 1

STRING_CONNECTION_CLOSED = """The FMC eStreamer server has closed the connection. There are a number of possible causes which may show above in the error log.

If you see no errors then this could be that:
 * the server is shutting down
 * there has been a client authentication failure (please check that your outbound IP address matches that associated with your certificate - note that if your device is subject to NAT then the certificate IP must match the upstream NAT IP)
 * there is a problem with the server. If you are running FMC v6.0, you may need to install "Sourcefire 3D Defense Center S3 Hotfix AZ 6.1.0.3-1"
"""

STRING_CONNECTION_COULD_NOT_CONNECT = """Could not connect to eStreamer Server at all. Are you sure the host and port are correct? If so then perhaps it is a firewall issue."""
STRING_CONNECTION_SSL_ERROR = """SSL Error {0}.

If you are seeing a certificate revoked error then the certificate has probably been deleted on the FMC server.

If you have downloaded a new pkcs12 file and you are still seeing this, you need to remove the following files cached key and cert files:
    {1}
    {2}
"""

STRING_CONNECTION_INVALID_HEADER = """The server returned an invalid version ({0}) - expected 1.

This is likely to be caused by CSCve44987 which is present on some versions between FMC 6.1.0.3 and 6.2.

You need to upgrade your FMC. For more information see: https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve44987.

Message={1}"""


STRING_PASSWORD_PROMPT = 'Please enter the PKCS12 password (press <enter> for blank password): '
STRING_PASSWORD_STDIN_EOF = 'Unable to read password from console. Are you running as a background process? Try running in test or foreground mode'


STRING_PREFLIGHT_PKCS12_MISSING = """The pkcs12 file specified in your config ({1}) does not exist.
        
In order to run eNcore you need to have a public-private key pair issued by your FMC.
This key pair is delivered in a pkcs12 file. In order to generate one you will need
to log into your FMC and navigate to:

    System > Integration > eStreamer

Once there, create a "New client" and enter the IP address of this device as the host.
Please note that the FMC will validate your connection by comparing the IP address it sees
with the IP address in the certificate - if you are behind a NAT device you will need to
adjust the IP address accordingly.

Download and copy the pkcs12 file to:

    {0}

or edit your config file"""

STRING_PREFLIGHT_HOST = "You have not configured your FMC host"
STRING_PREFLIGHT_HOST_PROMPT = "Please enter it here (enter blank host to ignore)"

STRING_PREFLIGHT_EXIT = "Exiting"

STRING_PREFLIGHT_WRONG_PYTHON = """This software is currently only compatible with Python 2.7. You are running {0}. Exiting"""

STRING_INVALID_PORT = "Invalid port. Port must be an unsigned 16bit number. Current value: {0}"

STRING_PYOPENSSL_MISSING = """eNcore is unable to split the PKCS12 file because pyOpenSSL is not installed.

You have two options:

# 1. Install pyOpenSSL using pip: `pip install pyOpenSSL` and eNcore will do it for you

In order to install pip you will need to install the following packages e.g.:

    sudo yum install python-pip python-devel openssl-devel gcc
    sudo pip install pyOpenSSL

If you have problems installing these packages and you are running on CentOS / RHEL
then try enabling the EPEL repo. For more information see:

    https://fedoraproject.org/wiki/EPEL


# 2. Alternatively you can use a command line version of OpenSSL and run the following two commands

openssl pkcs12 -in "{0}" -nocerts -nodes -out "{1}"
openssl pkcs12 -in "{0}" -clcerts -nokeys -out "{2}"

"""
