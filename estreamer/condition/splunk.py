
#********************************************************************
#      File:    splunk.py
#      Author:  Sam Strachan
#
#      Description:
#       Returns status of Splunk process
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

import os
import subprocess
from estreamer.condition.base import BaseCondition

class SplunkCondition( BaseCondition ):
    """Class for evaluating if settings.enabled is true"""
    def __init__( self ):
        super( SplunkCondition, self ).__init__()

    def isTrue( self ):
        if os.name == 'posix':
            try:
                output = subprocess.check_output( [
                    'splunk',
                    'status' ] )

                return True

            except subprocess.CalledProcessError:
                # This is thrown on Linux
                return False

            except OSError:
                # This is thrown on Windows subsystem for Linux
                return False

        elif os.name == 'nt':
            processName = "splunkd.exe"
            output = subprocess.check_output( [
                'tasklist',
                '/FI',
                "ImageName eq " + processName ] )

            return output.find( processName ) > -1



    def message( self ):
        return 'Splunk is not running.'
