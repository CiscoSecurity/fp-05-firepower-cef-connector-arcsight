
#********************************************************************
#      File:    stdOutClient.py
#      Author:  Sam Strachan
#
#      Description:
#       Logging client which outputs to StdOut. This is useful right
#       at the start of things where we haven't even had time to setup
#       and create a logging server (or worse, the logging server goes
#       wrong)
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

import sys
from estreamer.common import convert
from estreamer.crossprocesslogging import LevelStrings
from estreamer.crossprocesslogging.baseClient import BaseClient

class StdOutClient( BaseClient ):
    """StdOut logging client - always available but not really
    process safe"""
    def __init__( self, name = '', level = 0 ):
        super( StdOutClient, self).__init__(name, level)



    def __levelString( self, level ):
        try:
            return LevelStrings[level]
        except KeyError:
            return level



    def emit( self, message ):
        sys.stdout.write( '{0} {1}\t{2}\t{3}\n'.format(
            convert.toIso8601( message['time'] ),
            message['name'],
            self.__levelString( message['level'] ),
            message['data'],
        ))
