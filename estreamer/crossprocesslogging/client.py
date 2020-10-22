
#********************************************************************
#      File:    client.py
#      Author:  Sam Strachan
#
#      Description:
#       Cross process logging client
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

from estreamer.crossprocesslogging.baseClient import BaseClient

class Client( BaseClient ):
    """Multi process logging client"""
    def __init__( self, queue, name = None, level = 0 ):
        super( Client, self).__init__( name, level )
        self.queue = queue



    def emit( self, message ):
        self.queue.put( message )
