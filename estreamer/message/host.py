
#********************************************************************
#      File:    host.py
#      Author:  Sam Strachan
#
#      Description:
#       Creates a host request message
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

from estreamer.message.base import Base
import estreamer.definitions as definitions

class HostRequestMessage( Base ):
    """
    Class which represents the Host Request Message Format.
    Format is defined on page 41+ (or 2-25) of the 6.0.0 spec
    """
    def __init__( self, startIp, finishIp ):
        super( HostRequestMessage, self ).__init__(
            definitions.MESSAGE_TYPE_HOST_DATA_REQUEST,
            '>HHLLLLLLLLLLL' )

        # dataType: Request multiple hosts v5.0+
        self.append( 7, 4 )

        # flags: notes + banner
        self.append( 1 | 2, 4 )

        # ip addresses
        self.append( startIp, 16 )
        self.append( finishIp, 16 )
