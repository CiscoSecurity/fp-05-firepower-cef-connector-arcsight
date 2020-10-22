
#********************************************************************
#      File:    null.py
#      Author:  Sam Strachan / Huxley Barbee
#
#      Description:
#       Creates a null message
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

class NullMessage( Base ):
    """
    Definition for a Null message which is used to acknowledge receipt
    of a bundle
    """
    def __init__( self ):
        super( NullMessage, self ).__init__(
            definitions.MESSAGE_TYPE_NULL,
            '>HHL' )
