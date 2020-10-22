
#********************************************************************
#      File:    error.py
#      Author:  Sam Strachan
#
#      Description:
#       This file creates an error message
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

class ErrorMessage( Base ):
    """Error message"""
    def __init__( self, message ):
        super( ErrorMessage, self ).__init__(
            definitions.MESSAGE_TYPE_ERROR,
            '>HHLlH' )

        errorCode = -1
        self.append( errorCode, 4 )

        messageUtf8 = message.encode('utf-8')

        self.append( len(messageUtf8), 2 )
        self.append( messageUtf8, len(messageUtf8), '{0}s'.format(len(messageUtf8)) )
