
#********************************************************************
#      File:    __init__.py
#      Author:  Sam Strachan
#
#      Description:
#       message package
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

import struct
from estreamer.message.eventstream import EventStreamRequestMessage
from estreamer.message.streaming import StreamingRequestMessage
from estreamer.message.null import NullMessage
from estreamer.message.error import ErrorMessage

def parse( binary ):
    """Parses binary into a message dict"""
    ( version, messageType, messageLength ) = struct.unpack( '>HHL', binary[0:8] )

    message = {
        'length': messageLength,
        'version': version,
        'messageType': messageType,
        'data': binary[8:]
    }

    return message
