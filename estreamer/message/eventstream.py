
#********************************************************************
#      File:    eventstream.py
#      Author:  Sam Strachan / Huxley Barbee
#
#      Description:
#       Creates an event stream message - the initial message sent
#       at the start of an eStreamer session
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

class EventStreamRequestMessage( Base ):
    """
    Class which represents the Event Stream Request Message Format.
    Format is defined on page 26+ (or 2-10/11) of the 6.0.0 spec
    """
    def __init__( self, timestamp, flags ):
        super( EventStreamRequestMessage, self ).__init__(
            definitions.MESSAGE_TYPE_EVENT_STREAM_REQUEST,
            '>HHLLL' )

        self.append( timestamp, 4 )
        self.append( flags, 4 )
