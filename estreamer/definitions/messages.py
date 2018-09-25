
#********************************************************************
#      File:    messages.py
#      Author:  Sam Strachan / Huxley Barbee
#
#      Description:
#       This file contains all structures pertinent to messages
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

MESSAGE_VERSION = 1

MESSAGE_STREAMING_INFORMATION_REQUEST_SERVICE_ID = 6667

# Message Type
MESSAGE_TYPE_NULL                   = 0
MESSAGE_TYPE_ERROR                  = 1
MESSAGE_TYPE_EVENT_STREAM_REQUEST   = 2
MESSAGE_TYPE_EVENT_DATA             = 4
MESSAGE_TYPE_HOST_DATA_REQUEST      = 5
MESSAGE_TYPE_SINGLE_HOST_DATA       = 6
MESSAGE_TYPE_MULTIPLE_HOST_DATA     = 7
MESSAGE_TYPE_STREAMING_REQUEST      = 2049
MESSAGE_TYPE_STREAMING_INFORMATION  = 2051
MESSAGE_TYPE_MESSAGE_BUNDLE         = 4002

# Request Flag Type
MESSAGE_REQUEST_PACKET_DATA         = 1
MESSAGE_REQUEST_IMPACT              = 1 << 5
MESSAGE_REQUEST_INTRUSION           = 1 << 6
MESSAGE_REQUEST_METADATA            = 1 << 20
MESSAGE_REQUEST_ARCHIVE_TIMESTAMPS  = 1 << 23
MESSAGE_REQUEST_EVENT_EXTRA_DATA    = 1 << 27
MESSAGE_REQUEST_POLICY              = 1 << 29
MESSAGE_REQUEST_EXTENDED            = 1 << 30

# Extended requests
MESSAGE_EXTENDED_REQUEST_INTRUSION      = { 'version': 9 , 'code': 12 }
MESSAGE_EXTENDED_REQUEST_METADATA       = { 'version': 4 , 'code': 21 }
MESSAGE_EXTENDED_REQUEST_CORRELATION    = { 'version': 9 , 'code': 31 }
MESSAGE_EXTENDED_REQUEST_DISCOVERY      = { 'version': 11 , 'code': 61 }
MESSAGE_EXTENDED_REQUEST_CONNECTION     = { 'version': 14 , 'code': 71 }
MESSAGE_EXTENDED_REQUEST_USER           = { 'version': 4 , 'code': 91 }
MESSAGE_EXTENDED_REQUEST_MALWARE        = { 'version': 7 , 'code': 101 }
MESSAGE_EXTENDED_REQUEST_FILE           = { 'version': 6 , 'code': 111 }
MESSAGE_EXTENDED_REQUEST_IMPACT         = { 'version': 2 , 'code': 131 }
MESSAGE_EXTENDED_REQUEST_TERMINATE      = { 'version': 0 , 'code': 0 }
