
#********************************************************************
#      File:    ccad.py
#      Author:  Sam Strachan
#
#      Description:
#       Cisco Cloudlock App Discovery adapter. This is NOT production
#       ready.
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

import estreamer.adapters.csv
import estreamer.common
import estreamer.definitions as definitions
import estreamer

def dumps( source ):
    """Formats a connection event for CCAD"""
    # We are only interested in connection events
    if source['recordType'] != definitions.RECORD_RNA_CONNECTION_STATISTICS:
        return None

    # Create a flat wrapper
    record = estreamer.common.Flatdict( source, ignoreKeyErrors = True )

    # If no url, stop
    url = record['clientUrl.data']
    if len( url ) == 0:
        return None

    eventDatetime = record['@computed.eventDateTime'].split('T')

    username = record['@computed.user']
    if not username:
        username = '-'

    # # HACK - Very temporary hack
    # import datetime
    # dt = datetime.datetime.strptime( eventDatetime[0], '%Y-%m-%d' )
    # now = datetime.datetime.now()
    # lastMonth = now - datetime.timedelta( days = 28 )
    # dt = datetime.date( lastMonth.year, lastMonth.month, dt.day )
    # eventDatetime[0] = datetime.date.strftime( dt, '%Y-%m-%d' )
    # # HACK - Very temporary hack

    values = [
        eventDatetime[0],
        eventDatetime[1],
        record['initiatorIpAddress'],
        record['responderTransmittedBytes'],
        record['initiatorTransmittedBytes'],
        url,
        record['responderPort'],
        username
    ]

    items = []

    for value in values:
        items.append( estreamer.adapters.csv.toValue( value, quoteAlways = False ) )

    return ' '.join( items )
