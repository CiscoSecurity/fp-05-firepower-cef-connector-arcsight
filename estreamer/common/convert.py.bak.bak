
#********************************************************************
#      File:    convert.py
#      Author:  Sam Strachan
#
#      Description:
#       Common conversion functions
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

import uuid
import datetime
from estreamer import UnsupportedTimestampException

def isNull(value):
    """Returns True if \"NULL\""""
    return value == "NULL"



def isBoolean(value):
    """Returns True if \"True\" or \"False\""""
    return value == "True" or value == "False"



def isInt(value):
    """Returns True if convertible to integer"""
    try:
        int(value)
        return True
    except (ValueError, TypeError):
        return False



def isUint16( value ):
    """Returns True if convertible to uint16"""
    try:
        uint16 = int(value)
        return uint16 > -1 and uint16 < 1 << 16
    except (ValueError, TypeError):
        return False



def isFloat(value):
    """Returns True if convertible to float"""
    try:
        float(value)
        return True
    except (ValueError, TypeError):
        return False



def isUuid(value):
    """Returns true if convertible to UUID"""
    try:
        uuid.UUID(value)
        return True
    except (ValueError, TypeError):
        return False



def infer(value):
    """Converts a string to a native datatype. This will infer the
    type trying NULL > bool > int > float > uuid > string"""
    if isNull(value):
        return None

    if isBoolean(value):
        return bool(value)

    if isInt(value):
        return int(value)

    if isFloat(value):
        return float(value)

    if isUuid(value):
        return uuid.UUID(value)

    return value



def toTypedArray( string, delimiter ):
    """Converts a delimited string to a typed array. e.g. "1,2,3" will return
    [1,2,3]"""
    output = []
    values = string.split( delimiter )
    for value in values:
        if len(value.strip()):
            typed = infer( value.strip() )
            output.append( typed )

    return output



def toDatetime( timestamp ):
    """Returns a date if at all possible"""
    dateTime = None

    if isinstance( timestamp, int ) or isinstance( timestamp, float ):
        dateTime = datetime.datetime.fromtimestamp( timestamp )

    elif isinstance( timestamp, long ):
        dateTime = datetime.datetime.max

    elif isinstance( timestamp, datetime.date ):
        dateTime = timestamp

    elif timestamp is None:
        dateTime = datetime.datetime.min

    else:
        raise UnsupportedTimestampException('{0} ({1})'.format(
            timestamp,
            type( timestamp )
        ))

    return dateTime



def toIso8601( timestamp ):
    """Returns ISO 8601 string"""
    return toDatetime( timestamp ).isoformat()
