"""
Transforms to and from key-value pair file lines and a dict
"""
#********************************************************************
#      File:    kvpair.py
#      Author:  Sam Strachan
#
#      Description:
#       kvpair adapter
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
from estreamer.common import convert



def __parseValue( line, start ):
    key1 = start
    equals = line.find('=', key1)

    if equals != -1:
        # Take care of key first
        key2 = equals
        key = line[key1:key2]

        # Value is complicated by quotes
        isQuoted = line[equals + 1] == '"'
        val1 = equals + 1

        if isQuoted:
            val1 += 1
            val2 = line.find('"', val1)

            # if there isn't a closing quote then that's pretty bad but move on
            if val2 == -1:
                val2 = len(line)
        else:
            val2 = line.find(' ', val1)
            if val2 == -1:
                val2 = len(line)

        value = line[val1:val2].rstrip()

        if isQuoted:
            val2 += 1

        finish = val2 + 1
        if finish > len(line):
            finish = -1

        return (key, value, finish)
    else:
        return (None, None, None)



def loads( line ):
    """Parses a line into a dictionary"""
    start = 0
    items = {}

    while start != -1:
        (key, value, finish) = __parseValue(line, start)

        if key is None:
            break

        items[key] = convert.infer( value )
        start = finish

    return items



def loadsFile( lines ):
    """Parses a list of lines into dictionaries"""
    data = []
    for line in lines:
        items = loads( line.rstrip() )
        data.append(items)

    return data



def dumps(
        obj,
        delimiter = ', ',
        quoteEmptyString = False,
        quoteSpaces = True,
        sort = False,
        escapeNewLines = False ):

    """Serializes a dict to a key-value pair line"""
    items = []
    keys = obj.keys()

    if sort:
        keys = sorted( keys )

    for key in keys:
        value = obj[key]

        if isinstance( value, basestring ):
            if value.find(' ') > -1 and quoteSpaces:
                value = '"' + value + '"'

            elif value.find('=') > -1:
                value = '"' + value + '"'

            if quoteEmptyString and len( value ) == 0:
                value = '""'

            if escapeNewLines:
                value = value.replace('\n', '\\n').replace('\r', '')

            items.append(key + '=' + value)

        elif isinstance( value, uuid.UUID ):
            items.append(key + '="' + str(value) + '"')

        else:
            items.append(key + '=' + str(value) )

    return delimiter.join(items)
