
#********************************************************************
#      File:    jsonpath.py
#      Author:  Sam Strachan
#
#      Description:
#       Very basic implementation of jsonpath
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
import json
import os
from estreamer.exception import EncoreException
from estreamer.exception import ParsingException

def _parse( query ):
    keys = []
    element = ''
    index = 0
    while index < len( query ):
        if query[index] == '.':
            if len( element ):
                keys.append( element )
                element = ''

        elif query[index] == '[':
            if len( element ):
                keys.append( element )
                element = ''

            close = query.find(']', index )
            key = query[index + 1 : close]
            if key.startswith('\'') and key.endswith('\''):
                key = key[1:-1]

            else:
                key = int( key )

            keys.append( key )
            index = close

        else:
            element += query[index]

        index += 1

    if len( element ):
        keys.append( element )

    return keys



def _read( node, keys ):
    data = node
    # First key should always be $, ignore
    for index in range(1, len( keys )):
        key = keys[index]
        if isinstance( data, dict ):
            if key in data:
                data = data[key]

            else:
                raise ParsingException('Key "{0}" does not exist in node'.format( key ))

        elif isinstance( data, list ):
            if key > -1 and key < len( data ):
                data = data[key]

            else:
                raise ParsingException('Key "{0}" does not exist in node'.format( key ))

    return data



def _write( node, keys, value ):
    data = node
    for index in range(1, len( keys )):
        key = keys[index]
        if isinstance( data, dict ):
            # If this is the leaf node, write
            if index == len(keys) - 1:
                data[key] = value

            elif key in data:
                data = data[key]

            else:
                data[key] = {}
                data = data[key]

        elif isinstance( data, list ):
            if key > -1 and key < len( data ):
                data = data[key]

            else:
                raise ParsingException('Key "{0}" does not exist in node'.format( key ))



def _nodeValue( node, query, value = None ):
    try:
        keys = _parse( query )

    except:
        raise ParsingException('Bad query: {0}'.format( query ))

    if value is None:
        return _read( node, keys )

    _write( node, keys, value )



def _fileValue( filepath, query, value = None ):
    if not os.path.isfile( filepath ):
        raise EncoreException(
            'jsonpath: {0} does not exist or is not a file'.format( filepath ))

    with open( filepath, 'r' ) as jsonFile:
        try:
            dictionary = json.load( jsonFile )

        except ValueError as ex:
            raise ParsingException('Invalid JSON in file')

    if value is None:
        return val( dictionary, query )

    val( dictionary, query, value )

    with open( filepath, 'w' ) as jsonFile:
        jsonFile.write( json.dumps(
            dictionary,
            indent = 4,
            sort_keys = True) )



def val( data, query, value = None ):
    """
    Very basic implementation of jsonpath. All queries must start with $ and specify a full path
    """
    if isinstance( data, dict ):
        return _nodeValue( data, query, value )

    else:
        return _fileValue( data, query, value )
