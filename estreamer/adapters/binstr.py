#********************************************************************
#      File:    binstr.py
#      Author:  Mike Souza / Sam Strachan
#
#      Description:
#       Handles binary string serialization
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
import estreamer


def _repack( message ):
    values = [
        struct.pack('>H', message['version']),
        struct.pack('>H', message['messageType']),
        struct.pack('>L', message['length']),
        message['data'] ]

    return b''.join( values )



def _asByteArray( wireData ):
    output = []
    for index in range( 0, len( wireData ) ):
        ( byte, ) = struct.unpack( '>B', wireData[ index : index + 1 ] )
        output.append( byte )

    return output



def _radixAsFormat( radix ):
    if radix == 2:
        return '0>08b'

    elif radix == 8:
        return '0>04o'

    elif radix == 16:
        return '0>02x'

    raise estreamer.EncoreException('Unknown formatter radix')



def _plain( byteArray, radix ):
    spec = _radixAsFormat( radix )
    output = []
    for byte in byteArray:
        output.append( format( byte, spec ) )

    return ''.join( output )



def _chart( byteArray ):
    separator = '{: >5}{:-<63}{:<1}'.format('|', '', '|')

    output = [
        '{:<4}{:<8}{:<6}{:>3}{: >8}{:>8}{:>8}{:>8}{:>8}{:>8}'.format(
            'Byte', '|', '0', '|', '1', '|', '2', '|', '3', '|'),
        'Bit |0|0|0|0|0|0|0|0|0|0|1|1|1|1|1|1|1|1|1|1|2|2|2|2|2|2|2|2|2|2|3|3|',
        '    |0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|6|7|8|9|0|1|',
        separator
    ]

    index = 0
    for byte in byteArray:
        if index == 0:
            line = '    |'

        # Double space byte with pipe after
        line += ' '.join( '{:0>08b}'.format( byte ) ) + '|'
        index += 1
        if index == 4:
            output.append( line )
            output.append( separator )
            index = 0

    if index > 0:
        output.append( line )
        output.append( separator )

    output.append('END')
    output.append('')

    return '\n'.join( output )



def dumps( message, asChart = False, radix = 2 ):
    """Serializes the incoming object as a binary string"""
    # Convert back to the raw wire data format
    wireData = _repack( message )

    # Now convert to a nice byte array
    byteArray = _asByteArray( wireData )

    # Now to the output
    if asChart:
        return _chart( byteArray )

    return _plain( byteArray, radix )
