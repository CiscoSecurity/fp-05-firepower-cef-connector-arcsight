"""
Pretty writes the wire message out to a nice human readable string.
Probably only useful for debugging
"""
#********************************************************************
#      File:    pretty.py
#      Author:  Sam Strachan / Huxley Barbee
#
#      Description:
#       Pretty adapter
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
import binascii
import datetime
import estreamer.streams
import estreamer.definitions as definitions

COMMON = [
    'version',
    'messageType',
    'length',
    'recordType',
    'archiveTimestamp'
]

def __trait( value, indent = 0 ):
    writer = estreamer.streams.StringStream()

    for key, val in value.items():
        if key in COMMON:
            continue

        if key == 'record' or key == 'packetData':
            writer.write( key )
            writer.write( ': ' )
            writer.write( binascii.hexlify( val) )
            writer.write( '\n' )
            continue

        writer.write( '\t' * indent )
        writer.write( str( key ) )
        writer.write( ': ' )

        if isinstance( val, dict ):
            writer.write( '\n' )
            trait = __trait( val, indent + 1 )
            writer.write( trait )

        elif isinstance( val, list ):
            writer.write( '\n' )
            traits = __traits( val, indent + 1 )
            writer.write( traits )

        else:
            writer.write( val )
            writer.write( '\n' )

    return writer.string()



def __traits( valueList, indent ):
    writer = estreamer.streams.StringStream()

    for index in range( 0, len( valueList ) ):
        writer.write( '\t' * indent )
        writer.write( str( index ) )
        writer.write( ': \n')

        trait = __trait( valueList[ index ], indent + 1 )
        writer.write( trait )

    return writer.string()



def dumps( val, indent = 0):
    """Writes the incoming record as a pretty string"""
    writer = estreamer.streams.StringStream()

    for trait in COMMON:
        if trait not in val:
            continue

        writer.write( trait )
        writer.write( ': ' )

        if trait == 'archiveTimestamp':
            epoch = val[ trait ]

            if epoch == 0:
                writer.write( '0' )

            else:
                timestamp = \
                    datetime.datetime.fromtimestamp(epoch).strftime('%Y-%m-%d %H:%M:%S')

                writer.write( timestamp )
        else:
            writer.write( str( val[ trait ] ) )

        if trait == 'messageType':
            if val[ trait ] == 4:
                writer.write(' (Data)')


        elif trait == 'recordType':
            recordType = val[ trait ]
            writer.write( ' (' )

            if recordType in definitions.RECORDS:
                writer.write( definitions.RECORDS[ recordType ][ 'category' ] )

            else:
                writer.write( 'Unknown (undocumented?) Record Type' )

            writer.write( ')' )

        writer.write( '\n' )

    writer.write( '=' * 12 )
    writer.write( '\n' )

    trait = __trait( val, indent )
    writer.write( trait )
    return writer.string()
