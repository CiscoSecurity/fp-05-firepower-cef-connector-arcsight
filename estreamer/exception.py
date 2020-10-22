
#********************************************************************
#      File:    exception.py
#      Author:  Sam Strachan
#
#      Description:
#       Encore specific exceptions
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

#pylint: disable=W0703
class EncoreException( Exception ):
    """Encore exeption base class"""
    pass



class ParsingException( EncoreException ):
    """Parsing exception"""
    pass



class TimeoutException( EncoreException ):
    """Timeout exception"""
    pass



class ConnectionClosedException( EncoreException ):
    """Connection closed exception"""
    pass



class UnsupportedTimestampException( EncoreException ):
    """Unsupported timestamp exception"""
    pass



class MessageErrorException( EncoreException ):
    """eStreamer message error exception"""
    def __init__( self, param ):
        message = 'MessageErrorException'
        if isinstance( param, dict ):
            try:
                import estreamer.adapters.binary
                error = estreamer.adapters.binary.loads( param )
                message = '{0}: {1}'.format( error['code'], error['text'] )
            except Exception:
                import estreamer.adapters.base64
                message = estreamer.adapters.base64.dumps( param )

        else:
            message = param

        super( MessageErrorException, self ).__init__( message )
