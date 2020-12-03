
#********************************************************************
#      File:    diagnostics.py
#      Author:  Sam Strachan
#
#      Description:
#       Performs basic connection diagnostics without a full multi-process
#       execution of the whole software
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

from sys import getsizeof
import argparse
import binascii
import getpass
import os
import sys
import time

# Use this to avoid pyc bytecode everywhere
sys.dont_write_bytecode = True

# Path hack.
WORKING_DIRECTORY = os.path.abspath( os.path.dirname(__file__) + '/..')
sys.path.append(WORKING_DIRECTORY )

# Allow late imports,Exception
#pylint: disable=C0413,W0703
import estreamer
import estreamer.adapters.base64
import estreamer.adapters.binary
import estreamer.definitions as definitions
import estreamer.message
import estreamer.crossprocesslogging
import estreamer.pipeline

JSON_MESSAGE = {
    'length': 1195,
    'version': 1,
    'data': binascii.unhexlify(
         '00010002000004ab5fc84faa000000007b0a20202020224576656e7473223a0a202020207b0a202020202020202022436f6e6e656374696f6e4576656e74223a0a20202020202020207b0a202020202020202020202020224669656c64536574446566223a0a2020202020202020202020207b0a20202020202020202020202020202020224f75747075744669656c64536574223a205b224865616465724669656c64536574222c2022436f6e6e656374696f6e4b6579536574222c202244657461696c4669656c64536574225d0a2020202020202020202020207d2c0a202020202020202020202020224669656c6473223a205b224f75747075744669656c64536574225d0a20202020202020207d2c0a202020202020202022496e74727573696f6e4576656e74223a0a20202020202020207b0a202020202020202020202020224669656c64536574446566223a0a2020202020202020202020207b0a20202020202020202020202020202020224f75747075744669656c64536574223a205b224865616465724669656c64536574222c2022436f6e6e656374696f6e4b6579536574222c202244657461696c4669656c64536574222c2022496d70616374225d0a2020202020202020202020207d2c0a202020202020202020202020224669656c6473223a205b224f75747075744669656c64536574225d0a20202020202020207d2c0a20202020202020202246696c654576656e74223a0a20202020202020207b0a202020202020202020202020224669656c64536574446566223a0a2020202020202020202020207b0a20202020202020202020202020202020224f75747075744669656c64536574223a205b224865616465724669656c64536574222c2022436f6e6e656374696f6e4b6579536574222c202244657461696c4669656c64536574225d0a2020202020202020202020207d2c0a202020202020202020202020224669656c6473223a205b224f75747075744669656c64536574225d0a20202020202020207d0a202020207d2c0a20202020224f7574707574466f726d6174223a0a202020207b0a2020202020202020225472616e73666f726d223a202254657874222c0a2020202020202020225472616e73666f726d436f6e666967223a0a20202020202020207b0a20202020202020202020202022546578745374617274223a20227b222c0a2020202020202020202020202254657874456e64223a20227d222c0a2020202020202020202020202241727261795374617274223a20225b222c0a202020202020202020202020224172726179456e64223a20225d222c0a202020202020202020202020224c6162656c536570617261746f72223a20223a222c0a202020202020202020202020224669656c64536570617261746f72223a20222c20222c0a2020202020202020202020202256616c7565536570617261746f72223a20225c7530304136222c0a2020202020202020202020202251756f74654c6162656c223a20747275652c0a2020202020202020202020202251756f74654e6f6e4e756d65726963223a20747275652c0a202020202020202020202020224669656c6473223a205b224f75747075744669656c64536574225d0a20202020202020207d0a202020207d0a7d'
    ),
    'messageType': 1
}


class Diagnostics( object ):
    """Diagnostics class helps find out what's going on"""
    def __init__( self, settings ):
        self.settings = settings
        self.logger = estreamer.crossprocesslogging.getLogger( self.__class__.__name__ )



    def execute( self ):
        """Executes a simple diagnostic run"""
        if self.settings.reprocessPkcs12:
            self.logger.info( 'Clearing certificate and key' )
            estreamer.Crypto.create( settings = self.settings ).clean()

        self.logger.info( 'Check certificate' )
        try:
            estreamer.Crypto.create( settings = self.settings )

        except estreamer.EncoreException:
            self.logger.info( 'PKCS12 file needs processing' )

            # Wait half a second for logs to be written otherwise password prompt gets lost
            time.sleep( definitions.TIME_PAUSE )

            try:
                password = getpass.getpass( prompt = definitions.STRING_PASSWORD_PROMPT )

            except EOFError:
                raise estreamer.EncoreException( definitions.STRING_PASSWORD_STDIN_EOF )

            try:
                estreamer.Crypto.create( settings = self.settings, password = password )

            except estreamer.EncoreException:
                raise

        self.logger.info( 'Creating connection' )
        connection = estreamer.Connection( self.settings )
        connection.connect()

        self.logger.info( 'Creating request message' )
        timestamp = definitions.TIMESTAMP_NOW
        flags = self.settings.requestFlags()
        
#        message = estreamer.message.EventStreamRequestMessage( timestamp, flags )
        
#        message = JSON_MESSAGE
#        self.logger.info( 'Request message={0}'.format(
#            binascii.hexlify( message.getWireData()  )))

        try:
            self.logger.info( 'Sending request message' )

            connection.request( JSON_MESSAGE )

            self.logger.info( 'Receiving response message' )
            response = connection.response()

        except estreamer.ConnectionClosedException:
            self.logger.error( definitions.STRING_CONNECTION_CLOSED )
            raise

        self.logger.info( 'Response message={0}'.format(
            estreamer.adapters.base64.dumps( response )))


        if response['messageType'] == definitions.MESSAGE_TYPE_STREAMING_INFORMATION:
            self.logger.info( 'Streaming info response' )

        elif response['messageType'] == definitions.MESSAGE_TYPE_MESSAGE_BUNDLE:
            self.logger.info( 'Bundle' )

        elif response['messageType'] == definitions.MESSAGE_TYPE_NULL:
            self.logger.info( 'Null' )

        elif response['messageType'] == definitions.MESSAGE_TYPE_EVENT_DATA:
            self.logger.info( 'Parsing response message' )
            record = estreamer.pipeline.parse( response, self.settings )

            self.logger.info('Response record={0}'.format( record ))

        elif response['messageType'] == definitions.MESSAGE_TYPE_ERROR:
            self.logger.error( 'Error message received: {0}'.format(
                estreamer.adapters.base64.dumps( message ) ))

        else:
            self.logger.warning( 'Unknown message received: {0}'.format(
                estreamer.adapters.base64.dumps( message ) ))


        self.logger.info('Connection successful')



    @staticmethod
    def main():
        """
        CLI entry point
        """
        estreamer.crossprocesslogging.IsMultiProcess = False
        logger = estreamer.crossprocesslogging.StdOutClient(
            Diagnostics.__name__,
            estreamer.crossprocesslogging.DEBUG)

        try:
            parser = argparse.ArgumentParser( description = 'Runs estreamer diagnostics' )
            parser.add_argument(
                'configFilepath',
                help = 'The filepath of the config file')

            parser.add_argument(
                '--pkcs12',
                action = "count",
                help = 'Reprocess pkcs12 file')

            args = parser.parse_args()

            logger.info( 'Checking that configFilepath ({0}) exists'.format(
                args.configFilepath ))

            settings = estreamer.Settings.create( args.configFilepath )

            if args.pkcs12:
                settings.reprocessPkcs12 = True

            estreamer.crossprocesslogging.configure( settings )

            diagnostics = Diagnostics( settings )
            diagnostics.execute()

        except estreamer.EncoreException as ex:
            logger.error(ex)

        except Exception as ex:
            logger.exception(ex)



if __name__ == '__main__':
    Diagnostics.main()
