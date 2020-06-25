
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
        message = estreamer.message.EventStreamRequestMessage( timestamp, flags )
        self.logger.info( 'Request message={0}'.format(
            binascii.hexlify( message.getWireData() )))

        try:
            self.logger.info( 'Sending request message' )
            connection.request( message )

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
