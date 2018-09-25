
#********************************************************************
#      File:    preflight.py
#      Author:  Sam Strachan
#
#      Description:
#       Preflight does some checks in advance to see we have everything
#       needed to run
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
from __future__ import print_function
import os
import sys

# Use this to avoid pyc bytecode everywhere
sys.dont_write_bytecode = True

# Path hack.
WORKING_DIRECTORY = os.path.abspath( os.path.dirname( __file__ ) + '/..')
sys.path.append( WORKING_DIRECTORY )

# Allow late imports,Exception
#pylint: disable=C0413,W0703,E1101,W0613,W0212
import argparse
import estreamer.crossprocesslogging
import estreamer.definitions as definitions
import estreamer


class Preflight( object ):
    """
    Preflight does some checks in advance to see we have everything needed to run
    """

    def __init__( self ):
        estreamer.crossprocesslogging.IsMultiProcess = False
        estreamer.crossprocesslogging._configure(
            None,
            estreamer.crossprocesslogging.INFO,
            '%(message)s',
            True,
            False )

        self.logger = estreamer.crossprocesslogging.getLogger( self.__class__.__name__ )
        self.args = self._processarguments()



    def _processarguments( self ):
        parser = argparse.ArgumentParser(description='Runs eStreamer eNcore pre-flight checks')
        parser.add_argument(
            'filepath',
            help = 'The filepath of the config file')

        parser.add_argument(
            '--nostdin',
            dest = 'nostdin',
            action = 'store_true',
            help = 'Indicates no stdin available')

        return parser.parse_args()



    def _isPython27( self ):
        return sys.version.startswith( '2.7' )



    def _isPyUnicodeUCS2( self ):
        return sys.maxunicode < 0x10000



    def main( self ):
        """
        Main command line entry point
        """
        try:
            self.logger.debug('Checking python version')
            if self._isPython27():
                self.logger.debug('I am version 2.7')

            else:
                self.logger.error( definitions.STRING_PREFLIGHT_WRONG_PYTHON.format( sys.version ) )

            self.logger.debug('Checking python version')
            if self._isPyUnicodeUCS2():
                self.logger.debug('I am UnicodeUCS2')

            else:
                self.logger.debug('I am UnicodeUCS4' )

            self.logger.debug('Checking settings')
            settings = estreamer.Settings.create( self.args.filepath )

            if not os.path.isfile( settings.pkcs12Filepath ):
                self.logger.error( definitions.STRING_PREFLIGHT_PKCS12_MISSING.format(
                    os.path.abspath( settings.pkcs12Filepath ),
                    self.args.filepath ))

                sys.exit( definitions.EXIT_ERROR_CODE )

            if settings.host in [ '', '1.2.3.4' ]:
                self.logger.info( definitions.STRING_PREFLIGHT_HOST )

                host = ''
                if not self.args.nostdin:
                    self.logger.info( definitions.STRING_PREFLIGHT_HOST_PROMPT )
                    host = sys.stdin.readline().rstrip()

                    if len( host ) == 0:
                        self.logger.info( definitions.STRING_PREFLIGHT_EXIT )
                        sys.exit( definitions.EXIT_ERROR_CODE )

                    else:
                        estreamer.Configure().run( self.args.filepath, host = host )
                        self.logger.info('Host updated to {0}'.format( host ))

                else:
                    sys.exit( definitions.EXIT_ERROR_CODE )


        except estreamer.EncoreException as ex:
            self.logger.error( ex )

        except Exception as ex:
            self.logger.exception( ex )



if __name__ == '__main__':
    Preflight().main()
