
#********************************************************************
#      File:    crypto.py
#      Author:  Sam Strachan
#
#      Description:
#       Abstracts common high level crypto functions away
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

import estreamer
import estreamer.definitions as definitions

class Crypto( object ):
    """Helper class to contain and extract certificate and key from pkcs12"""
    def __init__( self, privateKeyFilepath, certificateFilepath ):
        if not os.path.isfile( privateKeyFilepath ):
            raise estreamer.EncoreException(
                'privateKeyFilepath: {0} does not exist or is not a file'.format(
                    privateKeyFilepath ))

        if not os.path.isfile( certificateFilepath ):
            raise estreamer.EncoreException(
                'certificateFilepath: {0} does not exist or is not a file'.format(
                    certificateFilepath ))

        self.privateKeyFilepath = privateKeyFilepath
        self.certificateFilepath = certificateFilepath



    def clean( self ):
        """Cleans up temporary cert and key files"""
        if os.path.exists( self.privateKeyFilepath ):
            os.remove( self.privateKeyFilepath )

        if os.path.exists( self.certificateFilepath ):
            os.remove( self.certificateFilepath )



    @staticmethod
    def extract( pkcs12Filepath, password, privateKeyFilepath, certificateFilepath ):
        """Extracts the key and certificate"""
        try:
            import OpenSSL.crypto

        except ImportError:
            raise estreamer.EncoreException(
                definitions.STRING_PYOPENSSL_MISSING.format(
                    pkcs12Filepath,
                    privateKeyFilepath,
                    certificateFilepath ))

        with open( pkcs12Filepath, 'rb' ) as pkcs12File:
            data = pkcs12File.read()

        try:
            pkcs12 = OpenSSL.crypto.load_pkcs12( data, password )

        except OpenSSL.crypto.Error:
            raise estreamer.EncoreException(
                'Unable to process pkcs12 file. Possibly a password problem')

        certificate = pkcs12.get_certificate()
        privateKey = pkcs12.get_privatekey()

        # Where type is FILETYPE_PEM or FILETYPE_ASN1 (for DER).
        cryptoType = OpenSSL.crypto.FILETYPE_PEM

        with open( privateKeyFilepath, 'wb+' ) as privateKeyFile:
            privateKeyFile.write( OpenSSL.crypto.dump_privatekey( cryptoType, privateKey ) )

        with open( certificateFilepath, 'wb+' ) as certificateFile:
            certificateFile.write( OpenSSL.crypto.dump_certificate( cryptoType, certificate ) )



    @staticmethod
    def create( settings = None, password = None, pkcs12Filepath = None ):
        """
        Creates a Crypto instance from a local public / private key pair but throws
        an exception if the pair does not exist
        """
        if settings is not None:
            if password is None:
                return Crypto(
                    settings.privateKeyFilepath(),
                    settings.publicKeyFilepath())

            else:
                if not os.path.isfile( settings.pkcs12Filepath ):
                    raise estreamer.EncoreException(
                        'pkcs12Filepath: {0} does not exist or is not a file'.format(
                            settings.pkcs12Filepath ))

                certificateFilepath = settings.publicKeyFilepath()
                privateKeyFilepath = settings.privateKeyFilepath()

                Crypto.extract(
                    settings.pkcs12Filepath,
                    password,
                    privateKeyFilepath,
                    certificateFilepath )

                return Crypto( privateKeyFilepath, certificateFilepath )

        elif pkcs12Filepath is not None:
            # This should only be used for unit testing
            if not os.path.isfile( pkcs12Filepath ):
                raise estreamer.EncoreException(
                    'pkcs12Filepath: {0} does not exist or is not a file'.format(
                        pkcs12Filepath ))

            certificateFilepath = pkcs12Filepath + '.cert'
            privateKeyFilepath = pkcs12Filepath + '.key'

            Crypto.extract(
                pkcs12Filepath,
                password,
                privateKeyFilepath,
                certificateFilepath )

            return Crypto( privateKeyFilepath, certificateFilepath )
