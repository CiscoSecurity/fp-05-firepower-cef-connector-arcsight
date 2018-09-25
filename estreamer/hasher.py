
#********************************************************************
#      File:    hasher.py
#      Author:  Sam Strachan
#
#      Description:
#       Calculates a hash of the project
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
import hashlib
import os

class Hasher( object ):
    """Generates a hash of the project"""
    def __init__( self ):
        self.root = './estreamer'
        if not os.path.exists( self.root ):
            self.root = './src/estreamer'



    @staticmethod
    def __include( fullpath ):
        if fullpath.endswith('hasher.py'):
            return False

        elif fullpath.endswith('estreamer/__init__.py'):
            return False

        elif fullpath.endswith( '.py' ):
            return True

        return False



    def __paths( self ):
        paths = []

        for dirpath, dirnames, files in os.walk( self.root ):
            for filename in files:
                fullpath = os.path.join(dirpath, filename).replace('\\', '/')
                if Hasher.__include( fullpath ):
                    paths.append( fullpath )

        return sorted( paths )



    def __catFiles( self ):
        data = ''
        for path in self.__paths():

            with open( path, mode='rb' ) as blob:
                content = blob.read()
                content = content.replace('\r\n', '\n')
                data += content

        return data



    def hexdigest( self ):
        """Outputs a sha256 digest of the estreamer code"""
        data = self.__catFiles()
        sha256 = hashlib.sha256( data )
        return sha256.hexdigest()



if __name__ == '__main__':
    HASHER = Hasher()
    print( HASHER.hexdigest() )
