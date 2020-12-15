
#********************************************************************
#      File:    file.py
#      Author:  Sam Strachan
#
#      Description:
#       This file encapsulates a file output stream and takes care of
#       creation, closing and rotating to new files
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

from __future__ import absolute_import
import os
import json
import time
import io
import uuid
from estreamer.streams.base import Base

class FileStream( Base ):
    """Class for writing output to a rotated log file"""
    def __init__( self, directory, threshold, rotate, filename = None, encoding = 'utf-8' ):
        self.file = None
        self.lines = 0
        self.directory = os.path.abspath( directory )
        self.threshold = threshold
        self.rotate = rotate
        self.filename = FileStream._sanitiseFilename( filename )
        self.encoding = encoding



    @staticmethod
    def _sanitiseFilename( filename ):
        """Returns a clean filename - incase someone is trying to inject a path"""
        if filename is None or filename == '':
            filename = 'log{0}'

        elif filename.find('/') > -1:
            filename = filename.replace('/', '')

        return filename



    def _ensureFile( self ):
        if not self.file:
            millis = int( time.time() )
            if not os.path.exists( self.directory ):
                os.makedirs( self.directory )

            filename = self.directory + '/' + self.filename.format( millis )

            if os.path.exists( filename ):
                # This is so unlikely in the real world, but just incase
                var = str( millis ) + '-' + str( uuid.uuid4() )
                filename = self.directory + '/' + self.filename.format( var )

            self.lines = 0
            self.file = io.open( filename, 'w+' )



    def onFileClose( self ):
        """Event handler for when a file is closed"""
        pass



    def _ensureRotation( self ):
        if self.rotate:
            if self.lines >= self.threshold:
                self.file.close()
                self.onFileClose()
                self.file = None



    def close( self ):
        if self.file is not None and not self.file.closed:
            self.file.close()
            self.onFileClose()



    def write( self, data ):
        """Writes to the underlying stream"""
        self._ensureFile()
        print ('data before write function in file.py')
#        s= ''
#        print (data)
#        if(isinstance(type(data), dict)) :
#            s = json.dumps(data)
#            print ('is dict')
#            self.file.write(s)
#        elif (isinstance(type(data), bytes)):
#            s = data.decode('utf-8')
#            print ('is byte')
#            self.file.write(s)
#        else :
#            print ('unknown type')
#            s = str(data.encode('utf-8'), 'utf-8')
#        s = str(json.dumps(data).encode('utf-8'), 'utf-8')
 
#            print("different type------zzzzzz")
#            print(type(data))
#            print (data)
#            print ("eend of different type -----z")

#        print (s)
        #self.file.write( data.encode( self.encoding ).decode('utf-8') )
#        s = json.dumps(bytes(data))
#                s=bytes(json.dumps(jsonSetting.store), 'utf-8')

#        s=json.dumps(str(data.decode('utf-8'))
        s= ", ".join("=".join((str(k),str(v))) for k,v in data.items())
        s+='\n'
        self.file.write(s)
        self.file.flush()
        self.lines += 1
        self._ensureRotation()
