
import os
import re
import subprocess
import sys
import splunk.admin as admin
import splunk.entity as en


class eNcoreConfig( admin.MConfigHandler ):

    CONFIG_FILE = 'encore'

    FIELDS = [
        { 'name': 'client_enabled', 'default': '0' },
        { 'name': 'host', 'default': '' },
        { 'name': 'port', 'default': '8302' },
        { 'name': 'process_pkcs12', 'default': '0' },
        { 'name': 'pkcs12_password', 'default': '' },
        { 'name': 'write_packets', 'default': '0' },
        { 'name': 'write_connections', 'default': '0' },
        { 'name': 'write_metadata', 'default': '0' },
        { 'name': 'changed', 'default': '0' }
    ]

    def setup( self ):
        """Constructor-ish"""
        if self.requestedAction == admin.ACTION_EDIT:
            for field in eNcoreConfig.FIELDS:
                self.supportedArgs.addOptArg( field['name'] )



    def handleList( self, confInfo ):
        """Respond to read event"""
        confDict = self.readConf( eNcoreConfig.CONFIG_FILE )
        if confDict is not None:
            for stanza, settings in confDict.items():
                for key, val in settings.items():
                    confInfo[stanza].append(key, val)
                    confInfo[stanza].append('changed', '1')



    def _configure( self ):
        # Helper function
        def _errorIf( pattern, string, msg = None ):
            match = re.search( pattern, string )
            if match:
                if msg is None:
                    msg = match.group(0)
                raise admin.ArgValidationException( msg )

        # pre-validation
        _errorIf( r'[^0-9]', self.callerArgs.data['port'][0], 'Port must be an integer')

        # Subprocess doesn't like $SPLUNK_HOME without shell so get the path here
        path = os.path.realpath( os.path.dirname( __file__ ) )

        cmds = [
            '{0}/configure.sh'.format( path ),
            self.callerArgs.data['client_enabled'][0],
            self.callerArgs.data['host'][0],
            self.callerArgs.data['port'][0],
            self.callerArgs.data['write_packets'][0],
            self.callerArgs.data['write_connections'][0],
            self.callerArgs.data['write_metadata'][0],
            self.callerArgs.data['process_pkcs12'][0],
            self.callerArgs.data['pkcs12_password'][0]
        ]

        # Run the output - and collect stderr too - into this string
        output = subprocess.check_output( cmds, stderr = subprocess.STDOUT )

        # Scan the output to catch any errors
        _errorIf( r'PKCS12 file \(.*\) does not exist', output )
        _errorIf( 'Mac verify error: invalid password?', output, 'Invalid PKCS12 password?' )

        # Write output to splunkd.log just in case
        sys.stderr.write( output.replace('\n', '\\n' ) )



    def handleEdit( self, confInfo ):
        """Respond to save event"""
        for field in eNcoreConfig.FIELDS:
            key = field['name']
            if self.callerArgs.data[ key ][0] in [None, '']:
                self.callerArgs.data[ key ][0] = field['default']

        self.callerArgs.data['changed'][0] = '1'

        # Do the real configuration here
        self._configure()

        # Don't save the password
        self.callerArgs.data['pkcs12_password'] = ''

        # And always reset pkcs12 processing
        self.callerArgs.data['process_pkcs12'] = '0'

        # Write to splunk config
        self.writeConf( eNcoreConfig.CONFIG_FILE , 'main', self.callerArgs.data)




# initialize the handler
admin.init( eNcoreConfig, admin.CONTEXT_NONE)
