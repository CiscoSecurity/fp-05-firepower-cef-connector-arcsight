"""
The cache module contains a class to manage and maintain the stream
of metadata from eStreamer
"""
#********************************************************************
#      File:    cache.py
#      Author:  Sam Strachan
#
#      Description:
#       metadata.Cache() saves a copy of all metadata which flows
#       through the client. The metadata is then used by the View
#       class to supplement non-metadata records with more human
#       readable data
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

#pylint: disable=C0302
import cPickle
import os
import estreamer.common
import estreamer.crossprocesslogging
import estreamer.definitions as definitions
import estreamer.metadata

class Cache( object ):
    """
    Class to manage and maintain the stream of metadata from
    eStreamer. In time this will also serialize and deserialize
    itself to and from disk
    """
    ACCESS_CONTROL_POLICIES = 'acPols'
    APPLICATION_PROTOCOLS = 'appProtocols'
    ATTRIBS = 'attributes'
    BLOCKED = 'blocked'
    CLASSIFICATIONS = 'classifications'
    CLIENT_APPLICATIONS = 'clientApps'
    CLOUDS = 'clouds'
    CORRELATION_CRITICALITY = 'correlationCriticality'
    CORRELATION_EVENT_TYPES = 'correlationEventTypes'
    CORRELATION_HOST_TYPE = 'correlationHostTypes'
    CORRELATION_RULES = 'correlationRules'
    DEVICES = 'devices'
    DNS_RECORDS = 'dnsRecords'
    DNS_RESPONSES = 'dnsResponses'
    DIRECTIONS = 'directions'
    FILE_ACTIONS = 'fileActions'
    FILE_ARCHIVE_STATUS = 'archiveFileStatus'
    FILE_DISPOSITIONS = 'fileDispositions'
    FILE_SANDBOXES = 'fileSandboxes'
    FILE_SHAS = 'fileShas'
    FILE_STATIC_ANALYSES = 'fileStaticAnalyses'
    FILE_STORAGES = 'fileStorages'
    FILE_TYPES = 'fileTypes'
    FIREAMP_DETECTORS = 'fireampDetectors'
    FIREAMP_TYPES = 'fireampTypes'
    FIREAMP_SUBTYPES = 'fireampSubtypes'
    FIREWALL_RULE_ACTIONS = 'firewallRuleActions'
    FIREWALL_RULE_REASONS = 'firewallRuleReasons'
    FW_RULES = 'firewallRules'
    GEOLOCATIONS = 'geolocations'
    ICMP_TYPES = 'icmpTypes'
    ICMP_CODES = 'icmpCodes'
    IDS_RULES = 'idsRules'
    IDS_RULES_RENDERED = 'idsRulesRendered'
    IMPACT = 'impact'
    INTERFACES = 'interfaces'
    IOC = 'ioc'
    IP_PROTOCOLS = 'ipProtocols'
    MALWARE_EVENT_TYPES = 'malwareEventTypes'
    MALWARE_ANALYSIS_STATUS = 'malwareAnalysis'
    NET_PROTOS = 'networkProtocols'
    NETMAP_DOMAINS = 'netmapDomains'
    OS_FINGERPRINTS = 'osFingerprints'
    PAYLOADS = 'payloads'
    POLICIES = 'policies'
    PRIORITIES = 'priorities'
    REALMS = 'realms'
    SECURITY_GROUPS = 'securityGroup'
    SECURITY_ZONES = 'securityZones'
    SI_LISTS_GENERAL = 'siGeneral'
    SI_LISTS_DISCOVERY = 'siDiscovery'
    SI_SRC_DESTS = 'siSrcDests'
    SINKHOLES = 'sinkholes'
    SOURCE_APPLICATIONS = 'sourceApps'
    SOURCE_DETECTORS = 'sourceDetectors'
    SOURCE_TYPES = 'sourceTypes'
    SSL_ACTIONS = 'sslActions'
    SSL_CIPHER_SUITES = 'sslCipherSuite'
    SSL_FLOWS_STATUSES = 'sslFlowStatuses'
    SSL_FLOW_FLAGS = 'sslFlowFlags'
    SSL_FLOW_MESSAGES = 'sslFlowMessages'
    SSL_CERT_STATUSES = 'sslCertStatuses'
    SSL_URL_CATEGORIES = 'sslUrlCategories'
    SSL_VERSIONS = 'sslVersions'
    SYSTEM_USERS = 'systemUsers'
    URL_REPUTATIONS = 'urlReputations'
    URL_CATEGORIES = 'urlCategories'
    USER_PROTOCOLS = 'userProtocols'
    USERS = 'users'
    XDATA_TYPES = 'xdataTypes'

    # Incase we need to map from the old perl metadata somehow
    mapping = {
        APPLICATION_PROTOCOLS: 'app_protos',
        ATTRIBS: 'attribs',
        BLOCKED: 'blocked',
        CLASSIFICATIONS: 'classifications',
        CLIENT_APPLICATIONS: 'client_apps',
        CLOUDS: 'clouds',
        CORRELATION_CRITICALITY: 'corr_criticallity',
        CORRELATION_EVENT_TYPES: 'corr_event_types',
        CORRELATION_HOST_TYPE: 'corr_host_type',
        CORRELATION_RULES: 'corr_rules',
        DEVICES: 'devices',
        DIRECTIONS: 'directions',
        FILE_ACTIONS: 'file_actions',
        FILE_DISPOSITIONS: 'file_dispositions',
        FILE_SANDBOXES: 'file_sandboxes',
        FILE_SHAS: 'file_shas',
        FILE_STORAGES: 'file_storages',
        FILE_TYPES: 'file_types',
        FIREAMP_DETECTORS: 'fireamp_detectors',
        FIREAMP_TYPES: 'fireamp_types',
        FIREAMP_SUBTYPES: 'fireamp_subtypes',
        FIREWALL_RULE_ACTIONS: 'fw_rule_actions',
        FIREWALL_RULE_REASONS: 'fw_rule_reasons',
        FW_RULES: 'fw_rules',
        GEOLOCATIONS: 'geolocations',
        ICMP_TYPES: 'icmp_types',
        ICMP_CODES: 'icmp_codes',
        IDS_RULES: 'ids_rules',
        INTERFACES: 'interfaces',
        IP_PROTOCOLS: 'ip_protos',
        MALWARE_EVENT_TYPES: 'malware_event_types',
        NET_PROTOS: 'net_protos',
        OS_FINGERPRINTS: 'os_fingerprints',
        PAYLOADS: 'payloads',
        POLICIES: 'policies',
        PRIORITIES: 'priorities',
        SECURITY_ZONES: 'security_zones',
        SI_SRC_DESTS: 'si_src_dests',
        SOURCE_APPLICATIONS: 'source_apps',
        SOURCE_DETECTORS: 'source_detectors',
        SOURCE_TYPES: 'source_types',
        SYSTEM_USERS: 'system_users',
        URL_REPUTATIONS: 'url_reputations',
        URL_CATEGORIES: 'url_categories',
        USERS: 'users',
        XDATA_TYPES: 'xdata_types'
    }



    AUTOMAP = {
        # 4
        definitions.RECORD_PRIORITY: {
            'cache': PRIORITIES,
            'id': 'id',
            'value': 'name' },

        # 55
        definitions.METADATA_RNA_CLIENT_APPLICATION: {
            'cache': CLIENT_APPLICATIONS,
            'id': 'id',
            'value': 'name' },

        # 59
        definitions.METADATA_RNA_NETWORK_PROTOCOL: {
            'cache': NET_PROTOS,
            'id': 'id',
            'value': 'name' },

        # 60
        definitions.METADATA_RNA_ATTRIBUTE: {
            'cache': ATTRIBS,
            'id': 'id',
            'value': 'name' },

        # 62
        definitions.RECORD_USER: {
            'cache': SYSTEM_USERS,
            'id': 'id',
            'value': 'name.data' },

        # 63
        definitions.METADATA_RNA_SERVICE: {
            'cache': APPLICATION_PROTOCOLS,
            'id': 'id',
            'value': 'name' },

        # 69
        definitions.METADATA_CORRELATION_POLICY: {
            'cache': POLICIES,
            'id': 'id',
            'value': 'name' },

        # 90
        definitions.METADATA_RNA_SOURCE_TYPE: {
            'cache': SOURCE_TYPES,
            'id': 'id',
            'value': 'name' },

        # 91
        definitions.METADATA_RNA_SOURCE_APP: {
            'cache': SOURCE_APPLICATIONS,
            'id': 'id',
            'value': 'name' },

        # 96
        definitions.METADATA_RNA_SOURCE_DETECTOR: {
            'cache': SOURCE_DETECTORS,
            'id': 'id',
            'value': 'name' },

        # 98
        definitions.RECORD_RUA_USER: {
            'cache': USERS,
            'id': 'id',
            'value': 'name.data' },

        # 109
        definitions.RECORD_RNA_WEB_APPLICATION_PAYLOAD: {
            'cache': PAYLOADS,
            'id': 'id',
            'value': 'name' },

        # 111
        definitions.METADATA_INTRUSION_EXTRA_DATA: {
            'cache': XDATA_TYPES,
            'id': 'type',
            'value': 'name.data' },

        # 115
        definitions.METADATA_SECURITY_ZONE_NAME: {
            'cache': SECURITY_ZONES,
            'id': 'uuid',
            'value': 'name.data' },

        # 116
        definitions.METADATA_INTERFACE_NAME: {
            'cache': INTERFACES,
            'id': 'uuid',
            'value': 'name.data' },

        # 118
        definitions.METADATA_INTRUSION_POLICY_NAME: {
            'cache': POLICIES,
            'id': 'uuid',
            'value': 'name.data' },

        # 120
        definitions.METADATA_ACCESS_CONTROL_RULE_ACTION: {
            'cache': FIREWALL_RULE_ACTIONS,
            'id': 'id',
            'value': 'name' },

        # 121
        definitions.METADATA_URL_CATEGORY: {
            'cache': URL_CATEGORIES,
            'id': 'id',
            'value': 'name' },

        # 122
        definitions.METADATA_URL_REPUTATION: {
            'cache': URL_REPUTATIONS,
            'id': 'id',
            'value': 'name' },

        # 123
        definitions.METADATA_SENSOR: {
            'cache': DEVICES,
            'id': 'id',
            'value': 'name' },

        # 124
        definitions.METADATA_ACCESS_CONTROL_POLICY_RULE_REASON: {
            'cache': FIREWALL_RULE_REASONS,
            'id': 'id',
            'value': 'description.data' },

        # 127
        definitions.METADATA_FIREAMP_CLOUD_NAME: {
            'cache': CLOUDS,
            'id': 'uuid',
            'value': 'name.data' },

        # 128
        definitions.METADATA_FIREAMP_EVENT_TYPE: {
            'cache': MALWARE_EVENT_TYPES,
            'id': 'id',
            'value': 'name' },

        # 129
        definitions.METADATA_FIREAMP_EVENT_SUBTYPE: {
            'cache': FIREAMP_SUBTYPES,
            'id': 'id',
            'value': 'name' },

        # 130
        definitions.METADATA_FIREAMP_DETECTOR_TYPE: {
            'cache': FIREAMP_DETECTORS,
            'id': 'id',
            'value': 'name' },

        # 131
        definitions.METADATA_FIREAMP_FILE_TYPE: {
            'cache': FILE_TYPES,
            'id': 'id',
            'value': 'name' },

        # 270
        definitions.METADATA_ICMP_CODE: {
            'cache': ICMP_CODES,
            'id': 'code',
            'value': 'description.data' },

        # 281
        definitions.METADATA_SECURITY_INTELLIGENCE_SRCDEST: {
            'cache': SI_SRC_DESTS,
            'id': 'id',
            'value': 'name' },

        # 282
        definitions.METADATA_SECURITY_INTELLIGENCE_CATEGORY_GENERAL: {
            'cache': SI_LISTS_GENERAL,
            'id': 'id',
            'value': 'name.data' },

        # 300
        definitions.METADATA_REALM: {
            'cache': REALMS,
            'id': 'id',
            'value': 'name' },

        # 302
        definitions.METADATA_SECURITY_GROUP: {
            'cache': SECURITY_GROUPS,
            'id': 'id',
            'value': 'name' },

        # 322
        definitions.METADATA_SINKHOLE: {
            'cache': SINKHOLES,
            'id': 'uuid',
            'value': 'name.data' },

        # 350
        definitions.METADATA_NETMAP_DOMAIN: {
            'cache': NETMAP_DOMAINS,
            'id': 'uuid',
            'value': 'name.data' },

        # 510
        definitions.METADATA_FILELOG_FILE_TYPE: {
            'cache': FILE_TYPES,
            'id': 'id',
            'value': 'name' },

        # 511
        definitions.METADATA_FILELOG_SHA: {
            'cache': FILE_SHAS,
            'id': 'shaHash',
            'value': 'fileName.data' },

        # 515
        definitions.METADATA_FILELOG_STORAGE: {
            'cache': FILE_STORAGES,
            'id': 'id',
            'value': 'name' },

        # 516
        definitions.METADATA_FILELOG_SANDBOX: {
            'cache': FILE_SANDBOXES,
            'id': 'id',
            'value': 'name' },

        # 517
        definitions.METADATA_FILELOG_SPERO: {
            'cache': FILE_DISPOSITIONS,
            'id': 'id',
            'value': 'name' },

        # 518
        definitions.METADATA_FILELOG_ARCHIVE: {
            'cache': FILE_ARCHIVE_STATUS,
            'id': 'id',
            'value': 'name' },

        # 519
        definitions.METADATA_FILELOG_STATIC_ANALYSIS: {
            'cache': FILE_STATIC_ANALYSES,
            'id': 'id',
            'value': 'name' },

        # 520
        definitions.METADATA_GEOLOCATION: {
            'cache': GEOLOCATIONS,
            'id': 'countryCode',
            'value': 'country.data' },

        # 530
        definitions.METADATA_FILE_POLICY_NAME: {
            'cache': POLICIES,
            'id': 'uuid',
            'value': 'name.data' },

        # 602
        definitions.METADATA_SSL_CIPHER_SUITE: {
            'cache': SSL_CIPHER_SUITES,
            'id': 'id',
            'value': 'name' },

        # 604
        definitions.METADATA_SSL_VERSION: {
            'cache': SSL_VERSIONS,
            'id': 'id',
            'value': 'name' },

        # 605
        definitions.METADATA_SSL_SERVER_CERTIFICATE_STATUS: {
            'cache': SSL_CERT_STATUSES,
            'id': 'id',
            'value': 'name' },

        # 606
        definitions.METADATA_SSL_ACTUAL_ACTION: {
            'cache': SSL_ACTIONS,
            'id': 'id',
            'value': 'name' },

        # 607
        definitions.METADATA_SSL_EXPECTED_ACTION: {
            'cache': SSL_ACTIONS,
            'id': 'id',
            'value': 'name' },

        # 608
        definitions.METADATA_SSL_FLOW_STATUS: {
            'cache': SSL_FLOWS_STATUSES,
            'id': 'id',
            'value': 'name' },

        # 613
        definitions.METADATA_SSL_URL_CATEGORY: {
            'cache': SSL_URL_CATEGORIES,
            'id': 'id',
            'value': 'name' },

        # 700
        definitions.METADATA_RECORD_NETWORK_ANALYSIS_POLICY: {
            'cache': POLICIES,
            'id': 'uuid',
            'value': 'name.data' }
    }



    def __init__( self, filepath ):
        self.filepath = filepath
        self.logger = estreamer.crossprocesslogging.getLogger(
            self.__class__.__name__ )
        self.data = {}



    def set( self, keys, value ):
        """Sets the value for the key array and ensures that all
        necessary keys exist along the way"""
        data = self.data
        for index, key in enumerate( keys ):
            if index == len( keys ) - 1:
                data[key] = value
            elif key not in data:
                data[key] = {}
            data = data[key]



    def get( self, keys ):
        """Gets the value for the given key array and returns None
        if there is no key"""
        data = self.data
        try:
            for key in keys:
                data = data[key]
            return data
        except (TypeError, AttributeError, KeyError):
            return None



    def has( self, keys ):
        """Returns whether or not the given key array exists"""
        data = self.data
        try:
            for key in keys:
                data = data[key]
            return True
        except (TypeError, AttributeError, KeyError):
            return False



    def save( self ):
        """Saves current cache to disk"""
        self.logger.info('Saving cache to {0}'.format( self.filepath ))
        with open( self.filepath, 'wb' ) as cacheFile:
            cPickle.dump( self.data, cacheFile )



    def load( self ):
        """Loads cache from disk"""
        # Default value
        self.data = Cache.__default()

        self.logger.info('Loading cache from {0}'.format(self.filepath ))
        if not os.path.exists( self.filepath ):
            self.logger.info('Cache file "{0}" does not exist. Using default values'.format(
                self.filepath) )
            return


        try:
            with open( self.filepath, 'rb' ) as cacheFile:
                data = cPickle.load( cacheFile )
                estreamer.common.extend( self.data, data )

        except (cPickle.UnpicklingError, EOFError) as ex:
            self.logger.warning(
                'Unable to make sense of cache file "{0}" ({1}). Using default settings'.format(
                    self.filepath, ex) )

            self.data = Cache.__default()



    @staticmethod
    def __default():
        return {
            Cache.DEVICES: {
                0: 'Defense Center'
            },

            Cache.SECURITY_ZONES: {
                '00000000-0000-0000-0000-000000000000': 'N/A'
            },

            Cache.INTERFACES: {
                '00000000-0000-0000-0000-000000000000': 'N/A'
            },

            Cache.CORRELATION_EVENT_TYPES: {
                '0': 'Unknown',
                '1': 'Intrusion Event',
                '2': 'Host Discovery',
                '3': 'User Activity',
                '4': 'Whitelist',
                '5': 'Malware Event'
            },

            Cache.CORRELATION_HOST_TYPE: {
                0: 'Host',
                1: 'Router',
                2: 'Bridge'
            },

            Cache.CORRELATION_CRITICALITY: {
                0: 'None',
                1: 'Low',
                2: 'Medium',
                3: 'High'
            },

            Cache.USERS: {
                0: 'Unknown'
            },

            Cache.IP_PROTOCOLS: {
                0: 'Unknown',
                1: 'ICMP',
                2: 'IGMP',
                3: 'GGP',
                4: 'IPv4',
                5: 'ST',
                6: 'TCP',
                7: 'CBT',
                8: 'EGP',
                9: 'IGP',
                10: 'BBN-RCC-MON',
                11: 'NVP-II',
                12: 'PUP',
                13: 'ARGUS',
                14: 'EMCON',
                15: 'XNET',
                16: 'CHAOS',
                17: 'UDP',
                18: 'MUX',
                19: 'DCN-MEAS',
                20: 'HMP',
                21: 'PRM',
                22: 'XNS-IDP',
                23: 'TRUNK-1',
                24: 'TRUNK-2',
                25: 'LEAF-1',
                26: 'LEAF-2',
                27: 'RDP',
                28: 'IRTP',
                29: 'ISO-TP4',
                30: 'NETBLT',
                31: 'MFE-NSP',
                32: 'MERIT-INP',
                33: 'DCCP',
                34: '3PC',
                35: 'IDPR',
                36: 'XTP',
                37: 'DDP',
                38: 'IDPR-CMTP',
                39: 'TP++',
                40: 'IL',
                41: 'IPv6',
                42: 'SDRP',
                43: 'IPv6-Route',
                44: 'IPv6-Frag',
                45: 'IDRP',
                46: 'RSVP',
                47: 'GRE',
                48: 'MHRP',
                49: 'BNA',
                50: 'ESP',
                51: 'AH',
                52: 'I-NLSP',
                53: 'SWIPE',
                54: 'NARP',
                55: 'MOBILE',
                56: 'TLSP',
                57: 'SKIP',
                58: 'IPv6-ICMP',
                59: 'IPv6-NoNxt',
                60: 'IPv6-Opts',
                62: 'CFTP',
                64: 'SAT-EXPAK',
                65: 'KRYPTOLAN',
                66: 'RVD',
                67: 'IPPC',
                69: 'SAT-MON',
                70: 'VISA',
                71: 'IPCV',
                72: 'CPNX',
                73: 'CPHB',
                74: 'WSN',
                75: 'PVP',
                76: 'BR-SAT-MON',
                77: 'SUN-ND',
                78: 'WB-MON',
                79: 'WB-EXPAK',
                80: 'ISO-IP',
                81: 'VMTP',
                82: 'SECURE-VMTP',
                83: 'VINES',
                # 84: 'TTP', # Removed as duplicate - and last always wins
                # http://stackoverflow.com/a/39678945
                84: 'IPTM',
                85: 'NSFNET-IGP',
                86: 'DGP',
                87: 'TCF',
                88: 'EIGRP',
                89: 'OSPF',
                90: 'Sprite-RPC',
                91: 'LARP',
                92: 'MTP',
                93: 'AX.25',
                94: 'IPIP',
                95: 'MICP',
                96: 'SCC-SP',
                97: 'ETHERIP',
                98: 'ENCAP',
                100: 'GMTP',
                101: 'IFMP',
                102: 'PNNI',
                103: 'PIM',
                104: 'ARIS',
                105: 'SCPS',
                106: 'QNX',
                107: 'A/N',
                108: 'IPComp',
                109: 'SNP',
                110: 'Compaq-Peer',
                111: 'IPX-in-IP',
                112: 'VRRP',
                113: 'PGM',
                115: 'L2TP',
                116: 'DDX',
                117: 'IATP',
                118: 'STP',
                119: 'SRP',
                120: 'UTI',
                121: 'SMP',
                122: 'SM',
                123: 'PTP',
                124: 'IS-IS over IPv4',
                125: 'FIRE',
                126: 'CRTP',
                127: 'CRUDP',
                128: 'SSCOPMCE',
                129: 'IPLT',
                130: 'SPS',
                131: 'PIPE',
                132: 'SCTP',
                133: 'FC',
                134: 'RSVP-E2E-IGNORE',
                135: 'Mobility Header',
                136: 'UDPLite',
                137: 'MPLS-in-IP',
                138: 'manet',
                139: 'HIP',
                140: 'Shim6',
                141: 'WESP',
                142: 'ROHC'
            },

            Cache.APPLICATION_PROTOCOLS: {
                0: 'Unknown'
            },

            Cache.CLIENT_APPLICATIONS: {
                0: 'Unknown'
            },

            Cache.SOURCE_APPLICATIONS: {
                0: 'Unknown'
            },

            Cache.PAYLOADS: {
                0: 'Unknown'
            },

            Cache.BLOCKED: {
                0: 'No',
                1: 'Yes',
                2: 'Would'
            },

            Cache.GEOLOCATIONS: {
                0: 'unknown'
            },

            Cache.FIREWALL_RULE_REASONS: {
                0: 'N/A',
                1: 'IP Block',
                2: 'IP Monitor',
                4: 'User Bypass',
                8: 'File Monitor',
                16: 'File Block',
                32: 'Intrusion Monitor',
                64: 'Intrusion Block',
                128: 'File Resume Block',
                256: 'File Resume Allow',
                512: 'File Custom Detection'
            },

            Cache.OS_FINGERPRINTS: {
                '00000000-0000-0000-0000-000000000000': {
                    'os': 'Unknown',
                    'vendor': 'Unknown',
                    'ver': 'Unknown'
                }
            },

            Cache.FILE_SHAS: {
                '0000000000000000000000000000000000000000000000000000000000000000': 'Unknown'
            },

            Cache.URL_REPUTATIONS: {
                0: 'Unknown'
            },

            Cache.URL_CATEGORIES: {
                0: 'Unknown'
            },

            Cache.SOURCE_DETECTORS: {
                0: 'Unknown'
            },

            Cache.SOURCE_TYPES: {
                0: 'RNA'
            },

            Cache.MALWARE_EVENT_TYPES: {
                0: 'Unknown'
            },

            Cache.FILE_TYPES: {
                0: 'Unknown'
            },

            Cache.DIRECTIONS: {
                0: 'Unknown',
                1: 'Download',
                2: 'Upload',
            },

            Cache.FILE_ACTIONS: {
                0: 'N/A',
                1: 'Detect',
                2: 'Block',
                3: 'Malware Cloud Lookup',
                4: 'Malware Block',
                5: 'Malware Whitelist',
                6: 'Cloud Lookup Timeout',
                7: 'Custom Detection',
                8: 'Custom Detection Block',
                9: 'Archive Block (Depth Exceeded)',
                10: 'Archive Block (Encrypted)',
                11: 'Archive Block (Failed To Inspect)'
            },

            Cache.FILE_DISPOSITIONS: {
                0: 'N/A',
                1: 'Clean',
                2: 'Unknown',
                3: 'Malware',
                4: 'Unavailable',
                5: 'Custom signature'
            },

            Cache.CLOUDS: {
                '00000000-0000-0000-0000-000000000000': 'N/A'
            },

            Cache.FIREAMP_DETECTORS: {
                0: 'RNA'
            },

            Cache.FIREAMP_TYPES: {
                0: 'N/A',
                1: 'Threat Detected in Network File Transfer',
                2: 'Threat Detected in Network File Transfer (Retrospective)',
                553648143: 'Threat Quarantined',
                553648145: 'Threat Detected in Exclusion',
                553648146: 'Cloud Recall Restore from Quarantine Started',
                553648147: 'Cloud Recall Quarantine Started',
                553648149: 'Quarantined Item Restored',
                553648150: 'Quarantine Restore Started',
                553648154: 'Cloud Recall Restore from Quarantine',
                553648155: 'Cloud Recall Quarantine',
                553648168: 'Blocked Execution',
                554696714: 'Scan Started',
                554696715: 'Scan Completed, No Detections',
                1090519054: 'Threat Detected',
                1091567628: 'Scan Completed With Detections',
                2164260880: 'Quarantine Failure',
                2164260884: 'Quarantine Restore Failed',
                2164260892: 'Cloud Recall Restore from Quarantine Failed',
                2164260893: 'Cloud Recall Quarantine Attempt Failed',
                2165309453: 'Scan Failed'
            },

            Cache.FIREAMP_SUBTYPES: {
                0: 'N/A',
                1: 'Create',
                2: 'Execute',
                4: 'Scan',
                22: 'Move'
            },

            Cache.SI_SRC_DESTS: {
                0: 'N/A'
            },

            Cache.FILE_STORAGES: {
                0: 'N/A',
                1: 'File Stored',
                2: 'File Stored',
                3: 'Unable to Store File',
                4: 'Unable to Store File',
                5: 'Unable to Store File',
                6: 'Unable to Store File',
                7: 'Unable to Store File',
                8: 'File Size is Too Large',
                9: 'File Size is Too Small',
                10: 'Unable to Store File',
                11: 'File Not Stored, Disposition Unavailable'
            },

            Cache.FILE_SANDBOXES: {
                0: 'File not sent for Analysis',
                1: 'Sent for Analysis',
                2: 'Sent for Analysis',
                4: 'Sent for Analysis',
                5: 'Failed to Send',
                6: 'Failed to Send',
                7: 'Failed to Send',
                8: 'Failed to Send',
                9: 'File Size is Too Small',
                10: 'File Size is Too Large',
                11: 'Sent for Analysis',
                12: 'Analysis Complete',
                13: 'Failure (Network Issue)',
                14: 'Failure (Rate Limit)',
                15: 'Failure (File Too Large)',
                16: 'Failure (File Read Error)',
                17: 'Failure (Internal Library Error)',
                19: 'File Not Sent Disposition Unavailable',
                20: 'Failure (Cannot Run File)',
                21: 'Failure (Analysis Timeout)',
                22: 'Sent for Analysis',
                23: 'File Transmit File Capacity Handled',
                #... File capacity handled (stored on the sensor) because file could
                # not be submitted to the sandbox for analysis',
                25: 'File Transmit Server Limited Exceeded Capacity Handled',
                #... - File capacity handled due to rate limiting on server',
                26: 'Communication Failure',
                # - File capacity handled due to cloud connectivity failure',
                27: 'Not Sent - File not sent due to configuration',
                28: 'Preclass No Match',
                # - File not sent for dynamic analysis since pre-classification didn't
                # find any embedded or suspicious object in the file',
                29: 'Transmit Sent Sandbox Private Cloud',
                # - File sent to the private cloud for dynamic analysis',
                30: 'Transmit Not Send Sendbox Private Cloud'
                    # - File not sent to the private cloud for analysis
            },

            Cache.SSL_ACTIONS: {
                0: 'Unknown',
                1: 'Do Not Decrypt',
                2: 'Block',
                3: 'Block With Reset',
                4: 'Decrypt (Known Key)',
                5: 'Decrypt (Replace Key)',
                6: 'Decrypt (Resign)'
            },

            Cache.SSL_FLOWS_STATUSES: {
                0: 'Unknown',
                1: 'No Match',
                2: 'Success',
                3: 'Uncached Session',
                4: 'Unknown Cipher Suite',
                5: 'Unsupported Cipher Suite',
                6: 'Unsupported SSL Version',
                7: 'SSL Compression Used',
                8: 'Session Undecryptable in Passive Mode',
                9: 'Handshake Error',
                10: 'Decryption Error',
                11: 'Pending Server Name Category Lookup',
                12: 'Pending Common Name Category Lookup',
                13: 'Internal Error',
                14: 'Network Parameters Unavailable',
                15: 'Invalid Server Certificate Handle',
                16: 'Server Certificate Fingerprint Unavailable',
                17: 'Cannot Cache Subject DN',
                18: 'Cannot Cache Issuer DN',
                19: 'Unknown SSL Version',
                20: 'External Certificate List Unavailable',
                21: 'External Certificate Fingerprint Unavailable',
                22: 'Internal Certificate List Invalid',
                23: 'Internal Certificate List Unavailable',
                24: 'Internal Certificate Unavailable',
                25: 'Internal Certificate Fingerprint Unavailable',
                26: 'Server Certificate Validation Unavailable' ,
                27: 'Server Certificate Validation Failure',
                28: 'Invalid Action'
            },

            Cache.IMPACT: {
                1: 'Red (vulnerable)',
                2: 'Orange (potentially vulnerable)',
                3: 'Yellow (currently not vulnerable)',
                4: 'Blue (unknown target)',
                5: 'Gray (unknown impact)'
            },

            Cache.MALWARE_ANALYSIS_STATUS: {
                0: 'File not analyzed',
                1: 'Analysis done',
                2: 'Analysis failed',
                3: 'Manual analysis request'
            },

            Cache.FILE_ARCHIVE_STATUS: {
                0: 'N/A - File is not being inspected as an archive',
                1: 'Pending - Archive is being inspected',
                2: 'Extracted - Successfully inspected without any problems',
                3: 'Failed - Failed to inspect, insufficient system resources',
                4: 'Depth Exceeded - Successful, but archive exceeded the nested inspection depth',
                5: 'Encrypted - Partially Successful',
                6: 'Not Inspectable - Partially Successful, File is possibly Malformed or Corrupt'
            },

            # This comes from:
            # http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
            Cache.SSL_CIPHER_SUITES: {
                0: 'TLS_NULL_WITH_NULL_NULL',
                1: 'TLS_RSA_WITH_NULL_MD5',
                2: 'TLS_RSA_WITH_NULL_SHA',
                3: 'TLS_RSA_EXPORT_WITH_RC4_40_MD5',
                4: 'TLS_RSA_WITH_RC4_128_MD5',
                5: 'TLS_RSA_WITH_RC4_128_SHA',
                6: 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5',
                7: 'TLS_RSA_WITH_IDEA_CBC_SHA',
                8: 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA',
                9: 'TLS_RSA_WITH_DES_CBC_SHA',
                10: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
                11: 'TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA',
                12: 'TLS_DH_DSS_WITH_DES_CBC_SHA',
                13: 'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA',
                14: 'TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA',
                15: 'TLS_DH_RSA_WITH_DES_CBC_SHA',
                16: 'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA',
                17: 'TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA',
                18: 'TLS_DHE_DSS_WITH_DES_CBC_SHA',
                19: 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA',
                20: 'TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA',
                21: 'TLS_DHE_RSA_WITH_DES_CBC_SHA',
                22: 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
                23: 'TLS_DH_anon_EXPORT_WITH_RC4_40_MD5',
                24: 'TLS_DH_anon_WITH_RC4_128_MD5',
                25: 'TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA',
                26: 'TLS_DH_anon_WITH_DES_CBC_SHA',
                27: 'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA',
                28: 'Reserved to avoid conflicts with SSLv3',
                30: 'TLS_KRB5_WITH_DES_CBC_SHA',
                31: 'TLS_KRB5_WITH_3DES_EDE_CBC_SHA',
                32: 'TLS_KRB5_WITH_RC4_128_SHA',
                33: 'TLS_KRB5_WITH_IDEA_CBC_SHA',
                34: 'TLS_KRB5_WITH_DES_CBC_MD5',
                35: 'TLS_KRB5_WITH_3DES_EDE_CBC_MD5',
                36: 'TLS_KRB5_WITH_RC4_128_MD5',
                37: 'TLS_KRB5_WITH_IDEA_CBC_MD5',
                38: 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA',
                39: 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA',
                40: 'TLS_KRB5_EXPORT_WITH_RC4_40_SHA',
                41: 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5',
                42: 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5',
                43: 'TLS_KRB5_EXPORT_WITH_RC4_40_MD5',
                44: 'TLS_PSK_WITH_NULL_SHA',
                45: 'TLS_DHE_PSK_WITH_NULL_SHA',
                46: 'TLS_RSA_PSK_WITH_NULL_SHA',
                47: 'TLS_RSA_WITH_AES_128_CBC_SHA',
                48: 'TLS_DH_DSS_WITH_AES_128_CBC_SHA',
                49: 'TLS_DH_RSA_WITH_AES_128_CBC_SHA',
                50: 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA',
                51: 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
                52: 'TLS_DH_anon_WITH_AES_128_CBC_SHA',
                53: 'TLS_RSA_WITH_AES_256_CBC_SHA',
                54: 'TLS_DH_DSS_WITH_AES_256_CBC_SHA',
                55: 'TLS_DH_RSA_WITH_AES_256_CBC_SHA',
                56: 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA',
                57: 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
                58: 'TLS_DH_anon_WITH_AES_256_CBC_SHA',
                59: 'TLS_RSA_WITH_NULL_SHA256',
                60: 'TLS_RSA_WITH_AES_128_CBC_SHA256',
                61: 'TLS_RSA_WITH_AES_256_CBC_SHA256',
                62: 'TLS_DH_DSS_WITH_AES_128_CBC_SHA256',
                63: 'TLS_DH_RSA_WITH_AES_128_CBC_SHA256',
                64: 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256',
                65: 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA',
                66: 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA',
                67: 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA',
                68: 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA',
                69: 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA',
                70: 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA',
                103: 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
                104: 'TLS_DH_DSS_WITH_AES_256_CBC_SHA256',
                105: 'TLS_DH_RSA_WITH_AES_256_CBC_SHA256',
                106: 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256',
                107: 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
                108: 'TLS_DH_anon_WITH_AES_128_CBC_SHA256',
                109: 'TLS_DH_anon_WITH_AES_256_CBC_SHA256',
                132: 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA',
                133: 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA',
                134: 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA',
                135: 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA',
                136: 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA',
                137: 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA',
                138: 'TLS_PSK_WITH_RC4_128_SHA',
                139: 'TLS_PSK_WITH_3DES_EDE_CBC_SHA',
                140: 'TLS_PSK_WITH_AES_128_CBC_SHA',
                141: 'TLS_PSK_WITH_AES_256_CBC_SHA',
                142: 'TLS_DHE_PSK_WITH_RC4_128_SHA',
                143: 'TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA',
                144: 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA',
                145: 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA',
                146: 'TLS_RSA_PSK_WITH_RC4_128_SHA',
                147: 'TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA',
                148: 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA',
                149: 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA',
                150: 'TLS_RSA_WITH_SEED_CBC_SHA',
                151: 'TLS_DH_DSS_WITH_SEED_CBC_SHA',
                152: 'TLS_DH_RSA_WITH_SEED_CBC_SHA',
                153: 'TLS_DHE_DSS_WITH_SEED_CBC_SHA',
                154: 'TLS_DHE_RSA_WITH_SEED_CBC_SHA',
                155: 'TLS_DH_anon_WITH_SEED_CBC_SHA',
                156: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
                157: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
                158: 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
                159: 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
                160: 'TLS_DH_RSA_WITH_AES_128_GCM_SHA256',
                161: 'TLS_DH_RSA_WITH_AES_256_GCM_SHA384',
                162: 'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256',
                163: 'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384',
                164: 'TLS_DH_DSS_WITH_AES_128_GCM_SHA256',
                165: 'TLS_DH_DSS_WITH_AES_256_GCM_SHA384',
                166: 'TLS_DH_anon_WITH_AES_128_GCM_SHA256',
                167: 'TLS_DH_anon_WITH_AES_256_GCM_SHA384',
                168: 'TLS_PSK_WITH_AES_128_GCM_SHA256',
                169: 'TLS_PSK_WITH_AES_256_GCM_SHA384',
                170: 'TLS_DHE_PSK_WITH_AES_128_GCM_SHA256',
                171: 'TLS_DHE_PSK_WITH_AES_256_GCM_SHA384',
                172: 'TLS_RSA_PSK_WITH_AES_128_GCM_SHA256',
                173: 'TLS_RSA_PSK_WITH_AES_256_GCM_SHA384',
                174: 'TLS_PSK_WITH_AES_128_CBC_SHA256',
                175: 'TLS_PSK_WITH_AES_256_CBC_SHA384',
                176: 'TLS_PSK_WITH_NULL_SHA256',
                177: 'TLS_PSK_WITH_NULL_SHA384',
                178: 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA256',
                179: 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA384',
                180: 'TLS_DHE_PSK_WITH_NULL_SHA256',
                181: 'TLS_DHE_PSK_WITH_NULL_SHA384',
                182: 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA256',
                183: 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA384',
                184: 'TLS_RSA_PSK_WITH_NULL_SHA256',
                185: 'TLS_RSA_PSK_WITH_NULL_SHA384',
                186: 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256',
                187: 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256',
                188: 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256',
                189: 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256',
                190: 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
                191: 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256',
                192: 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256',
                193: 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256',
                194: 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256',
                195: 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256',
                196: 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256',
                197: 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256',
                255: 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV',
                22016: 'TLS_FALLBACK_SCSV',
                49153: 'TLS_ECDH_ECDSA_WITH_NULL_SHA',
                49154: 'TLS_ECDH_ECDSA_WITH_RC4_128_SHA',
                49155: 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA',
                49156: 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA',
                49157: 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA',
                49158: 'TLS_ECDHE_ECDSA_WITH_NULL_SHA',
                49159: 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA',
                49160: 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA',
                49161: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
                49162: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
                49163: 'TLS_ECDH_RSA_WITH_NULL_SHA',
                49164: 'TLS_ECDH_RSA_WITH_RC4_128_SHA',
                49165: 'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA',
                49166: 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA',
                49167: 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA',
                49168: 'TLS_ECDHE_RSA_WITH_NULL_SHA',
                49169: 'TLS_ECDHE_RSA_WITH_RC4_128_SHA',
                49170: 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
                49171: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
                49172: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
                49173: 'TLS_ECDH_anon_WITH_NULL_SHA',
                49174: 'TLS_ECDH_anon_WITH_RC4_128_SHA',
                49175: 'TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA',
                49176: 'TLS_ECDH_anon_WITH_AES_128_CBC_SHA',
                49177: 'TLS_ECDH_anon_WITH_AES_256_CBC_SHA',
                49178: 'TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA',
                49179: 'TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA',
                49180: 'TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA',
                49181: 'TLS_SRP_SHA_WITH_AES_128_CBC_SHA',
                49182: 'TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA',
                49183: 'TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA',
                49184: 'TLS_SRP_SHA_WITH_AES_256_CBC_SHA',
                49185: 'TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA',
                49186: 'TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA',
                49187: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
                49188: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
                49189: 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256',
                49190: 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384',
                49191: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
                49192: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
                49193: 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256',
                49194: 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384',
                49195: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
                49196: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
                49197: 'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256',
                49198: 'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384',
                49199: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                49200: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                49201: 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256',
                49202: 'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384',
                49203: 'TLS_ECDHE_PSK_WITH_RC4_128_SHA',
                49204: 'TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA',
                49205: 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA',
                49206: 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA',
                49207: 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256',
                49208: 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384',
                49209: 'TLS_ECDHE_PSK_WITH_NULL_SHA',
                49210: 'TLS_ECDHE_PSK_WITH_NULL_SHA256',
                49211: 'TLS_ECDHE_PSK_WITH_NULL_SHA384',
                49212: 'TLS_RSA_WITH_ARIA_128_CBC_SHA256',
                49213: 'TLS_RSA_WITH_ARIA_256_CBC_SHA384',
                49214: 'TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256',
                49215: 'TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384',
                49216: 'TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256',
                49217: 'TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384',
                49218: 'TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256',
                49219: 'TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384',
                49220: 'TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256',
                49221: 'TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384',
                49222: 'TLS_DH_anon_WITH_ARIA_128_CBC_SHA256',
                49223: 'TLS_DH_anon_WITH_ARIA_256_CBC_SHA384',
                49224: 'TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256',
                49225: 'TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384',
                49226: 'TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256',
                49227: 'TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384',
                49228: 'TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256',
                49229: 'TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384',
                49230: 'TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256',
                49231: 'TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384',
                49232: 'TLS_RSA_WITH_ARIA_128_GCM_SHA256',
                49233: 'TLS_RSA_WITH_ARIA_256_GCM_SHA384',
                49234: 'TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256',
                49235: 'TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384',
                49236: 'TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256',
                49237: 'TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384',
                49238: 'TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256',
                49239: 'TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384',
                49240: 'TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256',
                49241: 'TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384',
                49242: 'TLS_DH_anon_WITH_ARIA_128_GCM_SHA256',
                49243: 'TLS_DH_anon_WITH_ARIA_256_GCM_SHA384',
                49244: 'TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256',
                49245: 'TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384',
                49246: 'TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256',
                49247: 'TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384',
                49248: 'TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256',
                49249: 'TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384',
                49250: 'TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256',
                49251: 'TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384',
                49252: 'TLS_PSK_WITH_ARIA_128_CBC_SHA256',
                49253: 'TLS_PSK_WITH_ARIA_256_CBC_SHA384',
                49254: 'TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256',
                49255: 'TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384',
                49256: 'TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256',
                49257: 'TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384',
                49258: 'TLS_PSK_WITH_ARIA_128_GCM_SHA256',
                49259: 'TLS_PSK_WITH_ARIA_256_GCM_SHA384',
                49260: 'TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256',
                49261: 'TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384',
                49262: 'TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256',
                49263: 'TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384',
                49264: 'TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256',
                49265: 'TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384',
                49266: 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
                49267: 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
                49268: 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
                49269: 'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
                49270: 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
                49271: 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384',
                49272: 'TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256',
                49273: 'TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384',
                49274: 'TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256',
                49275: 'TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384',
                49276: 'TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256',
                49277: 'TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384',
                49278: 'TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256',
                49279: 'TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384',
                49280: 'TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256',
                49281: 'TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384',
                49282: 'TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256',
                49283: 'TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384',
                49284: 'TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256',
                49285: 'TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384',
                49286: 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256',
                49287: 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384',
                49288: 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256',
                49289: 'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384',
                49290: 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256',
                49291: 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384',
                49292: 'TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256',
                49293: 'TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384',
                49294: 'TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256',
                49295: 'TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384',
                49296: 'TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256',
                49297: 'TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384',
                49298: 'TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256',
                49299: 'TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384',
                49300: 'TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256',
                49301: 'TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384',
                49302: 'TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256',
                49303: 'TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384',
                49304: 'TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256',
                49305: 'TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384',
                49306: 'TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256',
                49307: 'TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384',
                49308: 'TLS_RSA_WITH_AES_128_CCM',
                49309: 'TLS_RSA_WITH_AES_256_CCM',
                49310: 'TLS_DHE_RSA_WITH_AES_128_CCM',
                49311: 'TLS_DHE_RSA_WITH_AES_256_CCM',
                49312: 'TLS_RSA_WITH_AES_128_CCM_8',
                49313: 'TLS_RSA_WITH_AES_256_CCM_8',
                49314: 'TLS_DHE_RSA_WITH_AES_128_CCM_8',
                49315: 'TLS_DHE_RSA_WITH_AES_256_CCM_8',
                49316: 'TLS_PSK_WITH_AES_128_CCM',
                49317: 'TLS_PSK_WITH_AES_256_CCM',
                49318: 'TLS_DHE_PSK_WITH_AES_128_CCM',
                49319: 'TLS_DHE_PSK_WITH_AES_256_CCM',
                49320: 'TLS_PSK_WITH_AES_128_CCM_8',
                49321: 'TLS_PSK_WITH_AES_256_CCM_8',
                49322: 'TLS_PSK_DHE_WITH_AES_128_CCM_8',
                49323: 'TLS_PSK_DHE_WITH_AES_256_CCM_8',
                49324: 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM',
                49325: 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM',
                49326: 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8',
                49327: 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8',
                52392: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
                52393: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
                52394: 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
                52395: 'TLS_PSK_WITH_CHACHA20_POLY1305_SHA256',
                52396: 'TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256',
                52397: 'TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256',
                52398: 'TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256'
            },

            Cache.SSL_FLOW_FLAGS: {
                1: 'NSE_FLOW_VALID',
                2: 'NSE_FLOW_INITIALIZED',
                4: 'NSE_FLOW_INTERCEPT'
            },

            Cache.SSL_FLOW_MESSAGES: {
                0x00000001: 'NSE_MT__HELLO_REQUEST',
                0x00000002: 'NSE_MT__CLIENT_ALERT',
                0x00000004: 'NSE_MT__SERVER_ALERT',
                0x00000008: 'NSE_MT__CLIENT_HELLO',
                0x00000010: 'NSE_MT__SERVER_HELLO',
                0x00000020: 'NSE_MT__SERVER_CERTIFICATE',
                0x00000040: 'NSE_MT__SERVER_KEY_EXCHANGE',
                0x00000080: 'NSE_MT__CERTIFICATE_REQUEST',
                0x00000100: 'NSE_MT__SERVER_HELLO_DONE',
                0x00000200: 'NSE_MT__CLIENT_CERTIFICATE',
                0x00000400: 'NSE_MT__CLIENT_KEY_EXCHANGE',
                0x00000800: 'NSE_MT__CERTIFICATE_VERIFY',
                0x00001000: 'NSE_MT__CLIENT_CHANGE_CIPHER_SPEC',
                0x00002000: 'NSE_MT__CLIENT_FINISHED',
                0x00004000: 'NSE_MT__SERVER_CHANGE_CIPHER_SPEC',
                0x00008000: 'NSE_MT__SERVER_FINISHED',
                0x00010000: 'NSE_MT__NEW_SESSION_TICKET',
                0x00020000: 'NSE_MT__HANDSHAKE_OTHER',
                0x00040000: 'NSE_MT__APP_DATA_FROM_CLIENT',
                0x00080000: 'NSE_MT__APP_DATA_FROM_SERVER'
            },

            Cache.SSL_CERT_STATUSES: {
                0: 'Not checked - The server certificate status was not evaluated.',
                1: 'Unknown - The server certificate status could not be determined.',
                2: 'Valid - The server certificate is valid.',
                4: 'Self-signed - The server certificate is self-signed.',
                16: 'Invalid Issuer - The server certificate has an invalid issuer.',
                32: 'Invalid Signature - The server certificate has an invalid signature.',
                64: 'Expired - The server certificate is expired.',
                128: 'Not valid yet - The server certificate is not yet valid.',
                256: 'Revoked - The server certificate has been revoked.'
            },

            Cache.USER_PROTOCOLS: {
                683: 'IMAP',
                710: 'LDAP'
            }
        }



    def store( self, source ):
        """
        update() takes an incoming wire record and if appropriate
        takes the metadata from it and adds it to this class.
        """
        if 'recordType' not in source:
            return

        try:
            record = estreamer.common.Flatdict( source )
            recordTypeId = record['recordType']

            # In most general cases, this will do. However, some records are more complex
            # and will be dealth with below
            if recordTypeId in Cache.AUTOMAP:
                mapping = Cache.AUTOMAP[recordTypeId]
                self.set([ mapping['cache'], record[ mapping['id'] ] ], record[ mapping['value'] ] )


            # Now we do the special cases which need to update complex objects
            if recordTypeId == definitions.METADATA_RNA_FINGERPRINT:
                # 54
                self.set( [ Cache.OS_FINGERPRINTS, record['uuid']], {
                    'os': record['name'],
                    'vendor': record['vendor'],
                    'ver': record['version'] })

            elif recordTypeId == definitions.METADATA_RULE_MESSAGE:
                # 66
                self.set(
                    [ Cache.IDS_RULES, record['generatorId'], record['ruleId']],
                    record['message'])

                self.set(
                    [ Cache.IDS_RULES_RENDERED, record['generatorId'], record['ruleId']],
                    record['signatureId'])

            elif recordTypeId == definitions.METADATA_CLASSIFICATION:
                # 67
                self.set([ Cache.CLASSIFICATIONS, record['id'] ], {
                    'name': record['name'],
                    'desc': record['description'] })

            elif recordTypeId == definitions.METADATA_CORRELATION_RULE:
                # 70
                self.set([ Cache.CORRELATION_RULES, record['id']], {
                    'name': record['name'],
                    'desc': record['description'],
                    'type': record['eventType'] })

            elif recordTypeId == definitions.METADATA_ACCESS_CONTROL_POLICY_NAME:
                # 117 - This is all but deprecated now. Leave for the time being
                self.set([ Cache.POLICIES, record['uuid']], record['name.data'])

                # # Add the default action rule
                self.set([ Cache.FW_RULES, record['uuid'], '0'], 'Default Action')

            elif recordTypeId == definitions.METADATA_ACCESS_CONTROL_RULE_ID:
                # 119
                self.set(
                    [ Cache.FW_RULES, record['uuid'], record['id'] ], record['name.data'])

            elif recordTypeId == definitions.METADATA_ACCESS_CONTROL_POLICY or \
                recordTypeId == definitions.METADATA_PREFILTER_POLICY or \
                recordTypeId == definitions.METADATA_TUNNEL_OR_PREFILTER_RULE:
                # 145,6,7 - This is used to link to the sensor and supersedes 117
                self.set(
                    [ Cache.ACCESS_CONTROL_POLICIES, record['sensorId'], record['uuid']],
                    record['name.data'])

            elif recordTypeId == definitions.METADATA_IOC_NAME:
                # 161
                self.set([ Cache.IOC, record['id'] ], {
                    'category': record['category.data'],
                    'eventType': record['eventType.data'] })

            elif recordTypeId == definitions.METADATA_ICMP_TYPE:
                # 260
                self.set(
                    [ Cache.ICMP_TYPES, record['protocol'], record['type'] ],
                    record['description.data'])

            elif recordTypeId == definitions.METADATA_SECURITY_INTELLIGENCE_CATEGORY_DISCOVERY:
                # 280
                self.set(
                    [ Cache.SI_LISTS_DISCOVERY, record['id'], record['accessControlPolicyUuid'] ],
                    record['name.data'])

            elif recordTypeId == definitions.METADATA_DNS_RECORD:
                # 320
                self.set([ Cache.DNS_RECORDS, record['id'] ], {
                    'name': record['name.data'],
                    'description': record['description.data'] })

            elif recordTypeId == definitions.METADATA_DNS_RESPONSE:
                # 321
                self.set([ Cache.DNS_RESPONSES, record['id'] ], {
                    'name': record['name.data'],
                    'description': record['description.data'] })

        except KeyError as ex:
            msg = 'Metadata key ({0}) missing on object ({1}). Ignoring'.format( ex, str( source ) )
            self.logger.debug( msg )
