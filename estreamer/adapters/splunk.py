"""
Lightweight adapter which combines the splunk transformer with
the kvpair adapter
"""
#********************************************************************
#      File:    splunk.py
#      Author:  Sam Strachan
#
#      Description:
#       Splunk adapter
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

# Disable "too many lines"
#pylint: disable=C0302

import estreamer.common
import estreamer.definitions as definitions
import estreamer
import argparse
import estreamer.crossprocesslogging as logging

from estreamer.adapters.kvpair import dumps as kvdumps
from estreamer.metadata import View

FIELD_MAPPING = {
    View.OUTPUT_KEY: {
        View.ACTION: 'action',
        View.AGENT_USER: 'agent_user',
        View.APP_PROTO: 'app_proto',
        View.ARCHIVE_FILE_STATUS: 'archive_file_status',
        View.BLOCKED: 'blocked',
        View.CLASSIFICATION_DESCRIPTION: 'class_desc',
        View.CLASSIFICATION_NAME: 'class',
        View.CLIENT_APP: 'client_app',
        View.CLOUD: 'cloud',
        View.CORRELATION_RULE: 'corr_rule',
        View.CORRELATION_POLICY: 'corr_policy',
        View.DATA: 'data',
        View.DESCRIPTION: 'description',
        View.DESTINATION_APP_PROTO: 'dest_app_proto',
        View.DESTINATION_IP: 'destinationIp',
        View.DESTINATION_IP_COUNTRY: 'dest_ip_country',
        View.DESTINATION_CRITICALITY: 'dest_criticality',
        View.DESTINATION_HOSTTYPE: 'dest_host_type',
        View.DESTINATION_OS_NAME: 'dest_os_name',
        View.DESTINATION_OS_VENDOR: 'dest_os_vendor',
        View.DESTINATION_OS_VERSION: 'dest_os_ver',
        View.DESTINATION_USER: 'dest_user',
        View.DETECTOR: 'detector',
        View.DETECTION: 'detection',
        View.DETECTION_NAME: 'detection_name',
        View.DIRECTION: 'direction',
        View.DISPOSITION: 'disposition',
        View.DNS_RECORD_NAME: 'dns_record_name',
        View.DNS_RECORD_DESCRIPTION: 'dns_record_desc',
        View.DNS_RESPONSE_NAME: 'dns_response_name',
        View.DNS_RESPONSE_DESCRIPTION: 'dns_response_desc',
        View.EVENT_TIMESTAMP: None,
        View.EVENT_DESC: 'event_desc',
        View.EVENT_SEC: 'event_sec',
        View.EVENT_TYPE: 'event_type',
        View.EVENT_USEC: 'event_usec',
        View.FILE_ACTION: 'file_action',
        View.FILE_POLICY: 'file_policy',
        View.FILE_STORAGE_STATUS: 'file_storage_status',
        View.FILE_SANDBOX_STATUS: 'file_sandbox_status',
        View.FILE_TYPE: 'file_type',
        View.FW_POLICY: 'fw_policy',
        View.FW_RULE: 'fw_rule',
        View.FW_RULE_ACTION: 'fw_rule_action',
        View.FW_RULE_REASON: 'fw_rule_reason',
        View.IDS_POLICY: 'ids_policy',
        View.IFACE_EGRESS: 'iface_egress',
        View.IFACE_INGRESS: 'iface_ingress',
        View.IMPACT: 'impact',
        View.IMPACT_DESCRIPTION: 'impact_desc',
        View.IOC_CATEGORY: 'ioc_category',
        View.IP_PROTOCOL: 'ip_proto',
        View.MALWARE_ANALYSIS_STATUS: 'malware_analysis_status',
        View.MALWARE_EVENT_TYPE: 'malware_event_type',
        View.MALWARE_EVENT_SUBTYPE: 'malware_event_subtype',
        View.MONITOR_RULE.format(1): 'monitor_rule_1',
        View.MONITOR_RULE.format(2): 'monitor_rule_2',
        View.MONITOR_RULE.format(3): 'monitor_rule_3',
        View.MONITOR_RULE.format(4): 'monitor_rule_4',
        View.MONITOR_RULE.format(5): 'monitor_rule_5',
        View.MONITOR_RULE.format(6): 'monitor_rule_6',
        View.MONITOR_RULE.format(7): 'monitor_rule_7',
        View.MONITOR_RULE.format(8): 'monitor_rule_8',
        View.MSG: 'msg',
        View.NET_PROTO: 'net_proto',
        View.NETWORK_ANALYSIS_POLICY: 'net_analysis_policy',
        View.ORIGINAL_CLIENT_SRC_IP: 'originalClientSrcIp',
        View.PARENT_DETECTION: 'parent_detection',
        View.PRIORITY: 'priority',
        View.REC_TYPE_SIMPLE: 'rec_type_simple',
        View.REC_TYPE_DESCRIPTION: 'rec_type_desc',
        View.RENDERED_ID: 'sid',
        View.RETRO_DISPOSITION: 'retro_disposition',
        View.SEC_INTEL_EVENT: 'sec_intel_event',
        View.SEC_INTEL_IP: 'sec_intel_ip',
        View.SEC_INTEL_LIST1: 'sec_intel_list1',
        View.SEC_INTEL_LIST2: 'sec_intel_list2',
        View.SEC_INTEL_POLICY: 'sec_intel_policy',
        View.SEC_ZONE_INGRESS: 'sec_zone_ingress',
        View.SEC_ZONE_EGRESS: 'sec_zone_egress',
        View.SENSOR: 'sensor',
        View.SINKHOLE: 'sinkhole',
        View.SOURCE: 'source',
        View.SOURCE_APP_PROTO: 'src_app_proto',
        View.SOURCE_IP: 'sourceIp',
        View.SOURCE_IP_COUNTRY: 'src_ip_country',
        View.SOURCE_CRITICALITY: 'src_criticality',
        View.SOURCE_HOSTTYPE: 'src_host_type',
        View.SOURCE_TYPE: 'source_type',
        View.SOURCE_OS_NAME: 'src_os_name',
        View.SOURCE_OS_VENDOR: 'src_os_vendor',
        View.SOURCE_OS_VERSION: 'src_os_ver',
        View.SOURCE_USER: 'src_user',
        View.SPERO_DISPOSITION: 'spero_disposition',
        View.SSL_ACTUAL_ACTION: 'ssl_actual_action',
        View.SSL_CIPHER_SUITE: 'ssl_cipher_suite',
        View.SSL_EXPECTED_ACTION: 'ssl_expected_action',
        View.SSL_FLOW_FLAGS: 'ssl_flow_flag',
        View.SSL_FLOW_MESSAGES: 'ssl_flow_message',
        View.SSL_FLOW_STATUS: 'ssl_flow_status',
        View.SSL_SERVER_CERT_STATUS: 'ssl_server_cert_status',
        View.SSL_URL_CATEGORY: 'ssl_url_category',
        View.SSL_VERSION: 'ssl_version',
        View.SUBTYPE: 'subtype',
        View.TYPE: 'type',
        View.UNHANDLED: 'unhandled_by_client',
        View.URL_CATEGORY: 'url_category',
        View.URL_REPUTATION: 'url_reputation',
        View.USER: 'user',
        View.WEB_APP: 'web_app' },

    # 2
    definitions.RECORD_PACKET: {
        'deviceId': u'device_id',
        'eventId': u'event_id',
        'eventSecond': u'event_sec',
        'linkType': u'link_type',
        'packetData': u'packet',
        'packetLength': u'packet_len',
        'packetMicrosecond': u'packet_usec',
        'packetSecond': u'packet_sec'},

    # 4
    definitions.RECORD_PRIORITY: {
        'id': u'priority_id',
        'name': u'name'},

    # 9
    definitions.RECORD_INTRUSION_IMPACT_ALERT: {
        'blockLength': u'',
        'blockType': u'',
        'description.blockLength': u'',
        'description.blockType': u'',
        'description.data': u'description',
        'destinationIpAddress': u'dest_ip',
        'deviceId': u'device_id',
        'eventId': u'event_id',
        'eventSecond': u'event_sec',
        'impact': u'impact',
        'sourceIpAddress': u'src_ip'},

    #10
    definitions.RECORD_RNA_NEW_HOST: {
        'deviceId': u'device_id',
        'eventMicrosecond': u'event_usec',
        'eventSecond': u'event_sec',
        'eventSubtype': u'event_subtype',
        'eventType': u'event_type',
        'hasIpv6': u'has_ipv6',
        'hostProfile.blockString': u'',
        'hostProfile.blockType': u'',
        'hostProfile.clientApplications': u'',
        'hostProfile.clientFingerprints': u'',
        'hostProfile.dhcpFingerprints': u'',
        'hostProfile.hops': u'hops',
        'hostProfile.hostLastSeen': u'last_seen',
        'hostProfile.hostMacAddress': u'',
        'hostProfile.hostType': u'host_type',
        'hostProfile.ipAddress': u'',
        'hostProfile.ipv6ClientFingerprints': u'',
        'hostProfile.ipv6DhcpFingerprints': u'',
        'hostProfile.ipv6ServerFingerprints': u'',
        'hostProfile.jailbroken': u'jailbroken',
        'hostProfile.mobile': u'mobile',
        'hostProfile.mobileDeviceFingerprints': u'',
        'hostProfile.netbios.blockLength': u'',
        'hostProfile.netbios.blockType': u'',
        'hostProfile.netbios.data': u'netbios_domain',
        'hostProfile.networkProtocol': u'',
        'hostProfile.primarySecondary': u'',
        'hostProfile.serverFingerprints': u'',
        'hostProfile.smbFingerprints': u'',
        'hostProfile.tcpServer': u'',
        'hostProfile.transportProtocol': u'',
        'hostProfile.udpServer': u'',
        'hostProfile.userAgentFingerprints': u'',
        'hostProfile.vlanId': u'vlan_id',
        'hostProfile.vlanPresence': u'vlan_presence',
        'hostProfile.vlanPriority': u'vlan_priority',
        'hostProfile.vlanType': u'vlan_type',
        'ipAddress': u'ip_address',
        'macAddress': u'mac_address'},

    # 11
    definitions.RECORD_RNA_NEW_TCP_SERVICE: {
        'deviceId': u'device_id',
        'eventMicrosecond': u'event_usec',
        'eventSecond': u'event_sec',
        'eventSubtype': u'event_subtype',
        'eventType': u'event_type',
        'hasIpv6': u'has_ipv6',
        'hostServer.blockLength': u'',
        'hostServer.blockType': u'',
        'hostServer.confidence': u'confidence',
        'hostServer.hits': u'hits',
        'hostServer.lastUsed': u'last_used',
        'hostServer.port': u'port',
        'hostServer.serverInformation': u'',
        'hostServer.webApplication': u'',
        'ipAddress': u'',
        'macAddress': u'mac_address'},

    # 12
    definitions.RECORD_RNA_NEW_UDP_SERVICE: {
        'deviceId': u'device_id',
        'eventMicrosecond': u'event_usec',
        'eventSecond': u'event_sec',
        'eventSubtype': u'event_subtype',
        'eventType': u'event_type',
        'hasIpv6': u'has_ipv6',
        'hostServer.blockLength': u'',
        'hostServer.blockType': u'',
        'hostServer.confidence': u'confidence',
        'hostServer.hits': u'hits',
        'hostServer.lastUsed': u'last_used',
        'hostServer.port': u'port',
        'hostServer.serverInformation': u'',
        'hostServer.webApplication': u'',
        'ipAddress': u'',
        'macAddress': u'mac_address'},

    # 13
    definitions.RECORD_RNA_NEW_NET_PROTOCOL: {
        'deviceId': u'device_id',
        'eventMicrosecond': u'event_usec',
        'eventSecond': u'event_sec',
        'eventSubtype': u'event_subtype',
        'eventType': u'event_type',
        'hasIpv6': u'has_ipv6',
        'macAddress': u'mac_address',
        'networkProtocol': u'net_proto'},

    # 14
    definitions.RECORD_RNA_NEW_XPORT_PROTOCOL: {
        'deviceId': u'device_id',
        'eventMicrosecond': u'event_usec',
        'eventSecond': u'event_sec',
        'eventSubtype': u'event_subtype',
        'eventType': u'event_type',
        'hasIpv6': u'has_ipv6',
        'ipAddress':  u'ip_address',
        'macAddress': u'mac_address',
        'transportProtocol': u'ip_proto'},

    # 15
    definitions.RECORD_RNA_NEW_CLIENT_APP: {
        'client.applicationProto': u'app_proto',
        'client.blockLength': u'',
        'client.blockType': u'',
        'client.hits': u'hits',
        'client.id': u'client_id',
        'client.lastUsed': u'last_used',
        'client.version.blockLength': u'',
        'client.version.blockType': u'',
        'client.version.data': u'version',
        'client.webApplication': u'',
        'deviceId': u'device_id',
        'eventMicrosecond': u'event_usec',
        'eventSecond': u'event_sec',
        'eventSubtype': u'event_subtype',
        'eventType': u'event_type',
        'hasIpv6': u'has_ipv6',
        'macAddress': u'mac_address'},

    # 16
    definitions.RECORD_RNA_CHANGE_TCP_SERVICE_INFO: {
        'deviceId': u'device_id',
        'eventMicrosecond': u'event_usec',
        'eventSecond': u'event_sec',
        'eventSubtype': u'event_subtype',
        'eventType': u'event_type',
        'hasIpv6': u'has_ipv6',
        'hostServer.blockLength': u'',
        'hostServer.blockType': u'',
        'hostServer.confidence': u'confidence',
        'hostServer.hits': u'hits',
        'hostServer.lastUsed': u'last_used',
        'hostServer.port': u'port',
        'hostServer.serverInformation': u'',
        'hostServer.webApplication': u'',
        'ipAddress': u'ip_address',
        'macAddress': u'mac_address'},

    # 17
    definitions.RECORD_RNA_CHANGE_UDP_SERVICE_INFO: {
        'deviceId': u'device_id',
        'eventMicrosecond': u'event_usec',
        'eventSecond': u'event_sec',
        'eventSubtype': u'event_subtype',
        'eventType': u'event_type',
        'hasIpv6': u'has_ipv6',
        'hostServer.blockLength': u'',
        'hostServer.blockType': u'',
        'hostServer.confidence': u'confidence',
        'hostServer.hits': u'hits',
        'hostServer.lastUsed': u'last_used',
        'hostServer.port': u'port',
        'hostServer.serverInformation': u'',
        'hostServer.webApplication': u'',
        'macAddress': u'mac_address'},

    # 18
    definitions.RECORD_RNA_CHANGE_OS: {},

    # 19
    definitions.RECORD_RNA_CHANGE_HOST_TIMEOUT: {
        'deviceId': u'device_id',
        'eventMicrosecond': u'event_usec',
        'eventSecond': u'event_sec',
        'eventSubtype': u'event_subtype',
        'eventType': u'event_type',
        'hasIpv6': u'has_ipv6',
        'macAddress': u'mac_address'},

    # 20
    definitions.RECORD_RNA_CHANGE_HOST_REMOVE: {
        'deviceId': u'device_id',
        'eventMicrosecond': u'event_usec',
        'eventSecond': u'event_sec',
        'eventSubtype': u'event_subtype',
        'eventType': u'event_type',
        'hasIpv6': u'has_ipv6',
        'macAddress': u'mac_address'},

    # 21
    definitions.RECORD_RNA_CHANGE_HOST_ANR_DELETE: {
        'deviceId': u'device_id',
        'eventMicrosecond': u'event_usec',
        'eventSecond': u'event_sec',
        'eventSubtype': u'event_subtype',
        'eventType': u'event_type',
        'hasIpv6': u'has_ipv6',
        'macAddress': u'mac_address'},

    # 22
    definitions.RECORD_RNA_CHANGE_HOPS: {
        'deviceId': u'device_id',
        'eventMicrosecond': u'event_usec',
        'eventSecond': u'event_sec',
        'eventSubtype': u'event_subtype',
        'eventType': u'event_type',
        'hasIpv6': u'has_ipv6',
        'hops': u'hops',
        'macAddress': u'mac_address'},

    # 23
    definitions.RECORD_RNA_CHANGE_TCP_PORT_CLOSED: {},

    # 24
    definitions.RECORD_RNA_CHANGE_UDP_PORT_CLOSED: {},

    # 25
    definitions.RECORD_RNA_CHANGE_TCP_PORT_TIMEOUT: {
        'deviceId': u'device_id',
        'eventMicrosecond': u'event_usec',
        'eventSecond': u'event_sec',
        'eventSubtype': u'event_subtype',
        'eventType': u'event_type',
        'hasIpv6': u'has_ipv6',
        'macAddress': u'mac_address',
        'port': u'port'},

    # 26
    definitions.RECORD_RNA_CHANGE_UDP_PORT_TIMEOUT: {
        'deviceId': u'device_id',
        'eventMicrosecond': u'event_usec',
        'eventSecond': u'event_sec',
        'eventSubtype': u'event_subtype',
        'eventType': u'event_type',
        'hasIpv6': u'has_ipv6',
        'macAddress': u'mac_address',
        'port': u'port'},

    # 27
    definitions.RECORD_RNA_CHANGE_MAC_INFO: {
        'deviceId': u'device_id',
        'eventMicrosecond': u'event_usec',
        'eventSecond': u'event_sec',
        'eventSubtype': u'event_subtype',
        'eventType': u'event_type',
        'hasIpv6': u'has_ipv6',
        'mac.address': u'additional_mac_address',
        'mac.blockLength': u'',
        'mac.blockType': u'',
        'mac.lastSeen': u'last_seen',
        'mac.primary': u'primary',
        'mac.ttl': u'ttl',
        'macAddress': u'mac_address' },

    # 28
    definitions.RECORD_RNA_CHANGE_MAC_ADD: {
        'deviceId': u'device_id',
        'eventMicrosecond': u'event_usec',
        'eventSecond': u'event_sec',
        'eventSubtype': u'event_subtype',
        'eventType': u'event_type',
        'hasIpv6': u'has_ipv6',
        'mac.address': u'additional_mac_address',
        'mac.blockLength': u'',
        'mac.blockType': u'',
        'mac.lastSeen': u'last_seen',
        'mac.primary': u'primary',
        'mac.ttl': u'ttl',
        'macAddress': u'mac_address' },

    # 29
    definitions.RECORD_RNA_CHANGE_HOST_IP: {},

    # 31
    definitions.RECORD_RNA_CHANGE_HOST_TYPE: {
        'deviceId': u'device_id',
        'eventMicrosecond': u'event_usec',
        'eventSecond': u'event_sec',
        'eventSubtype': u'event_subtype',
        'eventType': u'event_type',
        'hasIpv6': u'has_ipv6',
        'hostType': u'host_type',
        'macAddress': u'mac_address'},

    # 34
    definitions.RECORD_RNA_CHANGE_VLAN_TAG: {},

    # 35 - is a copy of 15. See below
    # definitions.RECORD_RNA_CHANGE_CLIENT_APP_TIMEOUT

    # 42
    definitions.RECORD_RNA_CHANGE_NETBIOS_NAME: {},

    # 44
    definitions.RECORD_RNA_CHANGE_HOST_DROPPED: {},

    # 45
    definitions.RECORD_RNA_CHANGE_BANNER_UPDATE: {},

    # 46
    definitions.RECORD_RNA_USER_ADD_ATTRIBUTE: {},

    # 47
    definitions.RECORD_RNA_USER_UPDATE_ATTRIBUTE: {},

    # 48
    definitions.RECORD_RNA_USER_DELETE_ATTRIBUTE: {},

    # 51
    definitions.RECORD_RNA_CHANGE_TCP_SERVICE_CONFIDENCE: {},

    # 52
    definitions.RECORD_RNA_CHANGE_UDP_SERVICE_CONFIDENCE: {},

    # 53
    definitions.RECORD_RNA_CHANGE_OS_CONFIDENCE: {},

    # 54
    definitions.METADATA_RNA_FINGERPRINT: {
        'uuid': u'fpuuid',
        'name': u'os_name_data',
        'nameLength': u'',
        'vendor': u'os_vendor_data',
        'vendorLength': u'',
        'version': u'os_version_data',
        'versionLength': u''},

    # 55
    definitions.METADATA_RNA_CLIENT_APPLICATION: {
        'id': u'id',
        'length': u'',
        'name': u'name'},

    # 57
    definitions.METADATA_RNA_VULNERABILITY: {},

    # 58
    definitions.METADATA_RNA_CRITICALITY: {},

    # 59
    definitions.METADATA_RNA_NETWORK_PROTOCOL: {
        'id': u'id',
        'length': u'',
        'name': u'name'},

    # 60
    definitions.METADATA_RNA_ATTRIBUTE: {
        'id': u'id',
        'length': u'',
        'name': u'name'},

    # 61
    definitions.METADATA_RNA_SCAN_TYPE: {},

    # 62
    definitions.RECORD_USER: {
        'blockLength': u'',
        'blockType': u'',
        'id': u'id',
        'name': u'name',
        'protocol': u'protocol'},

    # 63
    definitions.METADATA_RNA_SERVICE: {
        'id': u'id',
        'name': u'name',
        'length': u''},

    # 66
    definitions.METADATA_RULE_MESSAGE: {
        'generatorId': u'gid',
        'ruleId': u'id',
        'ruleRevision': u'rev',
        'signatureId': u'sid',
        'messageLength': u'',
        'ruleUuid': u'rule_uuid',
        'ruleRevisionUuid': u'rev_uuid',
        'message': u'msg'},

    # 67
    definitions.METADATA_CLASSIFICATION: {
        'classificationid': u'id',
        'nameLength': u'',
        'name': u'name',
        'descriptionLength': u'',
        'description': u'description',
        'uuid': u'uuid',
        'revisionUuid': u'rev_uuid'},

    # 69
    definitions.METADATA_CORRELATION_POLICY: {
        'id': u'id',
        'revisionUuid': u'rev_uuid',
        'uuid': u'uuid',
        'description': u'description',
        'descriptionLength': u'',
        'name': u'name',
        'nameLength': u''},

    # 70
    definitions.METADATA_CORRELATION_RULE: {
        'correlationRevisionUuid': 'rev_uuid',
        'correlationRuleUuid': u'uuid',
        'description': u'description',
        'descriptionLength': u'',
        'eventType': u'event_type',
        'eventTypeLength': u'',
        'id': u'id',
        'name': u'name',
        'nameLength': u'',
        'whitelistUuid': u'whitelist_uuid'},

    # 71
    definitions.RECORD_RNA_CONNECTION_STATISTICS: {
        'applicationId': u'app_proto',
        'blockLength': u'',
        'blockType': u'',
        'clientApplicationId': u'client_app',
        'clientApplicationVersion.blockLength': u'',
        'clientApplicationVersion.blockType': u'',
        'clientApplicationVersion.data': u'client_version',
        'clientUrl.blockLength': u'',
        'clientUrl.blockType': u'',
        'clientUrl.data': u'url',
        'connectionCounter': u'connection_id',
        'destinationAutonomousSystem': u'dest_autonomous_system',
        'destinationMask': u'dest_mask',
        'destinationTos': u'dest_tos',
        'deviceId': u'device_id',
        'dnsQuery.blockLength': u'',
        'dnsQuery.blockType': u'',
        'dnsQuery.data': u'dns_query',
        'dnsRecordType': u'dns_rec_id',
        'dnsResponseType': u'dns_resp_id',
        'dnsTtl': u'dns_ttl',
        'egressInterface': u'iface_egress',
        'egressZone': u'sec_zone_egress',
        'endpointProfileId': u'',
        'fileEventCount': u'file_count',
        'firstPacketTimestamp': u'first_pkt_sec',
        'httpReferrer.blockLength': u'',
        'httpReferrer.blockType': u'',
        'httpReferrer.data': u'http_referrer',
        'httpResponse': u'http_response',
        'ingressInterface': u'iface_ingress',
        'ingressZone': u'sec_zone_ingress',
        'initiatorBytesDropped': u'src_bytes_dropped',
        'initiatorCountry': u'src_ip_country',
        'initiatorIpAddress': u'src_ip',
        'initiatorPacketsDropped': u'src_packets_dropped',
        'initiatorPort': u'src_port',
        'initiatorTransmittedBytes': u'src_bytes',
        'initiatorTransmittedPackets': u'src_pkts',
        'instanceId': u'instance_id',
        'intrusionEventCount': u'ips_count',
        'iocNumber': u'num_ioc',
        'lastPacketTimestamp': u'last_pkt_sec',
        'locationIpv6': u'',
        'monitorRule1': u'monitor_rule_1',
        'monitorRule2': u'monitor_rule_2',
        'monitorRule3': u'monitor_rule_3',
        'monitorRule4': u'monitor_rule_4',
        'monitorRule5': u'monitor_rule_5',
        'monitorRule6': u'monitor_rule_6',
        'monitorRule7': u'monitor_rule_7',
        'monitorRule8': u'monitor_rule_8',
        'netbios.blockLength': u'',
        'netbios.blockType': u'',
        'netbios.data': u'netbios_domain',
        'netflowSource': u'netflow_src',
        'networkAnalysisPolicyRevision': u'',
        'originalClientCountry': u'',
        'originalClientIpAddress': u'',
        'policyRevision': u'fw_policy', # -> int -> string
        'protocol': u'ip_proto',
        'qosAppliedInterface': u'',
        'qosRuleId': u'',
        'referencedHost.blockLength': u'',
        'referencedHost.blockType': u'',
        'referencedHost.data': u'referenced_host',
        'responderBytesDropped': u'dest_bytes_dropped',
        'responderCountry': u'dest_ip_country',
        'responderIpAddress': u'dest_ip',
        'responderPacketsDropped': u'dest_packets_dropped',
        'responderPort': u'dest_port',
        'responderTransmittedBytes': u'dest_bytes',
        'responderTransmittedPackets': u'dest_pkts',
        'ruleAction': u'fw_rule_action',
        'ruleId': u'fw_rule',
        'ruleReason': u'fw_rule_reason',
        'securityContext': u'security_context',
        'securityGroupId': u'',
        'securityIntelligenceLayer': u'ip_layer',
        'securityIntelligenceList1': u'',
        'securityIntelligenceList2': u'',
        'securityIntelligenceSourceDestination': u'sec_intel_ip', \
        # -> sec_intel_event
        'sinkholeUuid': u'sinkhole_uuid',
        'snmpIn': u'snmp_in',
        'snmpOut': u'snmp_out',
        'sourceAutonomousSystem': u'src_autonomous_system',
        'sourceMask': u'src_mask',
        'sourceTos': u'src_tos',
        'sslActualAction': u'ssl_actual_action',
        'sslCertificateFingerprint': u'ssl_cert_fingerprint',
        'sslCipherSuite': u'ssl_cipher_suite',
        'sslExpectedAction': u'ssl_expected_action',
        'sslFlowError': u'ssl_flow_error',
        'sslFlowFlags': u'ssl_flow_flags',
        'sslFlowMessages': u'ssl_flow_messages',
        'sslFlowStatus': u'ssl_flow_status',
        'sslPolicyId': u'ssl_policy_id',
        'sslRuleId': u'ssl_rule_id',
        'sslServerCertificateStatus': u'ssl_server_cert_status',
        'sslServerName.blockLength': u'',
        'sslServerName.blockType': u'',
        'sslServerName.data': u'ssl_server_name',
        'sslSessionId': u'ssl_session_id',
        'sslSessionIdLength': u'',
        'sslTicketId': u'ssl_ticket_id',
        'sslTicketIdLength': u'',
        'sslUrlCategory': u'ssl_url_category',
        'sslVersion': u'ssl_version',
        'tcpFlag': u'tcp_flags',
        'tunnelRuleId': u'',
        'urlCategory': u'url_category',
        'urlReputation': u'url_reputation',
        'userAgent.blockLength': u'',
        'userAgent.blockType': u'',
        'userAgent.data': u'user_agent',
        'userId': u'user',
        'vlanId': u'vlan_id',
        'webApplicationId': u'web_app',
        # discovery
        'deviceId': u'', # -> sensor
        'eventMicrosecond': u'event_usec',
        'eventSecond': u'event_sec',
        'eventSubtype': u'event_subtype',
        'eventType': u'event_type', # -> event_desc
        'hasIpv6': u'has_ipv6',
        'macAddress': u'mac_address'},

    # 73
    definitions.RECORD_RNA_CONNECTION_CHUNK: {},

    # 74
    definitions.RECORD_RNA_USER_SET_OS: {},

    # 75
    definitions.RECORD_RNA_USER_SET_SERVICE: {},

    # 76
    definitions.RECORD_RNA_USER_DELETE_PROTOCOL: {},

    # 77
    definitions.RECORD_RNA_USER_DELETE_CLIENT_APP: {},

    # 78
    definitions.RECORD_RNA_USER_DELETE_ADDRESS: {},

    # 79
    definitions.RECORD_RNA_USER_DELETE_SERVICE: {},

    # 80
    definitions.RECORD_RNA_USER_VULNERABILITIES_VALID: {},

    # 81
    definitions.RECORD_RNA_USER_VULNERABILITIES_INVALID: {},

    # 82
    definitions.RECORD_RNA_USER_SET_CRITICALITY: {},

    # 83
    definitions.RECORD_RNA_USER_SET_ATTRIBUTE_VALUE: {},

    # 84
    definitions.RECORD_RNA_USER_DELETE_ATTRIBUTE_VALUE: {},

    # 85
    definitions.RECORD_RNA_USER_ADD_HOST: {},

    # 86
    definitions.RECORD_RNA_USER_ADD_SERVICE: {},

    # 87
    definitions.RECORD_RNA_USER_ADD_CLIENT_APP: {},

    # 88
    definitions.RECORD_RNA_USER_ADD_PROTOCOL: {},

    # 89
    definitions.RECORD_RNA_USER_ADD_SCAN_RESULT: {},

    # 90
    definitions.METADATA_RNA_SOURCE_TYPE: {
        'id': u'id',
        'length': u'',
        'name': u'name'},

    # 91
    definitions.METADATA_RNA_SOURCE_APP: {
        'id': u'id',
        'length': u'',
        'name': u'name'},

    # 92
    definitions.RUA_EVENT_CHANGE_USER_DROPPED: {},

    # 93
    definitions.RUA_EVENT_CHANGE_USER_REMOVE: {},

    # 94
    definitions.RUA_EVENT_NEW_USER: {
        'deviceId': u'device_id',
        'eventMicrosecond': u'event_usec',
        'eventSecond': u'event_sec',
        'eventSubtype': u'event_subtype',
        'eventType': u'event_type',
        'hasIpv6': u'has_ipv6',
        'macAddress': u'mac_address',
        'user.blockLength': u'',
        'user.blockType': u'',
        'user.department.blockLength': u'',
        'user.department.blockType': u'',
        'user.department.data': u'',
        'user.email.blockLength': u'',
        'user.email.blockType': u'',
        'user.email.data': u'',
        'user.firstName.blockLength': u'',
        'user.firstName.blockType': u'',
        'user.firstName.data': u'',
        'user.lastName.blockLength': u'',
        'user.lastName.blockType': u'',
        'user.lastName.data': u'',
        'user.phone.blockLength': u'',
        'user.phone.blockType': u'',
        'user.phone.data': u'',
        'user.protocol': u'',
        'user.userId': u'user',
        'user.username.blockLength': u'',
        'user.username.blockType': u'',
        'user.username.data': u''},

    # 95
    definitions.RUA_EVENT_CHANGE_USER_LOGIN: {
        'deviceId': u'device_id',
        'eventMicrosecond': u'event_usec',
        'eventSecond': u'event_sec',
        'eventSubtype': u'event_subtype',
        'eventType': u'event_type',
        'hasIpv6': u'has_ipv6',
        'macAddress': u'mac_address',
        'user.applicationId': u'client_app',
        'user.blockLength': u'',
        'user.blockType': u'',
        'user.email.blockLength': u'',
        'user.email.blockType': u'',
        'user.email.data': u'email',
        'user.endpointProfileId': u'',
        'user.ipv4Address': u'ipv4',
        'user.ipv6Address': u'ipv6',
        'user.loginType': u'login_type',
        'user.reportedBy.blockLength': u'',
        'user.reportedBy.blockType': u'',
        'user.reportedBy.data': u'reported_by',
        'user.timestamp': u'timestamp',
        'user.userId': u'user',
        'user.username.blockLength': u'',
        'user.username.blockType': u'',
        'user.username.data': u'username'},

    # 96
    definitions.METADATA_RNA_SOURCE_DETECTOR: {
        'name': u'name',
        'length': u'',
        'id': u'id'},

    # 98
    definitions.RECORD_RUA_USER: {
        'blockLength': u'',
        'blockType': u'',
        'protocol': u'ip_proto',
        'id': u'id',
        'name.blockLength': u'',
        'name.blockType': u'',
        'name.data': u'name'},

    # 101
    definitions.RECORD_RNA_NEW_OS: {
        'deviceId': u'device_id',
        'eventMicrosecond': u'event_usec',
        'eventSecond': u'event_sec',
        'eventSubtype': u'event_subtype',
        'eventType': u'event_type',
        'macAddress': u'mac_address',
        'hasIpv6': u'has_ipv6',
        'ipAddress': u'ip_address',
        'osfingerprint.blockLength': u'',
        'osfingerprint.blockType': u'',
        'osfingerprint.lastSeen': u'last_seen',
        'osfingerprint.sourceId': u'source_id',
        'osfingerprint.sourceType': u'source_type',
        'osfingerprint.ttlDifference': u'ttl_difference',
        'osfingerprint.type': u'os_type',
        'osfingerprint.uuid': u'os_uuid'},

    # 102
    definitions.RECORD_RNA_CHANGE_IDENTITY_CONFLICT: {},

    # 103
    definitions.RECORD_RNA_CHANGE_IDENTITY_TIMEOUT: {
        'deviceId': u'device_id',
        'eventMicrosecond': u'event_usec',
        'eventSecond': u'event_sec',
        'eventSubtype': u'event_subtype',
        'eventType': u'event_type',
        'hasIpv6': u'has_ipv6',
        'identity.blockLength': u'',
        'identity.blockType': u'',
        'identity.sourceId': u'source_id',
        'identity.sourceType': u'source_type',
        'identity.port': u'port',
        'identity.protocol': u'ip_proto',
        'identity.serverMapId': u'server_map',
        'identity.uuid': u'identity_uuid',
        'macAddress': u'mac_address'},

    # 106
    definitions.RECORD_THIRD_PARTY_SCAN_VULNERABILITY: {},

    # 107 - is a copy of 15. See below
    # definitions.RECORD_RNA_CHANGE_CLIENT_APP_UPDATE

    # 109
    definitions.RECORD_RNA_WEB_APPLICATION_PAYLOAD: {
        'id': u'id',
        'name': u'name',
        'length': u''},

    # 110
    definitions.RECORD_INTRUSION_EXTRA_DATA: {
        'blob.blockLength': u'',
        'blob.blockType': u'',
        'blob.data': u'data',
        'blockLength': u'',
        'blockType': u'',
        'originalClientSrcIp': u'originalClientSrcIp',
        'deviceId': u'device_id',
        'eventId': u'event_id',
        'type': u'type'},

    # 111
    definitions.METADATA_INTRUSION_EXTRA_DATA: {
        'blockLength': u'',
        'blockType': u'',
        'encoding.blockLength': u'',
        'encoding.blockType': u'',
        'encoding.data': u'encoding',
        'name.blockLength': u'',
        'name.blockType': u'',
        'name.data': u'name',
        'type': u'type'},

    # 112
    definitions.RECORD_CORRELATION_EVENT: {
        'accessControlPolicyRevision': u'policy_uuid',
        'accessControlRule': u'policy_rule',
        'blockLength': u'',
        'blockType': u'',
        'blocked': u'blocked',
        'clientId': u'client_id',
        'clientVersion.data': u'client_version',
        'correlationEventSecond': u'',
        'destinationCountry': u'dest_ip_country',
        'destinationCriticality': u'dest_criticality',
        'destinationHostType': u'dest_host_type',
        'destinationIp': u'dest_ip',
        'destinationIpv6Address': u'',
        'destinationOperatingSystemFingerprintUuid': u'dest_os_fingerprint_uuid',
        'destinationPort': u'dest_port',
        'destinationServerId': u'dest_app_proto',
        'destinationUserId': u'dest_user',
        'destinationVlanId': u'dest_vlan_id',
        'deviceId': u'policy_sensor',
        'deviceEventId': u'policy_event_id', # -> Documentation collision
        'egressIntefaceUuid': u'iface_egress',
        'egressZoneUuid': u'sec_zone_egress',
        'eventDefinedMask': u'defined_mask',
        'eventDescription.blockLength': u'',
        'eventDescription.blockType': u'',
        'eventDescription.data': u'description',
        'eventDeviceId': u'',
        'eventId': u'event_id',
        'eventImpactFlags': u'impact_bits', # -> derives impact
        'eventType': u'event_type',
        'impact': u'impact',
        'ingressIntefaceUuid': u'iface_ingress',
        'ingressZoneUuid': u'sec_zone_ingress',
        'intrusionPolicy': u'intrusion_policy',
        'ipProtocol': u'ip_proto',
        'netbios.data': u'netbios_domain',
        'networkProtocol': u'net_proto',
        'policyId': u'corr_policy',
        'priority': u'priority',
        'ruleId': u'corr_rule', # -> used to be fw_rule then corr_rule
        'ruleAction': u'action',
        'securityContext': u'security_context',
        'securityIntelligenceUuid': u'',
        'signatureGeneratorId': u'gid',
        'signatureId': u'sid',
        'sourceCountry': u'src_ip_country',
        'sourceCriticality': u'src_criticality',
        'sourceHostType': u'src_host_type',
        'sourceIp': u'src_ip',
        'sourceIpv6Address': u'',
        'sourceOperatingSystemFingerprintUuid': u'src_os_fingerprint_uuid', # -> src_os_*
        'sourcePort': u'src_port',
        'sourceServerId': u'src_app_proto',
        'sourceUserId': u'src_user',
        'sourceVlanId': u'src_vlan_id',
        'sslActualAction': u'ssl_actual_action',
        'sslCertificateFingerprint': u'ssl_cert_fingerprint',
        'sslFlowStatus': u'ssl_flow_status',
        'sslPolicyId': u'ssl_policy_id',
        'sslRuleId': u'ssl_rule_id',
        'triggerEventMicrosecond': u'orig_event_usec',
        'triggerEventSecond': u'orig_event_sec',
        'url.data': u'url',
        'urlCategory': u'url_category',
        'urlReputation': u'url_reputation'},

    # 115
    definitions.METADATA_SECURITY_ZONE_NAME: {
        'blockLength': u'',
        'blockType': u'',
        'name.blockLength': u'',
        'name.blockType': u'',
        'name.data': u'name',
        'uuid': u'uuid'},

    # 116
    definitions.METADATA_INTERFACE_NAME: {
        'blockLength': u'',
        'blockType': u'',
        'name.blockLength': u'',
        'name.blockType': u'',
        'name.data': u'name',
        'uuid': u'uuid'},

    # 117
    definitions.METADATA_ACCESS_CONTROL_POLICY_NAME: {
        'blockLength': u'',
        'blockType': u'',
        'uuid': u'uuid',
        'name.data': u'name'},

    # 118
    definitions.METADATA_INTRUSION_POLICY_NAME: {
        'blockLength': u'',
        'blockType': u'',
        'uuid': u'uuid',
        'name.data': u'name'},

    # 119
    definitions.METADATA_ACCESS_CONTROL_RULE_ID: {
        'id': u'id',
        'blockType': u'',
        'blockLength': u'',
        'name.blockLength': u'',
        'name.blockType': u'',
        'name.data': u'name',
        'uuid': u'uuid'},

    # 120
    definitions.METADATA_ACCESS_CONTROL_RULE_ACTION: {
        'name': u'name',
        'length': u'',
        'id': u'id'},

    # 121
    definitions.METADATA_URL_CATEGORY: {
        'name': u'name',
        'length': u'',
        'id': u'id'},

    # 122
    definitions.METADATA_URL_REPUTATION: {
        'name': u'name',
        'length': u'',
        'id': u'id'},

    # 123
    definitions.METADATA_SENSOR: {
        'id': u'id',
        'name': u'name',
        'length': u''},

    # 124
    definitions.METADATA_ACCESS_CONTROL_POLICY_RULE_REASON: {
        'blockLength': u'',
        'blockType': u'',
        'description.data': u'description',
        'id': u'reason'},

    # 125
    definitions.RECORD_MALWARE_EVENT: {
        'accessControlPolicyUuid': u'policy_uuid', # -> file_policy
        'action': u'file_action',
        'agentUuid': u'agent_uuid',
        'applicationId': u'app_proto',
        'archiveDepth': u'archive_depth',
        'archiveName.blockLength': u'',
        'archiveName.blockType': u'',
        'archiveName.data': u'archive_name',
        'archiveSha.blockLength': u'',
        'archiveSha.blockType': u'',
        'archiveSha.data': u'archive_sha',
        'blockLength': u'',
        'blockType': u'',
        'clientApplicationId': u'client_app',
        'cloudUuid': u'', # -> cloud
        'connectionCounter': u'connection_id',
        'connectionEventTimestamp': u'connection_sec',
        'connectionInstance': u'instance_id',
        'destinationCountry': u'dest_ip_country',
        'destinationIpAddress': u'dest_ip',
        'destinationPort': u'dest_port',
        'detectionName.blockLength': u'',
        'detectionName.blockType': u'',
        'detectionName.data': u'detection',
        'detectorId': u'detector',
        'deviceId': u'device_id',
        'direction': u'direction',
        'disposition': u'disposition',
        'eventDescription.blockLength': u'',
        'eventDescription.blockType': u'',
        'eventDescription.data': u'event_description',
        'eventSubtypeId': u'subtype',
        'eventTypeId': u'type',
        'fileName.blockLength': u'',
        'fileName.blockType': u'',
        'fileName.data': u'file_name',
        'filePath.blockLength': u'',
        'filePath.blockType': u'',
        'filePath.data': u'file_path',
        'fileShaHash.blockLength': u'',
        'fileShaHash.blockType': u'',
        'fileShaHash.data': u'sha256',
        'fileSize': u'file_size',
        'fileTimestamp': u'file_ts',
        'fileType': u'file_type',
        'httpResponse': u'http_response',
        'iocNumber': u'num_ioc',
        'malwareEventTimestamp': u'event_sec',
        'parentFileName.blockLength': u'',
        'parentFileName.blockType': u'',
        'parentFileName.data': u'parent_fname',
        'parentShaHash.blockLength': u'',
        'parentShaHash.blockType': u'',
        'parentShaHash.data': u'parent_sha256',
        'protocol': u'ip_proto',
        'retroDisposition': u'retro_disposition',
        'securityContext': u'security_context',
        'sourceCountry': u'src_ip_country',
        'sourceIpAddress': u'src_ip',
        'sourcePort': u'src_port',
        'sslActualAction': u'ssl_actual_action',
        'sslCertificateFingerprint': u'ssl_cert_fingerprint',
        'sslFlowStatus': u'ssl_flow_status',
        'threatScore': u'threat_score',
        'uri.blockLength': u'',
        'uri.blockType': u'',
        'uri.data': u'uri',
        'user.blockLength': u'',
        'user.blockType': u'',
        'user.data': u'user',
        'userId': u'agent_user',
        'webApplicationId': u'web_app'},

    # 127
    definitions.METADATA_FIREAMP_CLOUD_NAME: {
        'blockLength': u'',
        'blockType': u'',
        'name.blockLength': u'',
        'name.blockType': u'',
        'name.data': u'name',
        'uuid': u'uuid'},

    # 128
    definitions.METADATA_FIREAMP_EVENT_TYPE: {
        'name': u'name',
        'id': u'id',
        'length': u''},

    # 129
    definitions.METADATA_FIREAMP_EVENT_SUBTYPE: {
        'name': u'name',
        'id': u'id',
        'length': u''},

    # 130
    definitions.METADATA_FIREAMP_DETECTOR_TYPE: {
        'name': u'name',
        'id': u'id',
        'length': u''},

    # 131
    definitions.METADATA_FIREAMP_FILE_TYPE: {
        'name': u'name',
        'id': u'id',
        'length': u''},

    # 132
    definitions.METADATA_SECURITY_CONTEXT_NAME: {},

    # 140
    definitions.RECORD_RULE_DOCUMENTATION_DATA: {},

    # 145
    definitions.METADATA_ACCESS_CONTROL_POLICY: {
        'blockLength': u'',
        'blockType': u'',
        'name.blockLength': u'',
        'name.blockType': u'',
        'name.data': u'name',
        'sensorId': u'',
        'uuid': u'uuid'},

    # 146
    definitions.METADATA_PREFILTER_POLICY: {
        'blockLength': u'',
        'blockType': u'',
        'name.blockLength': u'',
        'name.blockType': u'',
        'name.data': u'name',
        'sensorId': u'',
        'uuid': u'uuid'},

    # 147
    definitions.METADATA_TUNNEL_OR_PREFILTER_RULE: {
        'blockLength': u'',
        'blockType': u'',
        'name.blockLength': u'',
        'name.blockType': u'',
        'name.data': u'name',
        'sensorId': u'',
        'uuid': u'uuid'},

    # 160
    definitions.RECORD_RNA_IOC_SET: {
        'deviceId': u'device_id',
        'eventMicrosecond': u'event_usec',
        'eventSecond': u'event_sec',
        'eventSubtype': u'event_subtype',
        'eventType': u'event_type',
        'hasIpv6': u'has_ipv6',
        'id.blockLength': u'',
        'id.blockType': u'',
        'id.value': u'id',
        'macAddress': u'mac_address'},

    # 161
    definitions.METADATA_IOC_NAME: {
        'blockLength': u'',
        'blockType': u'',
        'category.blockLength': u'',
        'category.blockType': u'',
        'category.data': u'category',
        'eventType.blockLength': u'',
        'eventType.blockType': u'',
        'eventType.data': u'event_type',
        'id': u'num_ioc' },

    # 260
    definitions.METADATA_ICMP_TYPE: {
        'blockLength': u'',
        'blockType': u'',
        'description.blockLength': u'',
        'description.blockType': u'',
        'description.data': u'description',
        'protocol': u'ip_proto',
        'type': u'type'},

    # 270
    definitions.METADATA_ICMP_CODE: {
        'blockLength': u'',
        'blockType': u'',
        'code': u'code',
        'description.blockLength': u'',
        'description.blockType': u'',
        'description.data': u'description',
        'protocol': u'ip_proto',
        'type': u'type'},

    # 280
    definitions.METADATA_SECURITY_INTELLIGENCE_CATEGORY_DISCOVERY: {
        'accessControlPolicyUuid': u'policy_uuid',
        'blockLength': u'',
        'blockType': u'',
        'id': u'fw_rule',
        'name.blockLength': u'',
        'name.blockType': u'',
        'name.data': u'name'},

    # 281
    definitions.METADATA_SECURITY_INTELLIGENCE_SRCDEST: {
        'name': u'name',
        'id': u'id',
        'length': u''},

    # 282
    definitions.METADATA_SECURITY_INTELLIGENCE_CATEGORY_GENERAL: {},

    # 300
    definitions.METADATA_REALM: {},

    # 301
    definitions.RECORD_ENDPOINT_PROFILE_DATA: {},

    # 302
    definitions.METADATA_SECURITY_GROUP: {},

    # 320
    definitions.METADATA_DNS_RECORD: {
        'blockLength': u'',
        'blockType': u'',
        'description.blockLength': u'',
        'description.blockType': u'',
        'description.data': u'description',
        'id': u'id',
        'name.blockLength': u'',
        'name.blockType': u'',
        'name.data': u'name' },

    # 321
    definitions.METADATA_DNS_RESPONSE: {
        'blockLength': u'',
        'blockType': u'',
        'description.blockLength': u'',
        'description.blockType': u'',
        'description.data': u'description',
        'id': u'id',
        'name.blockLength': u'',
        'name.blockType': u'',
        'name.data': u'name' },

    # 322
    definitions.METADATA_SINKHOLE: {
        'blockType': u'',
        'blockLength': u'',
        'name.blockLength': u'',
        'name.blockType': u'',
        'name.data': u'name',
        'uuid': u'uuid'},

    # 350
    definitions.METADATA_NETMAP_DOMAIN: {},

    # 400
    definitions.RECORD_INTRUSION_EVENT: {
        'accessControlPolicyUuid': u'fw_policy',
        'accessControlRuleId': u'fw_rule',
        'applicationId': u'app_proto',
        'blockLength': u'',
        'blockType': u'',
        'blocked': u'blocked',
        'classificationId': u'', # -> read metadata
        'clientApplicationId': u'client_app',
        'connectionCounter': u'connection_id',
        'connectionInstanceId': u'instance_id',
        'connectionTimestamp': u'connection_sec',
        'destinationCountry': u'dest_ip_country',
        'destinationIpAddress': u'dest_ip',
        'destinationPortOrIcmpType': u'dest_port',
        'deviceId': u'device_id',
        'eventId': u'event_id',
        'eventMicrosecond': u'event_usec',
        'eventSecond': u'event_sec',
        'generatorId': u'gid',
        'httpResponse': u'http_response',
        'impact': u'', # -> Derived
        'impactFlags': u'impact_bits',
        'interfaceEgressUuid': u'iface_egress',
        'interfaceIngressUuid': u'iface_ingress',
        'iocNumber': u'num_ioc',
        'ipProtocolId': u'ip_proto',
        'mplsLabel': u'mpls_label',
        'networkAnalysisPolicyUuid': u'',
        'pad': u'',
        'policyUuid': u'ids_policy',
        'priorityId': u'priority',
        'ruleRevision': u'rev',
        'securityContext': u'security_context',
        'securityZoneEgressUuid': u'sec_zone_egress',
        'securityZoneIngressUuid': u'sec_zone_ingress',
        'sourceCountry': u'src_ip_country',
        'sourceIpAddress': u'src_ip',
        'sourcePortOrIcmpType': u'src_port',
        'sslActualAction': u'ssl_actual_action',
        'sslCertificateFingerprint': u'',
        'sslFlowStatus': u'ssl_flow_status',
        'userId': u'user',
        'vlanId': u'vlan_id',
        'webApplicationId': u'web_app'},

    # 500
    definitions.RECORD_FILELOG_EVENT: {
        'action': u'file_action',
        'applicationId': u'app_proto',
        'archiveDepth': u'archive_depth',
        'archiveFileStatus': u'archive_file_status',
        'archiveName.blockLength': u'',
        'archiveName.blockType': u'',
        'archiveName.data': u'archive_name',
        'archiveSha.blockLength': u'',
        'archiveSha.blockType': u'',
        'archiveSha.data': u'archive_sha',
        'blockLength': u'',
        'blockType': u'',
        'clientApplicationId': u'client_app',
        'connectionCounter': u'connection_id',
        'connectionInstance': u'instance_id',
        'connectionTimestamp': u'connection_sec',
        'destinationCountry': u'dest_ip_country',
        'destinationIpAddress': u'dest_ip',
        'destinationPort': u'dest_port',
        'deviceId': u'device_id',
        'direction': u'direction',
        'disposition': u'disposition',
        'fileAnalysisStatus': u'file_sandbox_status',
        'fileEventTimestamp': u'event_sec',
        'fileName.blockLength': u'',
        'fileName.blockType': u'',
        'fileName.data': u'file_name',
        'fileSize': u'file_size',
        'fileStorageStatus': u'file_storage_status',
        'fileTypeId': u'file_type',
        'httpResponse': u'http_response',
        'localMalwareAnalysisStatus': u'malware_analysis_status',
        'protocol': u'ip_proto',
        'securityContext': u'security_context',
        'shaHash': u'sha256',
        'signature.blockLength': u'',
        'signature.blockType': u'',
        'signature.data': u'signature',
        'sourceCountry': u'src_ip_country',
        'sourceIpAddress': u'src_ip',
        'sourcePort': u'src_port',
        'speroDisposition': u'spero_disposition',
        'sslActualAction': u'ssl_actual_action',
        'sslCertificateFingerprint': u'ssl_cert_fingerprint',
        'sslFlowStatus': u'ssl_flow_status',
        'threatScore': u'threat_score',
        'uri.blockLength': u'',
        'uri.blockType': u'',
        'uri.data': u'uri',
        'userId': u'user',
        'webApplicationId': u'web_app'},

    # 502 - is a copy of 500. See below
    # definitions.RECORD_FILELOG_MALWARE_EVENT

    # 510
    definitions.METADATA_FILELOG_FILE_TYPE: {
        'name': u'name',
        'id': u'id',
        'length': u''},

    # 511
    definitions.METADATA_FILELOG_SHA: {
        'blockLength': u'',
        'blockType': u'',
        'disposition': u'disposition',
        'fileName.blockLength': u'',
        'fileName.blockType': u'',
        'fileName.data': u'name',
        'shaHash': u'sha256',
        'userDefined': u'user_defined'},

    # 515
    definitions.METADATA_FILELOG_STORAGE: {
        'id': u'id',
        'name': u'name',
        'length': u''},

    # 516
    definitions.METADATA_FILELOG_SANDBOX: {
        'id': u'id',
        'name': u'name',
        'length': u''},

    # 517
    definitions.METADATA_FILELOG_SPERO: {
        'id': u'id',
        'name': u'name',
        'length': u''},

    # 518
    definitions.METADATA_FILELOG_ARCHIVE: {
        'id': u'status',
        'name': u'description',
        'length': u''},

    # 519
    definitions.METADATA_FILELOG_STATIC_ANALYSIS: {
        'id': u'status',
        'name': u'description',
        'length': u''},

    # 520
    definitions.METADATA_GEOLOCATION: {
        'blockLength': u'',
        'blockType': u'',
        'country.blockLength': u'',
        'country.blockType': u'',
        'country.data': u'name',
        'countryCode': u'id'},

    # 530
    definitions.METADATA_FILE_POLICY_NAME: {
        'blockLength': u'',
        'blockType': u'',
        'name.blockLength': u'',
        'name.blockType': u'',
        'name.data': u'name',
        'uuid': u'uuid'},

    # 600
    definitions.METADATA_SSL_POLICY: {},

    # 601
    definitions.METADATA_SSL_RULE_ID: {},

    # 602
    definitions.METADATA_SSL_CIPHER_SUITE: {
        'id': u'id',
        'name': u'name',
        'length': u''},

    # 604
    definitions.METADATA_SSL_VERSION: {
        'id': u'id',
        'name': u'name',
        'length': u''},

    # 605
    definitions.METADATA_SSL_SERVER_CERTIFICATE_STATUS: {
        'id': u'id',
        'name': u'description',
        'length': u''},

    # 606
    definitions.METADATA_SSL_ACTUAL_ACTION: {
        'name': u'description',
        'length': u'',
        'id': u'id'},

    # 607
    definitions.METADATA_SSL_EXPECTED_ACTION: {},

    # 608
    definitions.METADATA_SSL_FLOW_STATUS: {
        'name': u'description',
        'length': u'',
        'id': u'id'},

    # 613
    definitions.METADATA_SSL_URL_CATEGORY: {},

    # 614
    definitions.METADATA_SSL_CERTIFICATE_DETAILS_DATA: {},

    # 700
    definitions.METADATA_RECORD_NETWORK_ANALYSIS_POLICY: {
        'blockLength': u'',
        'blockType': u'',
        'name.blockLength': u'',
        'name.blockType': u'',
        'name.data': u'name',
        'uuid': u'uuid'}
}



# Copies

# 35 <= 15
FIELD_MAPPING[ definitions.RECORD_RNA_CHANGE_CLIENT_APP_TIMEOUT ] = \
    FIELD_MAPPING[ definitions.RECORD_RNA_NEW_CLIENT_APP ]

# 107 <= 15
FIELD_MAPPING[ definitions.RECORD_RNA_CHANGE_CLIENT_APP_UPDATE ] = \
    FIELD_MAPPING[ definitions.RECORD_RNA_NEW_CLIENT_APP ]

# 502 <= 500
FIELD_MAPPING[ definitions.RECORD_FILELOG_MALWARE_EVENT ] = \
    FIELD_MAPPING[ definitions.RECORD_FILELOG_EVENT ]

def __logger():
    return logging.getLogger(__name__)


def __selectWithNewKeys( record ):

    index = record['recordType']

    output = {}

    # Create settings
    parser = argparse.ArgumentParser(description='Runs eStreamer eNcore')
    parser.add_argument(
        'configFilepath',
        help = 'The filepath of the config file')

    parser.add_argument(
        '--pkcs12',
        action = "count",
        help = 'Reprocess pkcs12 file')

    args = parser.parse_args()

    settingsFilepath = args.configFilepath
    settings = estreamer.Settings.create( settingsFilepath )


    settingsFilepath = args.configFilepath

    # Map each of the fields
    if index in FIELD_MAPPING:
        recordMap = FIELD_MAPPING[index]
        for key in recordMap:
            newKey = recordMap[ key ]
            if newKey is not None and len(newKey) > 0:
                if key in record:
                    output[newKey] = record[key]
                    if index == 10 : 
                        __logger().info("Key:  "+key)
                        __logger().info("Value: "+str(record[key]))
                    #logger.info("Key")
                    #logger.info(key)

#                if self.record['recordType'] == 110 :
#                    self.logger.info("XFF data")
#                    for key in self.record:
#                        self.logger.info(key) # This will return me the key
 #                       for items in self.record.store[key]:
#                            self.logger.info("    %s" % items) # This will return me the subkey

 #                           for values in self.record.store[key][items]:
  #                              self.logger.info("        %s" % values) #this return the values for each subkey)
#                    self.logger.info(estreamer.common.display(self.record))



    # Copy the computed fields
    try:
        computedKey = View.OUTPUT_KEY
        source = record.store
        if computedKey in source:
            mappings = FIELD_MAPPING[ computedKey ]
            for key in source[ computedKey ]:
                newKey = mappings[ key ]
                if newKey is not None:
                    output[ newKey ] = source[ computedKey ][ key ]

    except KeyError as keyError:
        raise estreamer.EncoreException(
            'Unable to map {0} field: {1}'.format(
                View.OUTPUT_KEY,
                keyError.message))


    # Always copy recordType
    output['rec_type'] = record['recordType']

    return output



def __convert( source ):
    """
    convert transforms the incoming source messages to a splunk compatible
    dictionary. This must always return something even if it's just a dict
    containing a single 'rec_type' key
    """
    # Just in case things get this far but we don't know about the record
    if source['recordType'] not in definitions.RECORDS:
        return {
            'rec_type': source['recordType']
        }

    # Create a flat wrapper
    record = estreamer.common.Flatdict( source )

    # Transform
    output = __selectWithNewKeys( record )

    return output



def dumps( source ):
    """Converts a source record into a splunk output line"""
    data = __convert( source )

    line = '{0}={1} '.format('rec_type', data['rec_type'])
    del data['rec_type']

    # from datetime import datetime
    # secs = datetime.now() - datetime(1970, 1, 1)
    # data['event_sec'] = int( secs.total_seconds() )

    line += kvdumps(
        data,
        delimiter = ' ',
        quoteEmptyString = True,
        sort = False,
        escapeNewLines = True )

    return line
