#!/usr/bin/python3

from pysnmp.hlapi import *

# This is functionally equivalent to
# snmpwalk -v3 -l auth -u USERNAME -a SHA -A AUTHPASS -x AES -X PRIVPASS TARGET OSPF-MIB::ospfLsdbAdvertisement -m +SNMP-MIB

username = input("Username: ")
authpass = input("Auth pass (SHA-1): ")
privpass = input("Priv pass (AES256): ")
target = input("Target: ")

for (errorIndication,
     errorStatus,
     errorIndex,
     varBinds) in nextCmd(SnmpEngine(),
                          UsmUserData(username, authpass, privpass,
                                      authProtocol=usmHMACSHAAuthProtocol,
                                      privProtocol=usmAesCfb256Protocol),
                          UdpTransportTarget((target, 161)),
                          ContextData(),
                          ObjectType(ObjectIdentity('.1.3.6.1.2.1.14.4.1.8')),
                          lexicographicMode=False):

    if errorIndication:
        print(errorIndication)
        break
    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        break
    else:
        for varBind in varBinds:
            print(' = '.join([x.prettyPrint() for x in varBind]))
