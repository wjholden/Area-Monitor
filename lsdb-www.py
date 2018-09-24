#!/usr/bin/python3

from pysnmp.hlapi import *

username = "thebletch"
authpass = "AUTHPASS"
privpass = "PRIVPASS"
target = "192.168.1.1"

lsdb = []

# Perform an SNMP Walk over OSPF-MIB::ospfLsdbAdvertisement. Save the LSA's to the LSDB array.
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
            # print(' = '.join([x.prettyPrint() for x in varBind]))
            name, value = varBind
            lsdb.append(bytes.fromhex(value.prettyPrint()[2:]))

# Now we have a list of LSAs in our LSDB that we pulled from an OSPF router.
print(lsdb)
assert len(lsdb) > 0
