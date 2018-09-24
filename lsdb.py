#!/usr/bin/python3

from pysnmp.hlapi import *
import struct
import ipaddress

# This is functionally equivalent to
# snmpwalk -v3 -l auth -u USERNAME -a SHA -A AUTHPASS -x AES -X PRIVPASS TARGET OSPF-MIB::ospfLsdbAdvertisement -m +SNMP-MIB

username = "thebletch"
authpass = "AUTHPASS"
privpass = "PRIVPASS"
target = "192.168.1.1"

lsdb = []

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
# Iterate through each LSA, constructing a DOT file as we go.
assert len(lsdb) > 0

g = "digraph G {\n"

for lsa in lsdb:
    position = 0
    header = struct.unpack_from("!HBBIIIHH", lsa, position)
    link_state_id = ipaddress.IPv4Address(header[3])
    position += 20

    if header[2] == 1:
        # router LSA
        # https://tools.ietf.org/html/rfc2328#page-206
        g += "\"Router {0}\";\n".format(link_state_id)
        router_lsa = struct.unpack_from("!HH", lsa, position)
        position += 4
        num_links = router_lsa[1]
        assert num_links > 0
        for i in range(num_links):
            assert position < len(lsa)
            link = struct.unpack_from("!IIBBH", lsa, position)
            position += 12
            link_id = ipaddress.IPv4Address(link[0])
            link_data = ipaddress.IPv4Address(link[1])
            link_type = link[2]
            tos = link[3]
            metric = link[4]

            if link_type == 1 or link_type == 4: # point-to-point or virtual link
                g += "//\"Router {0}\" -> \"Router {1}\" [label=\"{2}\"];\n".format(
                    link_state_id, link_id, metric)
                g += "// skip point-to-point; if numbered, same edge is a transit network. #provemewrong\n"
            elif link_type == 2: # transit network
                g += "\"Router {0}\" -> \"DR {1}\" [label=\"{2}\"];\n".format(
                    link_state_id, link_id, metric)
            elif link_type == 3: # stub network
                g += "\"Router {0}\" -> \"{1}/{2}\" [label=\"{3}\"];\n".format(
                    link_state_id, link_id, link_data, metric)
            else:
                assert False # this should never happen
        
    elif header[2] == 2:
        # network LSA
        # https://tools.ietf.org/html/rfc2328#page-210
        num_attached = (len(lsa) - 24) // 4
        assert(num_attached > 0)
        netmask = ipaddress.IPv4Address(
            struct.unpack_from("!I", lsa, position)[0])
        position += 4
        g += "\"DR {0}\" [label=\"{1}\" shape=rect];\n".format(
            link_state_id, ipaddress.ip_network(str(link_state_id) + "/" +
                                                 str(netmask), False))
        for i in range(num_attached):
            attached_router = ipaddress.IPv4Address(
                struct.unpack_from("!I", lsa, position)[0])
            position += 4
            g += "\"DR {0}\" -> \"Router {1}\";\n".format(
                link_state_id, attached_router)

g += "}"
print(g)
