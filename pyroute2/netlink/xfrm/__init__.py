'''
RTNetlink: network setup
========================

RTNL is a netlink protocol, used to get and set information
about different network objects -- addresses, routes, interfaces
etc.

RTNL protocol-specific data in messages depends on the object
type. E.g., complete packet with the interface address information::

    nlmsg header:
        + uint32 length
        + uint16 type
        + uint16 flags
        + uint32 sequence number
        + uint32 pid
    ifaddrmsg structure:
        + unsigned char ifa_family
        + unsigned char ifa_prefixlen
        + unsigned char ifa_flags
        + unsigned char ifa_scope
        + uint32 ifa_index
    [ optional NLA tree ]

NLA for this kind of packets can be of type IFA_ADDRESS, IFA_LOCAL
etc. -- please refer to the corresponding source.

Other objects types require different structures, sometimes really
complex. All these structures are described in sources.

---------------------------

Module contents:

'''
from pyroute2.common import map_namespace

#  XFRMnetlink multicast group flags (for use with bind())
XFRMGRP_NONE = 0x0
XFRMGRP_ACQUIRE = 0x1
XFRMGRP_EXPIRE = 0x2
XFRMGRP_SA = 0x4
XFRMGRP_POLICY = 0x8
XFRMGRP_NOP = 0x10
XFRMGRP_REPORT = 0x20

# multicast group ids (for use with {add,drop}_membership)
XFRMNLGRP_NONE = 0
XFRMNLGRP_ACQUIRE = 1
XFRMNLGRP_EXPIRE = 2
XFRMNLGRP_SA = 3
XFRMNLGRP_POLICY = 4
XFRMNLGRP_AEVENTS = 5
XFRMNLGRP_REPORT = 6
XFRMNLGRP_MIGRATE = 7
XFRMNLGRP_MAPPING = 8

# Types of messages
# XFRM_BASE = 16
XFRM_MSG_NEWSA = 16
XFRM_MSG_DELSA = 17
XFRM_MSG_GETSA = 18
XFRM_MSG_NEWPOLICY = 19
XFRM_MSG_DELPOLICY = 20
XFRM_MSG_GETPOLICY = 21
XFRM_MSG_ALLOCSPI = 22
XFRM_MSG_ACQUIRE = 23
XFRM_MSG_EXPIRE = 24
XFRM_MSG_UPDPOLICY = 25
XFRM_MSG_UPDSA = 26
XFRM_MSG_POLEXPIRE = 27
XFRM_MSG_FLUSHSA = 28
XFRM_MSG_FLUSHPOLICY = 29
XFRM_MSG_NEWAE = 30
XFRM_MSG_GETAE = 31
XFRM_MSG_REPORT = 32
XFRM_MSG_MIGRATE = 33
XFRM_MSG_NEWSADINFO = 34
XFRM_MSG_GETSADINFO = 35
XFRM_MSG_NEWSPDINFO = 36
XFRM_MSG_GETSPDINFO = 37
XFRM_MSG_MAPPING = 38
(XFRM_NAMES, XFRM_VALUES) = map_namespace('XFRM_', globals())

TC_H_INGRESS = 0xfffffff1
TC_H_CLSACT = TC_H_INGRESS
TC_H_ROOT = 0xffffffff


XFRMGRP_DEFAULTS = XFRMGRP_ACQUIRE |\
    XFRMGRP_EXPIRE |\
    XFRMGRP_SA |\
    XFRMGRP_POLICY |\
    XFRMGRP_REPORT

encap_type = {'unspec': 0,
              'mpls': 1,
              0: 'unspec',
              1: 'mpls'}

rtypes = {'RTN_UNSPEC': 0,
          'RTN_UNICAST': 1,      # Gateway or direct route
          'RTN_LOCAL': 2,        # Accept locally
          'RTN_BROADCAST': 3,    # Accept locally as broadcast
          #                        send as broadcast
          'RTN_ANYCAST': 4,      # Accept locally as broadcast,
          #                        but send as unicast
          'RTN_MULTICAST': 5,    # Multicast route
          'RTN_BLACKHOLE': 6,    # Drop
          'RTN_UNREACHABLE': 7,  # Destination is unreachable
          'RTN_PROHIBIT': 8,     # Administratively prohibited
          'RTN_THROW': 9,        # Not in this table
          'RTN_NAT': 10,         # Translate this address
          'RTN_XRESOLVE': 11}    # Use external resolver
# normalized
rt_type = dict([(x[0][4:].lower(), x[1]) for x in rtypes.items()] +
               [(x[1], x[0][4:].lower()) for x in rtypes.items()])

rtprotos = {'RTPROT_UNSPEC': 0,
            'RTPROT_REDIRECT': 1,  # Route installed by ICMP redirects;
            #                        not used by current IPv4
            'RTPROT_KERNEL': 2,    # Route installed by kernel
            'RTPROT_BOOT': 3,      # Route installed during boot
            'RTPROT_STATIC': 4,    # Route installed by administrator
            # Values of protocol >= RTPROT_STATIC are not
            # interpreted by kernel;
            # keep in sync with iproute2 !
            'RTPROT_GATED': 8,      # gated
            'RTPROT_RA': 9,         # RDISC/ND router advertisements
            'RTPROT_MRT': 10,       # Merit MRT
            'RTPROT_ZEBRA': 11,     # Zebra
            'RTPROT_BIRD': 12,      # BIRD
            'RTPROT_DNROUTED': 13,  # DECnet routing daemon
            'RTPROT_XORP': 14,      # XORP
            'RTPROT_NTK': 15,       # Netsukuku
            'RTPROT_DHCP': 16}      # DHCP client
# normalized
rt_proto = dict([(x[0][7:].lower(), x[1]) for x in rtprotos.items()] +
                [(x[1], x[0][7:].lower()) for x in rtprotos.items()])

rtscopes = {'RT_SCOPE_UNIVERSE': 0,
            'RT_SCOPE_SITE': 200,
            'RT_SCOPE_LINK': 253,
            'RT_SCOPE_HOST': 254,
            'RT_SCOPE_NOWHERE': 255}
# normalized
rt_scope = dict([(x[0][9:].lower(), x[1]) for x in rtscopes.items()] +
                [(x[1], x[0][9:].lower()) for x in rtscopes.items()])
