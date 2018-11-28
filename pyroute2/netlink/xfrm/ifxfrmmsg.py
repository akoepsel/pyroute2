import socket
import ctypes
from pyroute2.common import map_namespace
from pyroute2.netlink import nlmsg
from pyroute2.netlink import nla


# security context domains of interpretation
XFRM_SC_DOI_RESERVED = 0
XFRM_SC_DOI_LSM = 1

# security context algorithms
XFRM_SC_ALG_RESERVED = 0
XFRM_SC_ALG_SELINUX = 1

(XFRM_SC_NAMES, XFRM_SC_VALUES) = map_namespace('XFRM_SC', globals())

# state attributes
#
XFRM_STATE_NOECN = 0x1
XFRM_STATE_DECAP_DSCP = 0x2
XFRM_STATE_NOPMTUDISC  = 0x4
XFRM_STATE_WILDRECV = 0x8
XFRM_STATE_ICMP = 0x10
XFRM_STATE_AF_UNSPEC = 0x20
XFRM_STATE_ALIGN4 = 0x40
XFRM_STATE_ESN = 0x80

(XFRM_STATE_NAMES, XFRM_STATE_VALUES) = map_namespace('XFRM_STATE', globals())

XFRM_POLICY_TYPE_MAIN = 0,
XFRM_POLICY_TYPE_SUB = 1,
XFRM_POLICY_TYPE_MAX = 2,
XFRM_POLICY_TYPE_ANY = 255

(XFRM_POLICY_TYPE_NAMES, XFRM_POLICY_TYPE_VALUES) = map_namespace('XFRM_POLICY_TYPE', globals())

XFRM_POLICY_IN  = 0,
XFRM_POLICY_OUT = 1,
XFRM_POLICY_FWD = 2,
XFRM_POLICY_MASK = 3,
XFRM_POLICY_MAX = 3

(XFRM_POLICY_NAMES, XFRM_POLICY_VALUES) = map_namespace('XFRM_POLICY', globals()) # FIXME: do not mix up with XFRM_POLICY_TYPE

XFRM_SHARE_ANY = 0
XFRM_SHARE_SESSION = 1
XFRM_SHARE_USER = 2
XFRM_SHARE_UNIQUE = 3

(XFRM_SHARE_NAMES, XFRM_SHARE_VALUES) = map_namespace('XFRM_SHARE', globals())

XFRM_MODE_TRANSPORT = 0
XFRM_MODE_TUNNEL = 1
XFRM_MODE_ROUTEOPTIMIZATION = 2
XFRM_MODE_IN_TRIGGER = 3
XFRM_MODE_BEET = 4
XFRM_MODE_MAX = 5

(XFRM_MODE_NAMES, XFRM_MODE_VALUES) = map_namespace('XFRM_MODE', globals())

XFRM_AE_UNSPEC = 0x0
XFRM_AE_RTHR = 0x1
XFRM_AE_RVAL = 0x2
XFRM_AE_LVAL = 0x4
XFRM_AE_ETHR = 0x8
XFRM_AE_CR = 0x10
XFRM_AE_CE = 0x20
XFRM_AE_CU = 0x40
XFRM_AE_MAX = 0x41

(XFRM_AE_NAMES, XFRM_AE_VALUES) = map_namespace('XFRM_AE', globals())



class ifxfrmmsg(nlmsg):
    '''
    XFRM information

    C structure::
     
        there is no fixed header in these xfrm messages, but a flat list of NLAs

    '''
    prefix = 'XFRMA_'

    fields = ()

    nla_map = (('XFRMA_UNSPEC', 'hex'),
               ('XFRMA_ALG_AUTH', 'algo'),
               ('XFRMA_ALG_CRYPT', 'algo'),
               ('XFRMA_ALG_COMP', 'algo'),
               ('XFRMA_ENCAP', 'encap_tmpl'),
               ('XFRMA_TMPL', 'user_tmpl'),
               ('XFRMA_SA', 'usersa_info'),
               ('XFRMA_POLICY', 'userpolicy_info'),
               ('XFRMA_SEC_CTX', 'sec_ctx'),
               ('XFRMA_LTIME_VAL', 'lifetime_cur'),
               ('XFRMA_REPLAY_VAL', 'replay_state'),
               ('XFRMA_REPLAY_THRESH', 'uint32'),
               ('XFRMA_ETIMER_THRESH', 'uint32'),
               ('XFRMA_SRCADDR', 'address_t'),
               ('XFRMA_COADDR', 'address_t'),
               ('XFRMA_LASTUSED', 'uint64'),
               ('XFRMA_POLICY_TYPE', 'userpolicy_type'),
               ('XFRMA_MIGRATE', 'user_migrate'),
               ('XFRMA_ALG_AEAD', 'algo_aead'),
               ('XFRMA_KMADDRESS', 'user_kmaddress'),
               ('XFRMA_ALG_AUTH_TRUNC', 'algo_auth'),
               ('XFRMA_MARK', 'mark'),
               ('XFRMA_TFCPAD', 'uint32'),
               ('XFRMA_REPLAY_ESN_VAL', 'replay_state_esn'),
               ('XFRMA_SA_EXTRA_FLAGS', 'uint32'),
               ('XFRMA_PROTO', 'uint8'),
               ('XFRMA_ADDRESS_FILTER', 'address_filter'),
               ('XFRMA_PAD', 'uint8'), # TODO: ???
               ('XFRMA_OFFLOAD_DEV', 'user_offload'),
               ('XFRMA_SET_MARK', 'uint32'),
               ('XFRMA_SET_MARK_MASK', 'uint32'),
               ('XFRMA_IF_ID', 'uint32'),
               ('XFRMA_SAD_UNSPEC', 'hex'),
               ('XFRMA_SAD_CNT', 'uint32'),
               ('XFRMA_SAD_HINFO', 'sadhinfo'),
               ('XFRMA_SPD_UNSPEC', 'hex'),
               ('XFRMA_SPD_INFO', 'spdinfo'),
               ('XFRMA_SPD_HINFO', 'spdhinfo'),
               ('XFRMA_SPD_IPV4_HTHRESH', 'spdhthresh'),
               ('XFRMA_SPD_IPV6_HTHRESH', 'spdhthresh'))


    class xfrm_address_t(ctypes.Union):
        '''This class wraps a C-union named struct xfrm_address_t.
           It provides method encode() returning a 16 elements wide
           tuple, a method decode() capable of unpacking a list, tuple 
           or integer value and a clear method for setting all bytes to 0.
           This structure is frequently used by xfrm, so we introduce 
           a dedicated class for it here.

           typedef union {
                   __be32          a4;
                   __be32          a6[4];
                   struct in6_addr in6;
           } xfrm_address_t;
        '''
        _fields_ = [("a4", c_uint32), ("a6", c_uint32 * 4), ("bytes", c_ubyte * 16)]

        def __init__(self, value=None):
            self.decode(value)

        def __str__(self):
            return '0x{}'.format("".join(['{:02x}'.format(i) for i in x.bytes]))

        def clear(self):
            for i in range(len(self.bytes)):
                self.bytes[i] = ctypes.c_ubyte(0)

        def encode(self):
            return [int(self.bytes[i]) for i in range(len(self.bytes))]

        def decode(self, value):
            self.clear()
            if value is None:
                return
            elif isinstance(value, (list, tuple)) and len(value) == 16:
                for i in range(len(value)):
                    self.bytes[i] = ctypes.c_ubyte(value[i])
            elif isinstance(value, (list, tuple)) and len(value) == 4:
                for i in range(len(value)):
                    self.a6[i] = ctypes.c_uint32(value[i])
            elif isinstance(value, int):
                self.a4 = ctypes.c_uint32(value)
            else:
                raise TypeError('unable to parse value of type {}'.format(type(value)))


    class id(nla):
        '''
        Not used by any NLA attributes

        struct xfrm_id {
                xfrm_address_t  daddr;
                __be32          spi;
                __u8            proto;
        };
        '''
        fields = (('daddr', '16s'),
                  ('spi', '>I'),
                  ('proto', 'B'))


    class selector(nla):
        '''
        Not used by any NLA attributes

        struct xfrm_selector {
                xfrm_address_t  daddr;
                xfrm_address_t  saddr;
                __be16  dport;
                __be16  dport_mask;
                __be16  sport;
                __be16  sport_mask;
                __u16   family;
                __u8    prefixlen_d;
                __u8    prefixlen_s;
                __u8    proto;
                int     ifindex;
                __kernel_uid32_t        user;
        };
        '''
        fields = (('daddr', '16s'),
                  ('saddr', '16s'),
                  ('dport', '>H'),
                  ('dport_mask', '>H'),
                  ('sport', '>H'),
                  ('sport_mask', '>H'),
                  ('family', 'H'),
                  ('prefixlen_d', 'B'),
                  ('prefixlen_s', 'B'),
                  ('proto', 'B'),
                  ('ifindex', 'i'),
                  ('user', 'I'))
     

    class lifetime_cfg(nla):
        '''
        Not used by any NLA attributes

        struct xfrm_lifetime_cfg {
                __u64   soft_byte_limit;
                __u64   hard_byte_limit;
                __u64   soft_packet_limit;
                __u64   hard_packet_limit;
                __u64   soft_add_expires_seconds;
                __u64   hard_add_expires_seconds;
                __u64   soft_use_expires_seconds;
                __u64   hard_use_expires_seconds;
        };
        '''
        fields = (('soft_byte_limit', 'Q'),
                  ('hard_byte_limit', 'Q'),
                  ('soft_packet_limit', 'Q'),
                  ('hard_packet_limit', 'Q'),
                  ('soft_add_expires_seconds', 'Q'),
                  ('hard_add_expires_seconds', 'Q'),
                  ('soft_use_expires_seconds', 'Q'),
                  ('hard_use_expires_seconds', 'Q'))


    class address_t(nla):
        '''
        Used by NLA attributes:
        - XFRMA_SRCADDR
        - XFRMA_COADDR

        typedef union {
                __be32          a4;
                __be32          a6[4];
                struct in6_addr in6;
        } xfrm_address_t;
        '''
        pack = 'struct'
        fields = (('addr', '16s'))


    class sec_ctx(nla):
        '''
        Used by NLA attributes:
        - XFRMA_SEC_CTX

        struct xfrm_sec_ctx {
                __u8    ctx_doi;
                __u8    ctx_alg;
                __u16   ctx_len;
                __u32   ctx_sid;
                char    ctx_str[0];
        };
        '''
        __slots__ = ()

        pack = 'struct'
        fields = [('value', 's')] # use ft_decode_string for decoding to catch the entire attribute

        def __init__(self):
            self.ctx_doi = None
            self.ctx_alg = None
            self.ctx_len = None
            self.ctx_sid = None
            self.ctx_str = ''

        def encode(self):
            fmt = '64BI%s' % (64 + 4 + len(self.alg_key))
            self.value = struct.pack(fmt, '{:<64}'.format(self.alg_name), self.alg_key_len, self.alg_key)
            nla_base.encode(self)

        def decode(self):
            nla_base.decode(self)
            fmt = '2BHI%s' % (len(self.value) - (1+1+2+4))
            (ctx_doi, ctx_alg, ctx_len, ctx_sid, ctx_str) = struct.unpack(fmt, self.value, offset=0)
            setattr(self, 'ctx_doi', ctx_doi)
            setattr(self, 'ctx_alg', ctx_alg)
            setattr(self, 'ctx_len', ctx_len)
            setattr(self, 'ctx_sid', ctx_sid)
            setattr(self, 'ctx_str', ctx_str)


    class lifetime_cur(nla):
        '''
        Used by NLA attributes:
        - XFRMA_LTIME_VAL

        struct xfrm_lifetime_cur {
                __u64   bytes;
                __u64   packets;
                __u64   add_time;
                __u64   use_time;
        };
        '''
        pack = 'struct'
        fields = (('bytes', 'Q'),
                  ('packets', 'Q'),
                  ('add_time', 'Q'),
                  ('use_time', 'Q'))


    class replay_state(nla):
        '''
        Used by NLA attributes:
        - XFRMA_REPLAY_VAL

        struct xfrm_replay_state {
                __u32   oseq;
                __u32   seq;
                __u32   bitmap;
        };
        '''
        pack = 'struct'
        fields = (('oseq', 'I'),
                  ('seq', 'I'),
                  ('bitmap', 'I'))


    class replay_state_esn(nla):
        '''
        This class is used to decode structs of type xfrm_replay_state_esn
        using a flexible key length. We cannot specify the key length, 
        as it is derived from the NLA attribute header at runtime.

        Used by NLA attributes:
        - XFRMA_REPLAY_ESN_VAL

        struct xfrm_replay_state_esn {
                unsigned int    bmp_len;
                __u32           oseq;
                __u32           seq;
                __u32           oseq_hi;
                __u32           seq_hi;
                __u32           replay_window;
                __u32           bmp[0];
        };
        '''
        __slots__ = ()

        pack = 'struct'
        fields = [('value', 's')] # use ft_decode_string for decoding to catch the entire attribute

        def __init__(self):
            self.bmp_len = 0
            self.oseq = 0
            self.seq = 0
            self.oseq_hi = 0
            self.seq_hi = 0
            self.replay_window = 0
            self.bmp = bytearray()

        def encode(self):
            fmt = '6I%s' % (6*4 + len(self.bmp))
            self.value = struct.pack(fmt, 
                    self.bmp_len,
                    self.oseq,
                    self.seq,
                    self.oseq_hi,
                    self.seq_hi,
                    self.replay_window,
                    self.bmp)
            nla_base.encode(self)

        def decode(self):
            nla_base.decode(self)
            fmt = '6I%s' % (len(self.value) - 6*4)
            (bmp_len, oseq, seq, oseq_hi, seq_hi, replay_window, bmp) = struct.unpack(fmt, self.value, offset=0)
            setattr(self, 'bmp_len', bmp_len)
            setattr(self, 'oseq', oseq)
            setattr(self, 'seq', seq)
            setattr(self, 'oseq_hi', oseq_hi)
            setattr(self, 'seq_hi', seq_hi)
            setattr(self, 'replay_window', replay_window)
            setattr(self, 'bmp', bmp)


    class algo(nla_base):
        '''
        This class is used to decode structs of type xfrm_algo
        using a flexible key length. We cannot specify the key length, 
        as it is derived from the NLA attribute header at runtime.

        Used by NLA attributes:
        - XFRMA_ALG_AUTH
        - XFRMA_ALG_CRYPT
        - XFRMA_ALG_COMP

        struct xfrm_algo {
                char            alg_name[64];
                unsigned int    alg_key_len;    /* in bits */
                char            alg_key[0];
        };
        '''
        __slots__ = ()

        pack = 'struct'
        fields = [('value', 's')] # use ft_decode_string for decoding to catch the entire attribute

        def __init__(self):
            self.alg_name = None
            eelf.alg_key_len = 0
            self.alg_key = bytearray()

        def encode(self):
            fmt = '64BI%s' % (64 + 4 + len(self.alg_key))
            self.value = struct.pack(fmt, '{:<64}'.format(self.alg_name), self.alg_key_len, self.alg_key)
            nla_base.encode(self)

        def decode(self):
            nla_base.decode(self)
            fmt = '64BI%s' % (len(self.value) - 64 - 4)
            (alg_name, alg_key_len, alg_key) = struct.unpack(fmt, self.value, offset=0)
            setattr(self, 'alg_name', alg_name)
            setattr(self, 'alg_key_len', alg_key_len)
            setattr(self, 'alg_key', alg_key)


    class algo_auth(nla):
        '''
        This class is used to decode structs of type xfrm_algo_auth
        using a flexible key length. We cannot specify the key length, 
        as it is derived from the NLA attribute header at runtime.

        Used by NLA attributes:
        - XFRMA_ALG_AUTH_TRUNC

        struct xfrm_algo_auth {
                char            alg_name[64];
                unsigned int    alg_key_len;    /* in bits */
                unsigned int    alg_trunc_len;  /* in bits */
                char            alg_key[0];
        };
        '''
        __slots__ = ()

        pack = 'struct'
        fields = [('value', 's')] # use ft_decode_string for decoding to catch the entire attribute

        def __init__(self):
            self.alg_name = None
            self.alg_key_len = 0
            self.alg_trunc_len = 0
            self.alg_key = bytearray()

        def encode(self):
            fmt = '64B2I%s' % (64 + 4 + 4 + len(self.alg_key))
            self.value = struct.pack(fmt, '{:<64}'.format(self.alg_name), self.alg_key_len, self.alg_trunc_len, self.alg_key)
            nla_base.encode(self)

        def decode(self):
            nla_base.decode(self)
            fmt = '64B2I%s' % (len(self.value) - 64 - 4 - 4)
            (alg_name, alg_key_len, alg_trunc_len, alg_key) = struct.unpack(fmt, self.value, offset=0)
            setattr(self, 'alg_name', alg_name)
            setattr(self, 'alg_key_len', alg_key_len)
            setattr(self, 'alg_trunc_len', alg_trunc_len)
            setattr(self, 'alg_key', alg_key)


    class algo_aead(nla):
        '''
        This class is used to decode structs of type xfrm_algo_aead
        using a flexible key length. We cannot specify the key length, 
        as it is derived from the NLA attribute header at runtime.

        Used by NLA attributes:
        - XFRMA_ALG_AEAD

        struct xfrm_algo_aead {
                char            alg_name[64];
                unsigned int    alg_key_len;    /* in bits */
                unsigned int    alg_icv_len;    /* in bits */
                char            alg_key[0];
        };
        '''
        __slots__ = ()

        pack = 'struct'
        fields = [('value', 's')] # use ft_decode_string for decoding to catch the entire attribute

        def __init__(self):
            self.alg_name = None
            self.alg_key_len = 0
            self.alg_icv_len = 0
            self.alg_key = bytearray()

        def encode(self):
            fmt = '64B2I%s' % (64 + 4 + 4 + len(self.alg_key))
            self.value = struct.pack(fmt, '{:<64}'.format(self.alg_name), self.alg_key_len, self.alg_icv_len, self.alg_key)
            nla_base.encode(self)

        def decode(self):
            nla_base.decode(self)
            fmt = '64B2I%s' % (len(self.value) - 64 - 4 - 4)
            (alg_name, alg_key_len, alg_icv_len, alg_key) = struct.unpack(fmt, self.value, offset=0)
            setattr(self, 'alg_name', alg_name)
            setattr(self, 'alg_key_len', alg_key_len)
            setattr(self, 'alg_icv_len', alg_icv_len)
            setattr(self, 'alg_key', alg_key)


    class stats(nla):
        '''
        Not used by any NLA attributes

        struct xfrm_stats {
                __u32   replay_window;
                __u32   replay;
                __u32   integrity_failed;
        };
        '''
        fields = (('replay_window', 'I'),
                  ('replay', 'I'),
                  ('integrity_failed', 'I'))


    class mark(nla):
        '''
        Used by NLA attributes:
        - XFRMA_MARK

        struct xfrm_mark {
                __u32           v; /* value */
                __u32           m; /* mask */
        };
        '''
        fields = (('v', 'I'),
                  ('m', 'I'))


    class sadhinfo(nla):
        '''
        Used by NLA attributes:
        - XFRMA_SAD_HINFO

        struct xfrmu_sadhinfo {
                __u32   sadhcnt;
                __u32   sadhmcnt;
        };
        '''
        pack = 'struct'
        fields = (('sadhcnt', 'I'),
                  ('sadhmcnt', 'I'))


    class spdinfo(nla):
        '''
        Used by NLA attributes:
        - XFRMA_SPD_INFO

        struct xfrmu_spdinfo {
                __u32 incnt;
                __u32 outcnt;
                __u32 fwdcnt;
                __u32 inscnt;
                __u32 outscnt;
                __u32 fwdscnt;
        };
        '''
        pack = 'struct'
        fields = (('incnt', 'I'),
                  ('outcnt', 'I'),
                  ('fwdcnt', 'I'),
                  ('inscnt', 'I'),
                  ('outscnt', 'I'),
                  ('fwdscnt', 'I'))


    class spdhinfo(nla):
        '''
        Used by NLA attributes:
        - XFRMA_SPD_HINFO

        struct xfrmu_spdhinfo {
                __u32 spdhcnt;
                __u32 dpdhmcnt;
        };
        '''
        pack = 'struct'
        fields = (('spdhcnt', 'I'),
                  ('spdhmcnt', 'I'))


    class spdhthresh(nla):
        '''
        Used by NLA attributes:
        - XFRMA_SPD_IPV4_HTHRESH
        - XFRMA_SPD_IPV6_HTHRESH

        struct xfrmu_spdhthresh {
                __u8 lbits;
                __u8 rbits;
        };
        '''
        pack = 'struct'
        fields = (('lbits', 'B'),
                  ('rbits', 'B'))


    class address_filter(nla):
        '''
        Used by NLA attributes:
        - XFRMA_ADDRESS_FILTER

        struct xfrm_address_filter {
                xfrm_address_t                  saddr;
                xfrm_address_t                  daddr;
                __u16                           family;
                __u8                            splen;
                __u8                            dplen;
        };
        '''
        fields = (('saddr', '16s'),
                  ('daddr', '16s'),
                  ('family', 'H'),
                  ('splen', 'B'),
                  ('dplen', 'B'))


    class user_offload(nla):
        '''
        Used by NLA attributes:
        - XFRMA_OFFLOAD_DEV

        struct xfrm_user_offload {
                int                             ifindex;
                __u8                            flags;
        };
        '''
        fields = (('ifindex', 'i'),
                  ('flags', 'B'))


    class user_kmaddress(nla):
        '''
        Used by NLA attributes:
        - XFRMA_KMADDRESS

        struct xfrm_user_kmaddress {
                xfrm_address_t                  local;
                xfrm_address_t                  remote;
                __u32                           reserved;
                __u16                           family;
        };
        '''
        fields = (('local', '16s'),
                  ('remote', '16s'),
                  ('reserved', 'I'),
                  ('family', 'H'))


    class user_migrate(nla):
        '''
        Used by NLA attributes:
        - XFRMA_MIGRATE

        struct xfrm_user_migrate {
                xfrm_address_t                  old_daddr;
                xfrm_address_t                  old_saddr;
                xfrm_address_t                  new_daddr;
                xfrm_address_t                  new_saddr;
                __u8                            proto;
                __u8                            mode;
                __u16                           reserved;
                __u32                           reqid;
                __u16                           old_family;
                __u16                           new_family;
        };
        '''
        fields = (('old_daddr', '16s'),
                  ('old_saddr', '16s'),
                  ('new_daddr', '16s'),
                  ('new_saddr', '16s'),
                  ('proto', 'B'),
                  ('mode', 'B'),
                  ('reserved', 'H'),
                  ('reqid', 'I'),
                  ('old_family', 'H'),
                  ('new_family', 'H'))


    class userpolicy_type(nla):
        '''
        Used by NLA attributes:
        - XFRMA_POLICY_TYPE

        struct xfrm_userpolicy_type {
                __u8            type;
                __u16           reserved1;
                __u8            reserved2;
        };
        '''
        fields = (('type', 'B'),
                  ('reserved1', 'H'),
                  ('reserved2', 'H'))


    class user_tmpl(nla):
        '''
        Used by NLA attributes:
        - XFRMA_TMPL

        struct xfrm_user_tmpl {
                struct xfrm_id          id;
                __u16                   family;
                xfrm_address_t          saddr;
                __u32                   reqid;
                __u8                    mode;
                __u8                    share;
                __u8                    optional;
                __u32                   aalgos;
                __u32                   ealgos;
                __u32                   calgos;
        };
        '''
        fields = (# xfrm_user_tmpl
                  # .xfrm_id
                  ('daddr', '16s'),
                  ('spi', '>I'),
                  ('proto', 'B'),
                  # xfrm_user_tmpl
                  ('family', 'H'),
                  ('saddr', '16s'),
                  ('reqid', 'I'),
                  ('mode', 'B'),
                  ('share', 'B'),
                  ('optional', 'B'),
                  ('aalgos', 'I'),
                  ('ealgos', 'I'),
                  ('calgos', 'I'))


    class encap_tmpl(nla):
        '''
        Used by NLA attributes:
        - XFRMA_ENCAP

        struct xfrm_encap_tmpl {
                __u16           encap_type;
                __be16          encap_sport;
                __be16          encap_dport;
                xfrm_address_t  encap_oa;
        };
        '''
        fields = (# xfrm_encap_tmpl
                  ('encap_type', 'H'),
                  ('encap_sport', '>H'),
                  ('encap_dport', '>H'),
                  ('encap_oa', '16s'))


    class usersa_info(nla):
        '''
        struct xfrm_usersa_info {
                struct xfrm_selector            sel;
                struct xfrm_id                  id;
                xfrm_address_t                  saddr;
                struct xfrm_lifetime_cfg        lft;
                struct xfrm_lifetime_cur        curlft;
                struct xfrm_stats               stats;
                __u32                           seq;
                __u32                           reqid;
                __u16                           family;
                __u8                            mode;           /* XFRM_MODE_xxx */
                __u8                            replay_window;
                __u8                            flags;
        };
        '''
        fields = (# xfrm_usersa_info
                  # .xfrm_selector
                  ('daddr', '16s'),
                  ('saddr', '16s'),
                  ('dport', '>H'),
                  ('dport_mask', '>H'),
                  ('sport', '>H'),
                  ('sport_mask', '>H'),
                  ('family', 'H'),
                  ('prefixlen_d', 'B'),
                  ('prefixlen_s', 'B'),
                  ('proto', 'B'),
                  ('ifindex', 'i'),
                  ('user', 'I'),
                  # .xfrm_id
                  ('daddr', '16s'),
                  ('spi', '>I'),
                  ('proto', 'B'),
                  # .xfrm_address_t
                  ('saddr', '16s'),
                  # .xfrm_lifetime_cfg
                  ('soft_byte_limit', 'Q'),
                  ('hard_byte_limit', 'Q'),
                  ('soft_packet_limit', 'Q'),
                  ('hard_packet_limit', 'Q'),
                  ('soft_add_expires_seconds', 'Q'),
                  ('hard_add_expires_seconds', 'Q'),
                  ('soft_use_expires_seconds', 'Q'),
                  ('hard_use_expires_seconds', 'Q'),
                  # .xfrm_lifetime_cur
                  ('bytes', 'Q'),
                  ('packets', 'Q'),
                  ('add_time', 'Q'),
                  ('use_time', 'Q'),
                  # .xfrm_stats
                  ('replay_window', 'I'),
                  ('replay', 'I'),
                  ('integrity_failed', 'I'),
                  # xfrm_usersa_info
                  ('seq', 'I'),
                  ('reqid', 'I'),
                  ('family', 'H'),
                  ('mode', 'B'),
                  ('replay_window', 'B'),
                  ('flags', 'B'))


     class userpolicy_info(nla):
        '''
        struct xfrm_userpolicy_info {
                struct xfrm_selector            sel;
                struct xfrm_lifetime_cfg        lft;
                struct xfrm_lifetime_cur        curlft;
                __u32                           priority;
                __u32                           index;
                __u8                            dir;
                __u8                            action;
        #define XFRM_POLICY_ALLOW       0
        #define XFRM_POLICY_BLOCK       1
                __u8                            flags;
        #define XFRM_POLICY_LOCALOK     1       /* Allow user to override global policy */
                /* Automatically expand selector to include matching ICMP payloads. */
        #define XFRM_POLICY_ICMP        2
                __u8                            share;
        };
        '''
        fields = (# xfrm_userpolicy_info
                  # .xfrm_selector
                  ('daddr', '16s'),
                  ('saddr', '16s'),
                  ('dport', '>H'),
                  ('dport_mask', '>H'),
                  ('sport', '>H'),
                  ('sport_mask', '>H'),
                  ('family', 'H'),
                  ('prefixlen_d', 'B'),
                  ('prefixlen_s', 'B'),
                  ('proto', 'B'),
                  ('ifindex', 'i'),
                  ('user', 'I'),
                  # .xfrm_lifetime_cfg
                  ('soft_byte_limit', 'Q'),
                  ('hard_byte_limit', 'Q'),
                  ('soft_packet_limit', 'Q'),
                  ('hard_packet_limit', 'Q'),
                  ('soft_add_expires_seconds', 'Q'),
                  ('hard_add_expires_seconds', 'Q'),
                  ('soft_use_expires_seconds', 'Q'),
                  ('hard_use_expires_seconds', 'Q'),
                  # .xfrm_lifetime_cur
                  ('bytes', 'Q'),
                  ('packets', 'Q'),
                  ('add_time', 'Q'),
                  ('use_time', 'Q'),
                  # xfrm_userpolicy_info
                  ('priority', 'I'),
                  ('index', 'I'),
                  ('dir', 'B'),
                  ('action', 'B'),
                  ('flags', 'B'),
                  ('share', 'B'))



class ifxfrmmsg_newsa(ifxfrmmsg):
    '''
    XFRM_MSG_NEWSA

    C structure:: struct xfrm_usersa_info {}
     
    '''
    fields = (# xfrm_usersa_info
              # .xfrm_selector
              ('daddr', '16s'),
              ('saddr', '16s'),
              ('dport', '>H'),
              ('dport_mask', '>H'),
              ('sport', '>H'),
              ('sport_mask', '>H'),
              ('family', 'H'),
              ('prefixlen_d', 'B'),
              ('prefixlen_s', 'B'),
              ('proto', 'B'),
              ('ifindex', 'i'),
              ('user', 'I'),
              # .xfrm_id
              ('daddr', '16s'),
              ('spi', '>I'),
              ('proto', 'B'),
              # .xfrm_address_t
              ('saddr', '16s'),
              # .xfrm_lifetime_cfg
              ('soft_byte_limit', 'Q'),
              ('hard_byte_limit', 'Q'),
              ('soft_packet_limit', 'Q'),
              ('hard_packet_limit', 'Q'),
              ('soft_add_expires_seconds', 'Q'),
              ('hard_add_expires_seconds', 'Q'),
              ('soft_use_expires_seconds', 'Q'),
              ('hard_use_expires_seconds', 'Q'),
              # .xfrm_lifetime_cur
              ('bytes', 'Q'),
              ('packets', 'Q'),
              ('add_time', 'Q'),
              ('use_time', 'Q'),
              # .xfrm_stats
              ('replay_window', 'I'),
              ('replay', 'I'),
              ('integrity_failed', 'I'),
              # xfrm_usersa_info
              ('seq', 'I'),
              ('reqid', 'I'),
              ('family', 'H'),
              ('mode', 'B'),
              ('replay_window', 'B'),
              ('flags', 'B'))



class ifxfrmmsg_delsa(ifxfrmmsg):
    '''
    XFRM_MSG_DELSA

    C structure:: struct xfrm_usersa_id {}
     
    '''
    fields = (('daddr', '16s'),
              ('spi', '>I'),
              ('family', 'H'),
              ('proto', 'B'))


class ifxfrmmsg_getsa(ifxfrmmsg):
    '''
    XFRM_MSG_GETSA

    C structure:: struct xfrm_usersa_id {}
     
    '''
    fields = (('daddr', '16s'),
              ('spi', '>I'),
              ('family', 'H'),
              ('proto', 'B'))


class ifxfrmmsg_newpolicy(ifxfrmmsg):
    '''
    XFRM_MSG_NEWPOLICY

    C structure:: struct xfrm_userpolicy_info {}
     
    '''
    fields = (# xfrm_userpolicy_info
              # .xfrm_selector
              ('daddr', '16s'),
              ('saddr', '16s'),
              ('dport', '>H'),
              ('dport_mask', '>H'),
              ('sport', '>H'),
              ('sport_mask', '>H'),
              ('family', 'H'),
              ('prefixlen_d', 'B'),
              ('prefixlen_s', 'B'),
              ('proto', 'B'),
              ('ifindex', 'i'),
              ('user', 'I'),
              # .xfrm_lifetime_cfg
              ('soft_byte_limit', 'Q'),
              ('hard_byte_limit', 'Q'),
              ('soft_packet_limit', 'Q'),
              ('hard_packet_limit', 'Q'),
              ('soft_add_expires_seconds', 'Q'),
              ('hard_add_expires_seconds', 'Q'),
              ('soft_use_expires_seconds', 'Q'),
              ('hard_use_expires_seconds', 'Q'),
              # .xfrm_lifetime_cur
              ('bytes', 'Q'),
              ('packets', 'Q'),
              ('add_time', 'Q'),
              ('use_time', 'Q'),
              # xfrm_userpolicy_info
              ('priority', 'I'),
              ('index', 'I'),
              ('dir', 'B'),
              ('action', 'B'),
              ('flags', 'B'),
              ('share', 'B'))


class ifxfrmmsg_delpolicy(ifxfrmmsg):
    '''
    XFRM_MSG_DELPOLICY

    C structure:: struct xfrm_userpolicy_id {}
     
    '''
    fields = (# xfrm_userpolicy_id
              # .xfrm_selector
              ('daddr', '16s'),
              ('saddr', '16s'),
              ('dport', '>H'),
              ('dport_mask', '>H'),
              ('sport', '>H'),
              ('sport_mask', '>H'),
              ('family', 'H'),
              ('prefixlen_d', 'B'),
              ('prefixlen_s', 'B'),
              ('proto', 'B'),
              ('ifindex', 'i'),
              ('user', 'I'),
              # xfrm_userpolicy_id
              ('index', 'uint32'),
              ('dir', 'uint8't))
 

class ifxfrmmsg_getpolicy(ifxfrmmsg):
    '''
    XFRM_MSG_GETPOLICY

    C structure:: struct xfrm_userpolicy_id {}
     
    '''
    fields = (# xfrm_userpolicy_id
              # .xfrm_selector
              ('daddr', '16s'),
              ('saddr', '16s'),
              ('dport', '>H'),
              ('dport_mask', '>H'),
              ('sport', '>H'),
              ('sport_mask', '>H'),
              ('family', 'H'),
              ('prefixlen_d', 'B'),
              ('prefixlen_s', 'B'),
              ('proto', 'B'),
              ('ifindex', 'i'),
              ('user', 'I'),
              # xfrm_userpolicy_id
              ('index', 'I'),
              ('dir', 'B'))
 

class ifxfrmmsg_allocspi(ifxfrmmsg):
    '''
    XFRM_MSG_ALLOCSPI

    C structure:: struct xfrm_userspi_info {}
     
    '''
    fields = (# xfrm_userspi_info
              # .xfrm_usersa_info
              # ..xfrm_selector
              ('daddr', '16s'),
              ('saddr', '16s'),
              ('dport', '>H'),
              ('dport_mask', '>H'),
              ('sport', '>H'),
              ('sport_mask', '>H'),
              ('family', 'H'),
              ('prefixlen_d', 'B'),
              ('prefixlen_s', 'B'),
              ('proto', 'B'),
              ('ifindex', 'i'),
              ('user', 'I'),
              # ..xfrm_id
              ('daddr', '16s'),
              ('spi', '>I'),
              ('proto', 'B'),
              # ..xfrm_address_t
              ('saddr', '16s'),
              # ..xfrm_lifetime_cfg
              ('soft_byte_limit', 'Q'),
              ('hard_byte_limit', 'Q'),
              ('soft_packet_limit', 'Q'),
              ('hard_packet_limit', 'Q'),
              ('soft_add_expires_seconds', 'Q'),
              ('hard_add_expires_seconds', 'Q'),
              ('soft_use_expires_seconds', 'Q'),
              ('hard_use_expires_seconds', 'Q'),
              # ..xfrm_lifetime_cur
              ('bytes', 'Q'),
              ('packets', 'Q'),
              ('add_time', 'Q'),
              ('use_time', 'Q'),
              # ..xfrm_stats
              ('replay_window', 'I'),
              ('replay', 'I'),
              ('integrity_failed', 'I'),
              # .xfrm_usersa_info
              ('seq', 'I'),
              ('reqid', 'I'),
              ('family', 'H'),
              ('mode', 'B'),
              ('replay_window', 'B'),
              ('flags', 'B'))
              # xfrm_userspi_info
              ('min', 'I'),
              ('max', 'I'))


class ifxfrmmsg_acquire(ifxfrmmsg):
    '''
    XFRM_MSG_ACQUIRE

    C structure:: struct xfrm_user_acquire {}
     
    '''
    fields = (# xfrm_user_acquire
              # .xfrm_id
              ('daddr', '16s'),
              ('spi', '>I'),
              ('proto', 'B'),
              # .xfrm_address_t
              ('saddr', '16s'),
              # .xfrm_selector
              ('daddr', '16s'),
              ('saddr', '16s'),
              ('dport', '>H'),
              ('dport_mask', '>H'),
              ('sport', '>H'),
              ('sport_mask', '>H'),
              ('family', 'H'),
              ('prefixlen_d', 'B'),
              ('prefixlen_s', 'B'),
              ('proto', 'B'),
              ('ifindex', 'i'),
              ('user', 'I'),
              # .xfrm_userpolicy_info
              # ..xfrm_selector
              ('daddr', '16s'),
              ('saddr', '16s'),
              ('dport', '>H'),
              ('dport_mask', '>H'),
              ('sport', '>H'),
              ('sport_mask', '>H'),
              ('family', 'H'),
              ('prefixlen_d', 'B'),
              ('prefixlen_s', 'B'),
              ('proto', 'B'),
              ('ifindex', 'i'),
              ('user', 'I'),
              # ..xfrm_lifetime_cfg
              ('soft_byte_limit', 'Q'),
              ('hard_byte_limit', 'Q'),
              ('soft_packet_limit', 'Q'),
              ('hard_packet_limit', 'Q'),
              ('soft_add_expires_seconds', 'Q'),
              ('hard_add_expires_seconds', 'Q'),
              ('soft_use_expires_seconds', 'Q'),
              ('hard_use_expires_seconds', 'Q'),
              # ..xfrm_lifetime_cur
              ('bytes', 'Q'),
              ('packets', 'Q'),
              ('add_time', 'Q'),
              ('use_time', 'Q'),
              # .xfrm_userpolicy_info
              ('priority', 'I'),
              ('index', 'I'),
              ('dir', 'B'),
              ('action', 'B'),
              ('flags', 'B'),
              ('share', 'B'))
              # xfrm_user_acquire
              ('aalgos', 'I'),
              ('ealgos', 'I'),
              ('calgos', 'I'),
              ('seq', 'I'))


 class ifxfrmmsg_expire(ifxfrmmsg):
    '''
    XFRM_MSG_EXPIRE

    C structure:: struct xfrm_user_expire {}
     
    '''
    fields = (# xfrm_user_expire
              # .xfrm_usersa_info
              # ..xfrm_selector
              ('daddr', '16s'),
              ('saddr', '16s'),
              ('dport', '>H'),
              ('dport_mask', '>H'),
              ('sport', '>H'),
              ('sport_mask', '>H'),
              ('family', 'H'),
              ('prefixlen_d', 'B'),
              ('prefixlen_s', 'B'),
              ('proto', 'B'),
              ('ifindex', 'i'),
              ('user', 'I'),
              # ..xfrm_id
              ('daddr', '16s'),
              ('spi', '>I'),
              ('proto', 'B'),
              # ..xfrm_address_t
              ('saddr', '16s'),
              # ..xfrm_lifetime_cfg
              ('soft_byte_limit', 'Q'),
              ('hard_byte_limit', 'Q'),
              ('soft_packet_limit', 'Q'),
              ('hard_packet_limit', 'Q'),
              ('soft_add_expires_seconds', 'Q'),
              ('hard_add_expires_seconds', 'Q'),
              ('soft_use_expires_seconds', 'Q'),
              ('hard_use_expires_seconds', 'Q'),
              # ..xfrm_lifetime_cur
              ('bytes', 'Q'),
              ('packets', 'Q'),
              ('add_time', 'Q'),
              ('use_time', 'Q'),
              # ..xfrm_stats
              ('replay_window', 'I'),
              ('replay', 'I'),
              ('integrity_failed', 'I'),
              # .xfrm_usersa_info
              ('seq', 'I'),
              ('reqid', 'I'),
              ('family', 'H'),
              ('mode', 'B'),
              ('replay_window', 'B'),
              ('flags', 'B'))
              # xfrm_user_expire
              ('hard', 'B'))


class ifxfrmmsg_updpolicy(ifxfrmmsg):
    '''
    XFRM_MSG_UPDPOLICY

    C structure:: struct xfrm_userpolicy_info {}
     
    '''
    fields = (# xfrm_userpolicy_info
              # .xfrm_selector
              ('daddr', '16s'),
              ('saddr', '16s'),
              ('dport', '>H'),
              ('dport_mask', '>H'),
              ('sport', '>H'),
              ('sport_mask', '>H'),
              ('family', 'H'),
              ('prefixlen_d', 'B'),
              ('prefixlen_s', 'B'),
              ('proto', 'B'),
              ('ifindex', 'i'),
              ('user', 'I'),
              # .xfrm_lifetime_cfg
              ('soft_byte_limit', 'Q'),
              ('hard_byte_limit', 'Q'),
              ('soft_packet_limit', 'Q'),
              ('hard_packet_limit', 'Q'),
              ('soft_add_expires_seconds', 'Q'),
              ('hard_add_expires_seconds', 'Q'),
              ('soft_use_expires_seconds', 'Q'),
              ('hard_use_expires_seconds', 'Q'),
              # .xfrm_lifetime_cur
              ('bytes', 'Q'),
              ('packets', 'Q'),
              ('add_time', 'Q'),
              ('use_time', 'Q'),
              # xfrm_userpolicy_info
              ('priority', 'I'),
              ('index', 'I'),
              ('dir', 'B'),
              ('action', 'B'),
              ('flags', 'B'),
              ('share', 'B'))


class ifxfrmmsg_updsa(ifxfrmmsg):
    '''
    XFRM_MSG_UPDSA

    C structure:: struct xfrm_usersa_info {}
     
    '''
    fields = (# xfrm_usersa_info
              # .xfrm_selector
              ('daddr', '16s'),
              ('saddr', '16s'),
              ('dport', '>H'),
              ('dport_mask', '>H'),
              ('sport', '>H'),
              ('sport_mask', '>H'),
              ('family', 'H'),
              ('prefixlen_d', 'B'),
              ('prefixlen_s', 'B'),
              ('proto', 'B'),
              ('ifindex', 'i'),
              ('user', 'I'),
              # .xfrm_id
              ('daddr', '16s'),
              ('spi', '>I'),
              ('proto', 'B'),
              # .xfrm_address_t
              ('saddr', '16s'),
              # .xfrm_lifetime_cfg
              ('soft_byte_limit', 'Q'),
              ('hard_byte_limit', 'Q'),
              ('soft_packet_limit', 'Q'),
              ('hard_packet_limit', 'Q'),
              ('soft_add_expires_seconds', 'Q'),
              ('hard_add_expires_seconds', 'Q'),
              ('soft_use_expires_seconds', 'Q'),
              ('hard_use_expires_seconds', 'Q'),
              # .xfrm_lifetime_cur
              ('bytes', 'Q'),
              ('packets', 'Q'),
              ('add_time', 'Q'),
              ('use_time', 'Q'),
              # .xfrm_stats
              ('replay_window', 'I'),
              ('replay', 'I'),
              ('integrity_failed', 'I'),
              # xfrm_usersa_info
              ('seq', 'I'),
              ('reqid', 'I'),
              ('family', 'H'),
              ('mode', 'B'),
              ('replay_window', 'B'),
              ('flags', 'B'))


class ifxfrmmsg_polexpire(ifxfrmmsg):
    '''
    XFRM_MSG_POLEXPIRE

    C structure:: struct xfrm_user_polexpire {}
     
    '''
    fields = (# xfrm_user_polexpire
              # .xfrm_userpolicy_info
              # ..xfrm_selector
              ('daddr', '16s'),
              ('saddr', '16s'),
              ('dport', '>H'),
              ('dport_mask', '>H'),
              ('sport', '>H'),
              ('sport_mask', '>H'),
              ('family', 'H'),
              ('prefixlen_d', 'B'),
              ('prefixlen_s', 'B'),
              ('proto', 'B'),
              ('ifindex', 'i'),
              ('user', 'I'),
              # ..xfrm_lifetime_cfg
              ('soft_byte_limit', 'Q'),
              ('hard_byte_limit', 'Q'),
              ('soft_packet_limit', 'Q'),
              ('hard_packet_limit', 'Q'),
              ('soft_add_expires_seconds', 'Q'),
              ('hard_add_expires_seconds', 'Q'),
              ('soft_use_expires_seconds', 'Q'),
              ('hard_use_expires_seconds', 'Q'),
              # ..xfrm_lifetime_cur
              ('bytes', 'Q'),
              ('packets', 'Q'),
              ('add_time', 'Q'),
              ('use_time', 'Q'),
              # .xfrm_userpolicy_info
              ('priority', 'I'),
              ('index', 'I'),
              ('dir', 'B'),
              ('action', 'B'),
              ('flags', 'B'),
              ('share', 'B'))
              # xfrm_user_polexpire
              ('hard', 'B'))


class ifxfrmmsg_flushsa(ifxfrmmsg):
    '''
    XFRM_MSG_FLUSHSA

    C structure:: struct xfrm_usersa_flush {}
     
    '''
    fields = (('proto', 'B'))


class ifxfrmmsg_flushpolicy(ifxfrmmsg):
    '''
    XFRM_MSG_FLUSHPOLICY

    C structure:: none
     
    '''
    fields = ()


class ifxfrmmsg_newae(ifxfrmmsg):
    '''
    XFRM_MSG_NEWAE

    C structure:: struct xfrm_aevent_id {}
     
    '''
    fields = (# xfrm_aevent_id
              # .xfrm_usersa_info
              # ..xfrm_selector
              ('daddr', '16s'),
              ('saddr', '16s'),
              ('dport', '>H'),
              ('dport_mask', '>H'),
              ('sport', '>H'),
              ('sport_mask', '>H'),
              ('family', 'H'),
              ('prefixlen_d', 'B'),
              ('prefixlen_s', 'B'),
              ('proto', 'B'),
              ('ifindex', 'i'),
              ('user', 'I'),
              # ..xfrm_id
              ('daddr', '16s'),
              ('spi', '>I'),
              ('proto', 'B'),
              # ..xfrm_address_t
              ('saddr', '16s'),
              # ..xfrm_lifetime_cfg
              ('soft_byte_limit', 'Q'),
              ('hard_byte_limit', 'Q'),
              ('soft_packet_limit', 'Q'),
              ('hard_packet_limit', 'Q'),
              ('soft_add_expires_seconds', 'Q'),
              ('hard_add_expires_seconds', 'Q'),
              ('soft_use_expires_seconds', 'Q'),
              ('hard_use_expires_seconds', 'Q'),
              # ..xfrm_lifetime_cur
              ('bytes', 'Q'),
              ('packets', 'Q'),
              ('add_time', 'Q'),
              ('use_time', 'Q'),
              # ..xfrm_stats
              ('replay_window', 'I'),
              ('replay', 'I'),
              ('integrity_failed', 'I'),
              # .xfrm_usersa_info
              ('seq', 'I'),
              ('reqid', 'I'),
              ('family', 'H'),
              ('mode', 'B'),
              ('replay_window', 'B'),
              ('flags', 'B'),
              # .xfrm_address_t
              ('saddr', '16s'),
              # xfrm_aevent_id
              ('flags', 'I'),
              ('reqid', 'I'))


class ifxfrmmsg_getae(ifxfrmmsg):
    '''
    XFRM_MSG_GETAE

    C structure:: struct xfrm_aevent_id {}
     
    '''
    fields = (# xfrm_aevent_id
              # .xfrm_usersa_info
              # ..xfrm_selector
              ('daddr', '16s'),
              ('saddr', '16s'),
              ('dport', '>H'),
              ('dport_mask', '>H'),
              ('sport', '>H'),
              ('sport_mask', '>H'),
              ('family', 'H'),
              ('prefixlen_d', 'B'),
              ('prefixlen_s', 'B'),
              ('proto', 'B'),
              ('ifindex', 'i'),
              ('user', 'I'),
              # ..xfrm_id
              ('daddr', '16s'),
              ('spi', '>I'),
              ('proto', 'B'),
              # ..xfrm_address_t
              ('saddr', '16s'),
              # ..xfrm_lifetime_cfg
              ('soft_byte_limit', 'Q'),
              ('hard_byte_limit', 'Q'),
              ('soft_packet_limit', 'Q'),
              ('hard_packet_limit', 'Q'),
              ('soft_add_expires_seconds', 'Q'),
              ('hard_add_expires_seconds', 'Q'),
              ('soft_use_expires_seconds', 'Q'),
              ('hard_use_expires_seconds', 'Q'),
              # ..xfrm_lifetime_cur
              ('bytes', 'Q'),
              ('packets', 'Q'),
              ('add_time', 'Q'),
              ('use_time', 'Q'),
              # ..xfrm_stats
              ('replay_window', 'I'),
              ('replay', 'I'),
              ('integrity_failed', 'I'),
              # .xfrm_usersa_info
              ('seq', 'I'),
              ('reqid', 'I'),
              ('family', 'H'),
              ('mode', 'B'),
              ('replay_window', 'B'),
              ('flags', 'B'),
              # .xfrm_address_t
              ('saddr', '16s'),
              # xfrm_aevent_id
              ('flags', 'I'),
              ('reqid', 'I'))


class ifxfrmmsg_report(ifxfrmmsg):
    '''
    XFRM_MSG_REPORT

    C structure:: struct xfrm_user_report {}
     
    '''
    fields = (# xfrm_user_report
              ('proto', 'B'),
              # .xfrm_selector
              ('daddr', '16s'),
              ('saddr', '16s'),
              ('dport', '>H'),
              ('dport_mask', '>H'),
              ('sport', '>H'),
              ('sport_mask', '>H'),
              ('family', 'H'),
              ('prefixlen_d', 'B'),
              ('prefixlen_s', 'B'),
              ('proto', 'B'),
              ('ifindex', 'i'),
              ('user', 'I'))
 

class ifxfrmmsg_migrate(ifxfrmmsg):
    '''
    XFRM_MSG_MIGRATE

    C structure:: struct xfrm_userpolicy_id {}

    '''
    fields = (# xfrm_userpolicy_id
              # .xfrm_selector
              ('daddr', '16s'),
              ('saddr', '16s'),
              ('dport', '>H'),
              ('dport_mask', '>H'),
              ('sport', '>H'),
              ('sport_mask', '>H'),
              ('family', 'H'),
              ('prefixlen_d', 'B'),
              ('prefixlen_s', 'B'),
              ('proto', 'B'),
              ('ifindex', 'i'),
              ('user', 'I'),
              # xfrm_userpolicy_id
              ('index', 'uint32'),
              ('dir', 'uint8't))


class ifxfrmmsg_getsadinfo(ifxfrmmsg):
    '''
    XFRM_MSG_GETSADINFO

    C structure:: none

    '''
    fields = (('flags', 'I'))


class ifxfrmmsg_setspdinfo(ifxfrmmsg):
    '''
    XFRM_MSG_SETSPDINFO

    C structure:: none

    '''
    fields = (('flags', 'I'))


class ifxfrmmsg_getspdinfo(ifxfrmmsg):
    '''
    XFRM_MSG_GETSPDINFO

    C structure:: none

    '''
    fields = (('flags', 'I'))

