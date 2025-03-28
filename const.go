package mrt

const (
	TABLE_DUMP_V2_SUBTYPE_PEER_INDEX_TABLE = iota + 1
	TABLE_DUMP_V2_SUBTYPE_RIB_IPv4_UNICAST
	TABLE_DUMP_V2_SUBTYPE_RIB_IPv4_MULTICAST
	TABLE_DUMP_V2_SUBTYPE_RIB_IPv6_UNICAST
	TABLE_DUMP_V2_SUBTYPE_RIB_IPv6_MULTICAST
	TABLE_DUMP_V2_SUBTYPE_RIB_GENERIC
	TABLE_DUMP_V2_SUBTYPE_GEO_PEER_TABLE
	TABLE_DUMP_V2_SUBTYPE_RIB_IPv4_UNICAST_ADDPATH
	TABLE_DUMP_V2_SUBTYPE_RIB_IPv4_MULTICAST_ADDPATH
	TABLE_DUMP_V2_SUBTYPE_RIB_IPv6_UNICAST_ADDPATH
	TABLE_DUMP_V2_SUBTYPE_RIB_IPv6_MULTICAST_ADDPATH
	TABLE_DUMP_V2_SUBTYPE_RIB_GENERIC_ADDPATH
)

type RecordType uint16

const (
	TYPE_OSPFv2        RecordType = 11
	TYPE_TABLE_DUMP               = 12
	TYPE_TABLE_DUMP_V2            = 13
	TYPE_BGP4MP                   = 16
	TYPE_BGP4MP_ET                = 17
	TYPE_ISIS                     = 32
	TYPE_ISIS_ET                  = 33
	TYPE_OSPFv3                   = 48
	TYPE_OSPFv3_ET                = 49
)

func (t RecordType) HasExtendedTimestamp() bool {
	return t == TYPE_BGP4MP_ET || t == TYPE_ISIS_ET || t == TYPE_OSPFv3_ET
}
