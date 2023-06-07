package mrt

import (
	"encoding/binary"
	"fmt"
	"io"
)

type Reader struct {
	reader io.Reader
}

func NewReader(r io.Reader) *Reader {
	return &Reader{
		reader: r,
	}
}

func (r *Reader) Next() (Record, error) {
	hdrBytes := make([]byte, 12)
	if _, err := io.ReadFull(r.reader, hdrBytes); err != nil {
		return nil, err
	}

	hdrType := RecordType(binary.BigEndian.Uint16(hdrBytes[4:]))
	hdrSubtype := binary.BigEndian.Uint16(hdrBytes[6:])
	hdrLength := binary.BigEndian.Uint32(hdrBytes[8:])

	var record Record
	switch hdrType {
	case TYPE_OSPFv2:
		record = new(OSPFv2)
	case TYPE_TABLE_DUMP:
		switch hdrSubtype {
		case TABLE_DUMP_SUBTYPE_AFI_IPv4, TABLE_DUMP_SUBTYPE_AFI_IPv6:
			record = new(TableDump)
		default:
			return nil, fmt.Errorf("unknown MRT record subtype: %d", hdrSubtype)
		}
	case TYPE_TABLE_DUMP_V2:
		switch hdrSubtype {
		case TABLE_DUMP_V2_SUBTYPE_PEER_INDEX_TABLE:
			record = new(TableDumpV2PeerIndexTable)
		case TABLE_DUMP_V2_SUBTYPE_RIB_IPv4_UNICAST,
			TABLE_DUMP_V2_SUBTYPE_RIB_IPv4_MULTICAST,
			TABLE_DUMP_V2_SUBTYPE_RIB_IPv6_UNICAST,
			TABLE_DUMP_V2_SUBTYPE_RIB_IPv6_MULTICAST,
			TABLE_DUMP_V2_SUBTYPE_RIB_IPv4_UNICAST_ADDPATH,
			TABLE_DUMP_V2_SUBTYPE_RIB_IPv4_MULTICAST_ADDPATH,
			TABLE_DUMP_V2_SUBTYPE_RIB_IPv6_UNICAST_ADDPATH,
			TABLE_DUMP_V2_SUBTYPE_RIB_IPv6_MULTICAST_ADDPATH:
			record = new(TableDumpV2RIB)
		case TABLE_DUMP_V2_SUBTYPE_RIB_GENERIC:
			record = new(TableDumpV2RIBGeneric)
		default:
			return nil, fmt.Errorf("unknown MRT record subtype: %d", hdrSubtype)
		}
	case TYPE_BGP4MP, TYPE_BGP4MP_ET:
		switch hdrSubtype {
		case BGP4MP_SUBTYPE_BGP4MP_STATE_CHANGE, BGP4MP_SUBTYPE_BGP4MP_STATE_CHANGE_AS4:
			record = new(BGP4MPStateChange)
		case BGP4MP_SUBTYPE_BGP4MP_MESSAGE,
			BGP4MP_SUBTYPE_BGP4MP_MESSAGE_AS4,
			BGP4MP_SUBTYPE_BGP4MP_MESSAGE_LOCAL,
			BGP4MP_SUBTYPE_BGP4MP_MESSAGE_AS4_LOCAL:
			record = new(BGP4MPMessage)
		default:
			return nil, fmt.Errorf("unknown MRT record subtype: %d", hdrSubtype)
		}
	case TYPE_ISIS, TYPE_ISIS_ET:
		record = new(ISIS)
	case TYPE_OSPFv3, TYPE_OSPFv3_ET:
		record = new(OSPFv3)
	default:
		return nil, fmt.Errorf("unknown MRT record type: %d", hdrType)
	}

	data := make([]byte, len(hdrBytes)+int(hdrLength))
	copy(data, hdrBytes)
	if _, err := io.ReadFull(r.reader, data[len(hdrBytes):]); err != nil {
		return nil, err
	}

	if err := record.DecodeBytes(data); err != nil {
		return nil, err
	}

	return record, nil
}
