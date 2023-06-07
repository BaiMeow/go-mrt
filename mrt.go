package mrt

import (
	"bytes"
	"io"
	"net"
	"time"
)

type header struct {
	timestamp time.Time
	type_     RecordType
	subtype   uint16
}

func (h *header) Timestamp() time.Time {
	return h.timestamp
}

func (h *header) Type() RecordType {
	return h.type_
}

func (h *header) Subtype() uint16 {
	return h.subtype
}

func (h *header) decodeHeader(d *decoder) error {
	h.timestamp = d.unixTime()
	h.type_ = RecordType(d.uint16())
	h.subtype = d.uint16()
	d.skip(4) // Length (4 octets)
	if h.type_.HasExtendedTimestamp() {
		h.timestamp.Add(time.Duration(d.uint32()) * time.Microsecond)
	}
	return nil
}

const (
	TABLE_DUMP_SUBTYPE_AFI_IPv4 = 1
	TABLE_DUMP_SUBTYPE_AFI_IPv6 = 2
)

type TableDump struct {
	header
	ViewNumber     uint16
	SequenceNumber uint16
	Prefix         *net.IPNet
	OriginatedTime time.Time
	PeerIPAddress  net.IP
	PeerAS         AS
	BGPAttributes  []*BGPPathAttribute
}

func (r *TableDump) DecodeBytes(data []byte) error {
	d := &decoder{data}
	r.decodeHeader(d)
	r.ViewNumber = d.uint16()
	r.SequenceNumber = d.uint16()

	if r.subtype == TABLE_DUMP_SUBTYPE_AFI_IPv4 {
		ip := d.ipv4()
		mask := net.CIDRMask(int(d.uint8()), net.IPv4len*8)
		r.Prefix = &net.IPNet{IP: ip, Mask: mask}
	} else {
		ip := d.ipv6()
		mask := net.CIDRMask(int(d.uint8()), net.IPv6len*8)
		r.Prefix = &net.IPNet{IP: ip, Mask: mask}
	}

	d.skip(1) // Status (1 octet)
	r.OriginatedTime = d.unixTime()
	if r.subtype == TABLE_DUMP_SUBTYPE_AFI_IPv4 {
		r.PeerIPAddress = d.ipv4()
	} else {
		r.PeerIPAddress = d.ipv6()
	}
	r.PeerAS = d.as2()

	attrBytes := d.skip(d.size())
	reader := bgpPathAttributeReader{reader: bytes.NewReader(attrBytes), as4: false}
	for {
		attr, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		r.BGPAttributes = append(r.BGPAttributes, attr)
	}

	return nil
}

type TableDumpV2PeerIndexTable struct {
	header
	CollectorBGPID net.IP
	ViewName       string
	PeerEntries    []*TableDumpV2PeerEntry
}

func (r *TableDumpV2PeerIndexTable) DecodeBytes(data []byte) error {
	d := &decoder{data}
	r.decodeHeader(d)
	r.CollectorBGPID = d.ipv4()
	r.ViewName = d.string(int(d.uint16()))

	n := int(d.uint16())
	r.PeerEntries = make([]*TableDumpV2PeerEntry, n)
	for i := 0; i < n; i++ {
		entry := &TableDumpV2PeerEntry{}
		entry.PeerType = d.uint8()
		entry.PeerBGPID = d.ipv4()
		if entry.PeerType&0x1 == 0 {
			entry.PeerIPAddress = d.ipv4()
		} else {
			entry.PeerIPAddress = d.ipv6()
		}
		if entry.PeerType&0x2 == 0 {
			entry.PeerAS = d.as2()
		} else {
			entry.PeerAS = d.as4()
		}
		r.PeerEntries[i] = entry
	}

	return nil
}

type TableDumpV2PeerEntry struct {
	PeerType      uint8
	PeerBGPID     net.IP
	PeerIPAddress net.IP
	PeerAS        AS
}

type TableDumpV2RIB struct {
	header
	SequenceNumber uint32
	Prefix         *net.IPNet
	RIBEntries     []*TableDumpV2RIBEntry
}

func (r *TableDumpV2RIB) DecodeBytes(data []byte) error {
	d := &decoder{data}
	r.decodeHeader(d)
	r.SequenceNumber = d.uint32()

	if r.subtype == TABLE_DUMP_V2_SUBTYPE_RIB_IPv4_UNICAST ||
		r.subtype == TABLE_DUMP_V2_SUBTYPE_RIB_IPv4_MULTICAST ||
		r.subtype == TABLE_DUMP_V2_SUBTYPE_RIB_IPv4_UNICAST_ADDPATH ||
		r.subtype == TABLE_DUMP_V2_SUBTYPE_RIB_IPv4_MULTICAST_ADDPATH {
		r.Prefix = d.nlriIPv4()
	} else {
		r.Prefix = d.nlriIPv6()
	}

	n := int(d.uint16())
	r.RIBEntries = make([]*TableDumpV2RIBEntry, n)
	for i := 0; i < n; i++ {
		entry := &TableDumpV2RIBEntry{}
		entry.PeerIndex = d.uint16()
		entry.OriginatedTime = d.unixTime()

		if r.subtype >= TABLE_DUMP_V2_SUBTYPE_RIB_IPv4_UNICAST_ADDPATH && r.subtype <= TABLE_DUMP_V2_SUBTYPE_RIB_GENERIC_ADDPATH {
			entry.PathIdentifier = d.uint32()
		}

		attrBytes := d.skip(int(d.uint16()))
		reader := bgpPathAttributeReader{reader: bytes.NewReader(attrBytes), as4: true}
		for {
			attr, err := reader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			entry.BGPAttributes = append(entry.BGPAttributes, attr)
		}

		r.RIBEntries[i] = entry
	}

	return nil
}

type AFI uint16

const (
	AFIIPv4 AFI = 1
	AFIIPv6     = 2
)

type SAFI uint8

const (
	SAFIUnicast   SAFI = 1
	SAFIMulticast      = 2
)

type TableDumpV2RIBGeneric struct {
	header
	SequenceNumber uint32
	AFI            AFI
	SAFI           SAFI
	NLRI           []byte
	RIBEntries     []*TableDumpV2RIBEntry
}

func (r *TableDumpV2RIBGeneric) DecodeBytes(data []byte) error {
	d := &decoder{data}
	r.decodeHeader(d)
	r.SequenceNumber = d.uint32()
	r.AFI = AFI(d.uint16())
	r.SAFI = SAFI(d.uint8())
	// r.NLRI
	// r.RIBEntries
	return nil
}

type TableDumpV2RIBEntry struct {
	PeerIndex      uint16
	OriginatedTime time.Time
	PathIdentifier uint32
	BGPAttributes  []*BGPPathAttribute
}

const (
	BGP4MP_SUBTYPE_BGP4MP_STATE_CHANGE      = 0
	BGP4MP_SUBTYPE_BGP4MP_MESSAGE           = 1
	BGP4MP_SUBTYPE_BGP4MP_MESSAGE_AS4       = 4
	BGP4MP_SUBTYPE_BGP4MP_STATE_CHANGE_AS4  = 5
	BGP4MP_SUBTYPE_BGP4MP_MESSAGE_LOCAL     = 6
	BGP4MP_SUBTYPE_BGP4MP_MESSAGE_AS4_LOCAL = 7
)

type BGP4MPStateChange struct {
	header
	PeerAS         AS
	LocalAS        AS
	InterfaceIndex uint16
	AFI            AFI
	PeerIPAddress  net.IP
	LocalIPAddress net.IP
	OldState       uint16
	NewState       uint16
}

func (r *BGP4MPStateChange) DecodeBytes(data []byte) error {
	d := &decoder{data}
	r.decodeHeader(d)

	if r.subtype == BGP4MP_SUBTYPE_BGP4MP_STATE_CHANGE {
		r.PeerAS = d.as2()
		r.LocalAS = d.as2()
	} else {
		r.PeerAS = d.as4()
		r.LocalAS = d.as4()
	}

	r.InterfaceIndex = d.uint16()
	r.AFI = AFI(d.uint16())

	if r.AFI == AFIIPv4 {
		r.PeerIPAddress = d.ipv4()
		r.LocalIPAddress = d.ipv4()
	} else {
		r.PeerIPAddress = d.ipv6()
		r.LocalIPAddress = d.ipv6()
	}

	r.OldState = d.uint16()
	r.NewState = d.uint16()

	return nil
}

type BGP4MPMessage struct {
	header
	PeerAS         AS
	LocalAS        AS
	InterfaceIndex uint16
	AFI            AFI
	PeerIPAddress  net.IP
	LocalIPAddress net.IP
	BGPMessage     *BGPMessage
}

func (r *BGP4MPMessage) DecodeBytes(data []byte) error {
	d := &decoder{data}
	r.decodeHeader(d)

	as4 := r.subtype == BGP4MP_SUBTYPE_BGP4MP_MESSAGE_AS4 ||
		r.subtype == BGP4MP_SUBTYPE_BGP4MP_MESSAGE_AS4_LOCAL
	if as4 {
		r.PeerAS = d.as4()
		r.LocalAS = d.as4()
	} else {
		r.PeerAS = d.as2()
		r.LocalAS = d.as2()
	}

	r.InterfaceIndex = d.uint16()
	r.AFI = AFI(d.uint16())

	if r.AFI == AFIIPv4 {
		r.PeerIPAddress = d.ipv4()
		r.LocalIPAddress = d.ipv4()
	} else {
		r.PeerIPAddress = d.ipv6()
		r.LocalIPAddress = d.ipv6()
	}

	var err error
	r.BGPMessage, err = decodeBGPMessage(d.skip(d.size()), as4, r.AFI)

	return err
}

type Record interface {
	Timestamp() time.Time
	Type() RecordType
	Subtype() uint16
	DecodeBytes([]byte) error
}
