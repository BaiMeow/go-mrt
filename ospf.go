package mrt

import "net"

type OSPFv2 struct {
	header
	RemoteIPAddress     net.IP
	LocalIPAddress      net.IP
	OSPFMessageContents []byte
}

func (r *OSPFv2) DecodeBytes(data []byte) error {
	d := &decoder{data}
	r.decodeHeader(d)
	r.RemoteIPAddress = d.ipv4()
	r.LocalIPAddress = d.ipv4()
	r.OSPFMessageContents = d.bytes(d.size())
	return nil
}

type OSPFv3 struct {
	header
	AFI                 AFI
	RemoteIPAddress     net.IP
	LocalIPAddress      net.IP
	OSPFMessageContents []byte
}

func (r *OSPFv3) DecodeBytes(data []byte) error {
	d := &decoder{data}
	r.decodeHeader(d)
	r.AFI = AFI(d.uint16())
	r.LocalIPAddress = d.ipv4()
	r.RemoteIPAddress = d.ipv4()
	r.OSPFMessageContents = d.bytes(d.size())
	return nil
}
