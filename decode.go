package mrt

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"time"
)

type AS []byte

func (as AS) String() string {
	if len(as) == 2 {
		return strconv.FormatUint(uint64(binary.BigEndian.Uint16(as)), 10)
	} else if len(as) == 4 {
		return strconv.FormatUint(uint64(binary.BigEndian.Uint32(as)), 10)
	} else {
		return string(as)
	}
}

func (as AS) MarshalText() ([]byte, error) {
	if len(as) == 0 {
		return []byte(""), nil
	}
	if len(as) != 2 && len(as) != 4 {
		return nil, errors.New("invalid AS number")
	}
	return []byte(as.String()), nil
}

type decoder struct {
	buf []byte
}

func (d *decoder) uint8() uint8 {
	x := d.buf[0]
	d.buf = d.buf[1:]
	return x
}

func (d *decoder) uint16() uint16 {
	x := binary.BigEndian.Uint16(d.buf)
	d.buf = d.buf[2:]
	return x
}

func (d *decoder) uint32() uint32 {
	x := binary.BigEndian.Uint32(d.buf)
	d.buf = d.buf[4:]
	return x
}

func (d *decoder) uint64() uint64 {
	x := binary.BigEndian.Uint64(d.buf)
	d.buf = d.buf[8:]
	return x
}

func (d *decoder) string(n int) string {
	x := string(d.buf[:n])
	d.buf = d.buf[n:]
	return x
}

func (d *decoder) bytes(n int) []byte {
	x := make([]byte, n)
	d.copy(x)
	return x
}

func (d *decoder) ipv4() net.IP {
	x := make(net.IP, net.IPv4len)
	d.copy(x)
	return x
}

func (d *decoder) ipv4N(n int) net.IP {
	x := make(net.IP, net.IPv4len)
	d.copyN(x, n)
	return x
}

func (d *decoder) ipv6() net.IP {
	x := make(net.IP, net.IPv6len)
	d.copy(x)
	return x
}

func (d *decoder) ipv6N(n int) net.IP {
	x := make(net.IP, net.IPv6len)
	d.copyN(x, n)
	return x
}

func (d *decoder) as2() AS {
	x := make(AS, 2)
	d.copy(x)
	return x
}

func (d *decoder) as4() AS {
	x := make(AS, 4)
	d.copy(x)
	return x
}

func (d *decoder) nlriIPv4() *net.IPNet {
	l := int(d.uint8())
	ip := d.ipv4N((l + 7) >> 3)
	mask := net.CIDRMask(l, net.IPv4len<<3)
	return &net.IPNet{IP: ip, Mask: mask}
}

func (d *decoder) nlriIPv6() *net.IPNet {
	l := int(d.uint8())
	ip := d.ipv6N((l + 7) >> 3)
	mask := net.CIDRMask(l, net.IPv6len<<3)
	return &net.IPNet{IP: ip, Mask: mask}
}

func (d *decoder) unixTime() time.Time {
	return time.Unix(int64(d.uint32()), 0).UTC()
}

func (d *decoder) skip(n int) []byte {
	x := d.buf[:n]
	d.buf = d.buf[n:]
	return x
}

func (d *decoder) copy(b []byte) {
	copy(b, d.buf)
	d.buf = d.buf[len(b):]
}

func (d *decoder) copyN(b []byte, n int) {
	copy(b, d.buf[:n])
	d.buf = d.buf[n:]
}

func (d *decoder) size() int {
	return len(d.buf)
}
