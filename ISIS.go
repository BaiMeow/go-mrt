package mrt

type ISIS struct {
	header
	ISISPDU []byte
}

func (r *ISIS) DecodeBytes(data []byte) error {
	d := &decoder{data}
	r.decodeHeader(d)
	r.ISISPDU = d.bytes(d.size())
	return nil
}
