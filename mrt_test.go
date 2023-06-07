package mrt

import (
	"fmt"
	"io"
	"log"
	"os"
	"testing"
)

var Index []*TableDumpV2PeerEntry

func TestNewReader(t *testing.T) {
	file, err := os.OpenFile("06-07-2023-17-23.mrt", os.O_RDONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	rd := NewReader(file)
	for {
		rec, err := rd.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Println(err)
			continue
		}
		switch rec.Type() {
		case TYPE_TABLE_DUMP_V2:
			switch rec.Subtype() {
			case TABLE_DUMP_V2_SUBTYPE_PEER_INDEX_TABLE:
				t := rec.(*TableDumpV2PeerIndexTable)
				Index = t.PeerEntries
			case TABLE_DUMP_V2_SUBTYPE_RIB_IPv4_UNICAST_ADDPATH:
				t := rec.(*TableDumpV2RIB)
				fmt.Println("go to ", t.Prefix.String())
				for _, v := range t.RIBEntries {
					for _, p := range v.BGPAttributes {
						switch attri := p.Value.(type) {
						case BGPPathAttributeOrigin:
						case BGPPathAttributeASPath:
							fmt.Printf("path%d:\n", v.PathIdentifier)
							for _, as := range attri {
								for _, a := range as.Value {
									fmt.Println(a.String())
								}
							}
						}
					}
				}
			}
		}
	}
}
