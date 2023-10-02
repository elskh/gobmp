package bmp

import (
	"encoding/binary"
	"fmt"
	"strconv"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// InformationalTLV defines Informational TLV per rfc7854
type InformationalTLV struct {
	InformationType   int16
	InformationLength int16
	Information       []byte
}

// UnmarshalTLV builds a slice of Informational TLVs
func UnmarshalTLV(b []byte) ([]InformationalTLV, error) {
	if glog.V(6) {
		glog.Infof("BMP Informational TLV Raw: %s", tools.MessageHex(b))
	}
	tlvs := make([]InformationalTLV, 0)
	for i := 0; i < len(b); {
		// Extracting TLV type 2 bytes
		t := int16(binary.BigEndian.Uint16(b[i : i+2]))
		// Extracting TLV length
		l := int16(binary.BigEndian.Uint16(b[i+2 : i+4]))
		if l > int16(len(b)-(i+4)) {
			return nil, fmt.Errorf("invalid tlv length %d", l)
		}
		v := b[i+4 : i+4+int(l)]
		tlvs = append(tlvs, InformationalTLV{
			InformationType:   t,
			InformationLength: l,
			Information:       v,
		})
		i += 4 + int(l)
	}

	return tlvs, nil
}

type InformationalTLVAfiSafi struct {
	InformationType   int16
	InformationLength int16
	Information       []byte
	AfiSafi           string
	//Safi              uint8
}

var AfiSafiValue = map[uint32]string{
	100001: "ipv4_unicast",
	100002: "ipv4_multicast",
	100004: "ipv4_label",
	100128: "ipv4_vpn",
	100133: "ipv4_flowspec",
	200001: "ipv6_unicast",
	200002: "ipv6_multicast",
	200004: "ipv6_label",
	200128: "ipv6_vpn",
	200133: "ipv6_flowspec",
}

func UnmarshalTLVAfiSafi(b []byte) ([]InformationalTLVAfiSafi, error) {
	if glog.V(6) {
		glog.Infof("BMP Informational TLV Raw: %s", tools.MessageHex(b))
	}
	tlvs := make([]InformationalTLVAfiSafi, 0)
	for i := 0; i < len(b); {
		// Extracting TLV type 2 bytes
		t := int16(binary.BigEndian.Uint16(b[i : i+2]))
		// Extracting TLV length
		l := int16(binary.BigEndian.Uint16(b[i+2 : i+4]))
		if l > int16(len(b)-(i+4)) {
			return nil, fmt.Errorf("invalid tlv length %d", l)
		}
		if t == 9 || t == 10 || t == 17 {
			a := uint32(binary.BigEndian.Uint16(b[i+4 : i+6]))
			s := uint32(b[i+6])
			v := b[i+7 : i+4+int(l)]
			as := AfiSafiValue[a*100000+s]
			if as == "" {
				as = "afi=" + strconv.FormatUint(uint64(a), 10) + "_safi=" + strconv.FormatUint(uint64(s), 10)
			}
			tlvs = append(tlvs, InformationalTLVAfiSafi{
				InformationType:   t,
				InformationLength: l,
				Information:       v,
				AfiSafi:           as,
			})
			i += 4 + int(l)
		} else {
			v := b[i+4 : i+4+int(l)]
			tlvs = append(tlvs, InformationalTLVAfiSafi{
				InformationType:   t,
				InformationLength: l,
				Information:       v,
			})
			i += 4 + int(l)
		}

	}

	return tlvs, nil
}
