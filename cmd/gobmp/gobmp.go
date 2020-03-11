package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/golang/glog"
)

var (
	dstPort int
	srcPort int
)

func init() {
	flag.IntVar(&srcPort, "source-port", 5000, "port exposed to outside")
	flag.IntVar(&dstPort, "destination-port", 5050, "port openBMP is listening")
}

func server(incoming net.Listener, dstPort int) {
	glog.V(5).Infof("server running on port %d", srcPort)
	for {
		client, err := incoming.Accept()
		if err != nil {
			glog.Errorf("fail to accept client connection with error: %+v", err)
			continue
		}
		glog.V(5).Infof("client %+v accepted, calling the interceptor.", client.RemoteAddr())
		go interceptor(client, dstPort)
	}
}

func interceptor(client net.Conn, dstPort int) {
	var err error
	defer client.Close()
	server, err := net.Dial("tcp", ":"+fmt.Sprintf("%d", dstPort))
	if err != nil {
		glog.Errorf("fail to connect to destination with error: %+v", err)
		return
	}
	defer server.Close()
	glog.V(5).Infof("connection to destination server %v established, start intercepting", server.RemoteAddr())
	queue := make(chan []byte)
	pstop := make(chan struct{})
	// Starting parser per client with dedicated work queue
	go parser(queue, pstop)
	defer func() {
		glog.V(5).Infof("all done with client %+v and server %+v", client.RemoteAddr(), server.RemoteAddr())
		close(pstop)
	}()
	for {
		headerMsg := make([]byte, 6)
		if _, err := io.ReadAtLeast(client, headerMsg, 6); err != nil {
			glog.Errorf("fail to read from client %+v with error: %+v", client.RemoteAddr(), err)
			return
		}
		// Recovering common header first
		header, err := UnmarshalCommonHeader(headerMsg[:6])
		if err != nil {
			glog.Errorf("fail to recover BMP message Common Header with error: %+v", err)
			continue
		}
		// Allocating space for the message body
		msg := make([]byte, int(header.MessageLength)-6)
		// glog.V(5).Infof("Expected message lngth from client %+v is %d bytes", client.RemoteAddr(), int(header.MessageLength)-6)
		if _, err := io.ReadFull(client, msg); err != nil {
			glog.Errorf("fail to read from client %+v with error: %+v", client.RemoteAddr(), err)
			return
		}

		fullMsg := make([]byte, int(header.MessageLength))
		copy(fullMsg, headerMsg)
		copy(fullMsg[6:], msg)
		if _, err := server.Write(fullMsg); err != nil {
			glog.Errorf("fail to write to server %+v with error: %+v", server.RemoteAddr(), err)
			return
		}
		queue <- fullMsg
	}
}

func parser(queue chan []byte, stop chan struct{}) {
	for {
		select {
		case msg := <-queue:
			parsingWorker(msg)
		case <-stop:
			glog.Infof("received interrupt, stopping.")
		default:
		}
	}
}

func parsingWorker(b []byte) {
	perPerHeaderLen := 0
	// Loop through all found Common Headers in the slice and process them
	for p := 0; p < len(b); {
		// Recovering common header first
		ch, err := UnmarshalCommonHeader(b[p : p+6])
		if err != nil {
			glog.Errorf("fail to recover BMP message Common Header with error: %+v", err)
			return
		}
		p += 6
		// glog.V(5).Infof("recovered common header, version: %d message length: %d message type: %d", ch.Version, ch.MessageLength, ch.MessageType)
		switch ch.MessageType {
		case 0:
			// *  Type = 0: Route Monitoring
			lb := p + int(ch.MessageLength-6)
			if lb > len(b) {
				lb = len(b)
			}
			// glog.V(6).Infof("found Route Monitoring message: %s, length: %d", messageHex(b), len(b))
			rm, err := UnmarshalBMPRouteMonitorMessage(b[p:lb])
			if err != nil {
				glog.Errorf("fail to recover BMP Route Monitoring with error: %+v", err)
				return
			}
			if rm.CheckSAFI(71) {
				glog.V(5).Infof("route monitor message carries BGP-LS SAFI")
			} else {
				glog.V(5).Infof("route monitor message does not carry BGP-LS SAFI")
			}
			glog.V(6).Infof("parsed route monitor: \n%s", rm.String())
		case 1:
			// *  Type = 1: Statistics Report
			//glog.V(5).Infof("found Stats Report")

			/*pph*/
			_, err := UnmarshalPerPeerHeader(b[p : p+int(ch.MessageLength-6)])
			if err != nil {
				glog.Errorf("fail to recover BMP Per Peer Header with error: %+v", err)
				return
			}
			//glog.V(5).Infof("recovered per peer header %+v", *pph)
			// Move buffer pointer for the length of Per-Peer header
			perPerHeaderLen = 42

			/*sr*/
			_, err = UnmarshalBMPStatsReportMessage(b[p+perPerHeaderLen : len(b)])
			if err != nil {
				glog.Errorf("fail to recover BMP Stats Reports message with error: %+v", err)
				return
			}
			p += perPerHeaderLen
			// glog.V(6).Infof("recovered per stats reports message %+v", *sr)
		case 2:
			// *  Type = 2: Peer Down Notification
			glog.V(5).Infof("Peer Down message")
			// glog.V(6).Infof("Message: %+v", b[p:len(b)])
		case 3:
			// *  Type = 3: Peer Up Notification
			glog.V(5).Infof("Peer Up message")
			/*pph*/ _, err := UnmarshalPerPeerHeader(b[p : p+int(ch.MessageLength-6)])
			if err != nil {
				glog.Errorf("fail to recover BMP Per Peer Header with error: %+v", err)
				return
			}
			// glog.V(5).Infof("recovered per peer header %+v", *pph)
			// Move buffer pointer for the length of Per-Peer header
			perPerHeaderLen = 42
			/*pu*/ _, err = UnmarshalPeerUpMessage(b[p+perPerHeaderLen : p+int(ch.MessageLength)-6])
			if err != nil {
				glog.Errorf("fail to recover BMP Initiation message with error: %+v", err)
				return
			}
			p += perPerHeaderLen
			// glog.V(5).Infof("recovered per peer up message %+v", *pu)
			// glog.V(6).Infof("Sent Open %+v", *pu.SentOpen)
			// glog.V(6).Infof("Received Open %+v", *pu.ReceivedOpen)
		case 4:
			// *  Type = 4: Initiation Message
			glog.V(5).Infof("Initiation message")
			_, err := UnmarshalInitiationMessage(b[p : p+(int(ch.MessageLength)-6)])
			if err != nil {
				glog.Errorf("fail to recover BMP Initiation message with error: %+v", err)
				return
			}
		case 5:
			// *  Type = 5: Termination Message
			glog.V(5).Infof("Termination message")
		case 6:
			// *  Type = 6: Route Mirroring Message
			glog.V(5).Infof("Route Mirroring message")
		}
		perPerHeaderLen = 0
		p += (int(ch.MessageLength) - 6)
	}
}

func main() {
	flag.Parse()
	_ = flag.Set("logtostderr", "true")
	incoming, err := net.Listen("tcp", fmt.Sprintf(":%d", srcPort))
	if err != nil {
		glog.Errorf("fail to setup listener on port %d with error: %+v", srcPort, err)
		os.Exit(1)
	}

	// Wait for the interrupt
	signals := make(chan os.Signal, 1)
	stop := make(chan bool)
	signal.Notify(signals, os.Interrupt)
	go func() {
		for range signals {
			glog.Infof("received interrupt, stopping.")
			stop <- true
		}
	}()

	// Starting Interceptor server
	go server(incoming, dstPort)

	<-stop
	os.Exit(0)
}

// BMPCommonHeader defines BMP message Common Header per rfc7854
type BMPCommonHeader struct {
	Version       byte
	MessageLength int32
	MessageType   byte
}

// UnmarshalCommonHeader processes Common Header and returns BMPCommonHeader object
func UnmarshalCommonHeader(b []byte) (*BMPCommonHeader, error) {
	ch := &BMPCommonHeader{}
	if b[0] != 3 {
		return nil, fmt.Errorf("invalid version in common header, expected 3 found %d", b[0])
	}
	ch.Version = b[0]
	ch.MessageLength = int32(binary.BigEndian.Uint32(b[1:5]))
	ch.MessageType = b[5]
	// *  Type = 0: Route Monitoring
	// *  Type = 1: Statistics Report
	// *  Type = 2: Peer Down Notification
	// *  Type = 3: Peer Up Notification
	// *  Type = 4: Initiation Message
	// *  Type = 5: Termination Message
	// *  Type = 6: Route Mirroring Message
	switch ch.MessageType {
	case 0:
	case 1:
	case 2:
	case 3:
	case 4:
	case 5:
	case 6:
	default:
		return nil, fmt.Errorf("invalid message type in common header, expected between 0 and 6 found %d", b[5])
	}

	return ch, nil
}

// InformationalTLV defines Informational TLV per rfc7854
type InformationalTLV struct {
	InformationType   int16
	InformationLength int16
	Information       []byte
}

// BMPInitiationMessage defines BMP Initiation Message per rfc7854
type BMPInitiationMessage struct {
	TLV []InformationalTLV
}

// UnmarshalInitiationMessage processes Initiation Message and returns BMPInitiationMessage object
func UnmarshalInitiationMessage(b []byte) (*BMPInitiationMessage, error) {
	im := &BMPInitiationMessage{
		TLV: make([]InformationalTLV, 0),
	}
	for i := 0; i < len(b); {
		// Extracting TLV type 2 bytes
		t := int16(binary.BigEndian.Uint16(b[i : i+2]))
		switch t {
		case 0:
		case 1:
		case 2:
		default:
			return nil, fmt.Errorf("invalid tlv type, expected between 0 and 2 found %d", t)
		}
		// Extracting TLV length
		l := int16(binary.BigEndian.Uint16(b[i+2 : i+4]))
		if l > int16(len(b)-(i+4)) {
			return nil, fmt.Errorf("invalid tlv length %d", l)
		}
		v := b[i+4 : i+4+int(l)]
		im.TLV = append(im.TLV, InformationalTLV{
			InformationType:   t,
			InformationLength: l,
			Information:       v,
		})
		i += 4 + int(l)
	}

	return im, nil
}

// UnmarshalTLV builds a slice of Informational TLVs
func UnmarshalTLV(b []byte) ([]InformationalTLV, error) {
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

// BMPPerPeerHeader defines BMP Per-Peer Header per rfc7854
type BMPPerPeerHeader struct {
	PeerType          byte
	FlagV             bool
	FlagL             bool
	FlagA             bool
	PeerDistinguisher []byte
	PeerAddress       []byte
	PeerAS            int32
	PeerBGPID         []byte
	PeerTimestamp     time.Duration
}

// UnmarshalPerPeerHeader processes Per-Peer header
func UnmarshalPerPeerHeader(b []byte) (*BMPPerPeerHeader, error) {
	pph := &BMPPerPeerHeader{
		PeerDistinguisher: make([]byte, 8),
		PeerAddress:       make([]byte, 14),
		PeerBGPID:         make([]byte, 4),
	}
	// Extracting Peer type
	// *  Peer Type = 0: Global Instance Peer
	// *  Peer Type = 1: RD Instance Peer
	// *  Peer Type = 2: Local Instance Peer
	switch b[0] {
	case 0:
	case 1:
	case 2:
	default:
		return nil, fmt.Errorf("invalid peer type, expected between 0 and 2 found %d", b[0])
	}
	pph.PeerType = b[0]
	pph.FlagV = b[1]&0x80 == 0x80
	pph.FlagL = b[1]&0x40 == 0x40
	pph.FlagA = b[1]&0x20 == 0x20
	// RD 8 bytes
	copy(pph.PeerDistinguisher, b[4:12])
	// Peer Address 16 bytes
	copy(pph.PeerAddress, b[12:26])
	pph.PeerAS = int32(binary.BigEndian.Uint32(b[26:30]))
	copy(pph.PeerBGPID, b[30:34])
	pph.PeerTimestamp = time.Duration(binary.BigEndian.Uint64(b[34:42]))

	return pph, nil
}

// BMPPeerUpMessage defines BMPPeerUpMessage per rfc7854
type BMPPeerUpMessage struct {
	LocalAddress []byte
	LocalPort    uint16
	RemotePort   uint16
	SentOpen     *BGPOpenMessage
	ReceivedOpen *BGPOpenMessage
	Information  []InformationalTLV
}

// UnmarshalPeerUpMessage processes Peer Up message and returns BMPPeerUpMessage object
func UnmarshalPeerUpMessage(b []byte) (*BMPPeerUpMessage, error) {
	var err error
	pu := &BMPPeerUpMessage{
		LocalAddress: make([]byte, 16),
		SentOpen:     &BGPOpenMessage{},
		ReceivedOpen: &BGPOpenMessage{},
		Information:  make([]InformationalTLV, 0),
	}
	p := 0
	copy(pu.LocalAddress, b[:16])
	p += 16
	pu.LocalPort = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	pu.RemotePort = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	// Skip first marker 16 bytes
	p += 16
	l1 := int16(binary.BigEndian.Uint16(b[p : p+2]))
	pu.SentOpen, err = UnmarshalBGPOpenMessage(b[p : p+int(l1-16)])
	if err != nil {
		return nil, err
	}
	// Moving pointer to the next marker
	p += int(l1) - 16
	// Skip second marker
	p += 16
	l2 := int16(binary.BigEndian.Uint16(b[p : p+2]))
	pu.ReceivedOpen, err = UnmarshalBGPOpenMessage(b[p : p+int(l2-16)])
	if err != nil {
		return nil, err
	}
	p += int(l2) - 16
	// Last part is optional Informational TLVs
	if len(b) > int(p) {
		// Since pointer p does not point to the end of buffer,
		// then processing Informational TLVs
		tlvs, err := UnmarshalTLV(b[p : len(b)-int(p)])
		if err != nil {
			return nil, err
		}
		pu.Information = tlvs
	}
	return pu, nil
}

// BGPOpenMessage defines BGP Open Message structure
type BGPOpenMessage struct {
	Length             int16
	Type               byte
	Version            byte
	MyAS               uint16
	HoldTime           int16
	BGPID              []byte
	OptParamLen        byte
	OptionalParameters []BGPInformationalTLV
}

// BGPInformationalTLV defines BGP informational TLV object
type BGPInformationalTLV struct {
	Type   byte
	Length byte
	Value  []byte
}

// UnmarshalBGPOpenMessage validate information passed in byte slice and returns BGPOpenMessage object
func UnmarshalBGPOpenMessage(b []byte) (*BGPOpenMessage, error) {
	var err error
	p := 0
	m := BGPOpenMessage{
		BGPID: make([]byte, 4),
	}
	m.Length = int16(binary.BigEndian.Uint16(b[p : p+2]))
	p += 2
	if b[p] != 1 {
		return nil, fmt.Errorf("invalid message type %d for BGP Open Message", b[p])
	}
	m.Type = b[p]
	p++
	if b[p] != 4 {
		return nil, fmt.Errorf("invalid message version %d for BGP Open Message", b[p])
	}
	m.Version = b[p]
	p++
	m.MyAS = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	m.HoldTime = int16(binary.BigEndian.Uint16(b[p : p+2]))
	p += 2
	copy(m.BGPID, b[p:p+4])
	p += 4
	m.OptParamLen = b[p]
	p++
	if m.OptParamLen != 0 {
		m.OptionalParameters, err = UnmarshalBGPTLV(b[p : p+int(m.OptParamLen)])
		if err != nil {
			return nil, err
		}
	}

	return &m, nil
}

// UnmarshalBGPTLV builds a slice of Informational TLVs
func UnmarshalBGPTLV(b []byte) ([]BGPInformationalTLV, error) {
	tlvs := make([]BGPInformationalTLV, 0)
	for p := 0; p < len(b); {
		t := b[p]
		l := b[p+1]
		v := b[p+2 : p+2+int(l)]
		tlvs = append(tlvs, BGPInformationalTLV{
			Type:   t,
			Length: l,
			Value:  v,
		})
		p += 2 + int(l)
	}

	return tlvs, nil
}

// BMPStatsReport defines BMP Stats message structure
type BMPStatsReport struct {
	StatsCount int32
	StatsTLV   []InformationalTLV
}

// UnmarshalBMPStatsReportMessage builds BMP Stats Reports object
func UnmarshalBMPStatsReportMessage(b []byte) (*BMPStatsReport, error) {
	sr := BMPStatsReport{}
	p := 0
	l := int32(binary.BigEndian.Uint32(b[p : p+4]))
	if l > int32(len(b)) {
		return nil, fmt.Errorf("invalid length of Stats Report %d", l)
	}
	sr.StatsCount = l
	p += 4
	tlvs, err := UnmarshalTLV(b[p:])
	if err != nil {
		return nil, err
	}
	sr.StatsTLV = tlvs

	return &sr, nil
}

// BGPWithdrawnRoute defines a structure of BGP Withdrawn prefix
type BGPWithdrawnRoute struct {
	Length uint8
	Prefix []byte
}

func (wr *BGPWithdrawnRoute) String() string {
	var s string
	s += fmt.Sprintf("Withdrawn prefix length: %d\n", wr.Length)
	s += messageHex(wr.Prefix)
	s += "\n"

	return s
}

// BGPWithdrawnRoutes defines collection of BGP Withdrawn prefixes
type BGPWithdrawnRoutes struct {
	WithdrawnRoutes []BGPWithdrawnRoute
}

// BGPPathAttribute defines a structure of an attribute
type BGPPathAttribute struct {
	AttributeTypeFlags uint8
	AttributeType      uint8
	AttributeLength    uint16
	Attribute          []byte
}

func (pa *BGPPathAttribute) String() string {
	var s string
	s += fmt.Sprintf("Attribute Type Flags: 0x%02X\n", pa.AttributeTypeFlags)
	s += fmt.Sprintf("Attribute Type: 0x%02X\n", pa.AttributeType)
	s += fmt.Sprintf("Attribute Length: %d\n", pa.AttributeLength)
	if pa.AttributeType == 0x0e {
		// Found MP_REACH_NLRI attribute
		mp, _ := UnmarshalMPReachNLRI(pa.Attribute)
		s += mp.String()
	} else {
		s += messageHex(pa.Attribute)
		s += "\n"
	}
	return s
}

// BGPUpdate defines a structure of BGP Update message
type BGPUpdate struct {
	WithdrawnRoutesLength    uint16
	WithdrawnRoutes          BGPWithdrawnRoutes
	TotalPathAttributeLength uint16
	PathAttributes           []BGPPathAttribute
	NLRI                     []byte
}

func (up *BGPUpdate) String() string {
	var s string
	s += fmt.Sprintf("Withdrawn Routes Length: %d\n", up.WithdrawnRoutesLength)
	if up.WithdrawnRoutesLength != 0 {
		for _, wr := range up.WithdrawnRoutes.WithdrawnRoutes {
			s += wr.String()
		}
	}
	s += fmt.Sprintf("Total Path Attribute Length: %d\n", up.TotalPathAttributeLength)
	if up.TotalPathAttributeLength != 0 {
		for _, pa := range up.PathAttributes {
			s += pa.String()
		}
	}
	s += "NLRI: "
	s += messageHex(up.NLRI)
	s += "\n"

	return s
}

// BMPRouteMonitor defines a structure of BMP Route Monitoring message
type BMPRouteMonitor struct {
	Updates []BGPUpdate
}

func (rm *BMPRouteMonitor) String() string {
	var s string
	for _, u := range rm.Updates {
		s += u.String()
	}
	return s
}

// CheckSAFI checks if Route Monitor message carries specified SAFI and returns true or false
func (rm *BMPRouteMonitor) CheckSAFI(safi int) bool {
	for _, u := range rm.Updates {
		for _, pa := range u.PathAttributes {
			if pa.AttributeType == 0x0e {
				mp, _ := UnmarshalMPReachNLRI(pa.Attribute)
				if mp.SubAddressFamilyID == uint8(safi) {
					return true
				}
			}
		}
	}

	return false
}

// UnmarshalBMPRouteMonitorMessage builds BMP Route Monitor object
func UnmarshalBMPRouteMonitorMessage(b []byte) (*BMPRouteMonitor, error) {
	rm := BMPRouteMonitor{
		Updates: make([]BGPUpdate, 0),
	}
	p := 0
	_, err := UnmarshalPerPeerHeader(b[p : p+42])
	if err != nil {
		return nil, fmt.Errorf("fail to recover BMP Per Peer Header with error: %+v", err)
	}
	// Skip Per-Peer header's 42 bytes
	p += 42
	// Skip 16 bytes of a marker
	p += 16
	l := binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	u, err := UnmarshalBGPUpdate(b[p+1 : p+int(l-18)])
	if err != nil {
		return nil, err
	}
	rm.Updates = append(rm.Updates, *u)
	// p += int(l - 18)

	return &rm, nil
}

// UnmarshalBGPUpdate build BGP Update object from the byte slice provided
func UnmarshalBGPUpdate(b []byte) (*BGPUpdate, error) {
	p := 0
	u := BGPUpdate{}
	u.WithdrawnRoutesLength = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	// Skip Withdrawn Routes
	p += int(u.WithdrawnRoutesLength)
	u.TotalPathAttributeLength = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	attrs, err := UnmarshalPathAttributes(b[p : p+int(u.TotalPathAttributeLength)])
	if err != nil {
		return nil, err
	}
	u.PathAttributes = attrs
	p += int(u.TotalPathAttributeLength)
	u.NLRI = b[p:len(b)]

	return &u, nil
}

// UnmarshalPathAttributes builds BGP Path attributes slice
func UnmarshalPathAttributes(b []byte) ([]BGPPathAttribute, error) {
	attrs := make([]BGPPathAttribute, 0)

	for p := 0; p < len(b); {
		f := b[p]
		t := b[p+1]
		p += 2
		var l uint16
		// Chcking for Extened
		if f&0x10 == 0x10 {
			l = binary.BigEndian.Uint16(b[p : p+2])
			p += 2
		} else {
			l = uint16(b[p])
			p++
		}
		attrs = append(attrs, BGPPathAttribute{
			AttributeTypeFlags: f,
			AttributeType:      t,
			AttributeLength:    l,
			Attribute:          b[p : p+int(l)],
		})
		p += int(l)
	}

	return attrs, nil
}

// +---------------------------------------------------------+
// | Address Family Identifier (2 octets)                    |
// +---------------------------------------------------------+
// | Subsequent Address Family Identifier (1 octet)          |
// +---------------------------------------------------------+
// | Length of Next Hop Network Address (1 octet)            |
// +---------------------------------------------------------+
// | Network Address of Next Hop (variable)                  |
// +---------------------------------------------------------+
// | Reserved (1 octet)                                      |
// +---------------------------------------------------------+
// | Network Layer Reachability Information (variable)       |
// +---------------------------------------------------------+

// MPReachNLRI defines an MP Reach NLRI object
type MPReachNLRI struct {
	AddressFamilyID      uint16
	SubAddressFamilyID   uint8
	NextHopAddressLength uint8
	NextHopAddress       []byte
	Reserved             uint8
	NLRI                 []byte
}

// UnmarshalMPReachNLRI builds MP Reach NLRI attributes
func UnmarshalMPReachNLRI(b []byte) (*MPReachNLRI, error) {
	mp := MPReachNLRI{}
	p := 0
	mp.AddressFamilyID = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	mp.SubAddressFamilyID = uint8(b[p])
	p++
	mp.NextHopAddressLength = uint8(b[p])
	p++
	mp.NextHopAddress = b[p : p+int(mp.NextHopAddressLength)]
	p += int(mp.NextHopAddressLength)
	// Skip reserved byte
	p++
	mp.NLRI = b[p:len(b)]

	return &mp, nil
}

func (mp *MPReachNLRI) String() string {
	var s string
	s += fmt.Sprintf("Address Family ID: %d\n", mp.AddressFamilyID)
	s += fmt.Sprintf("Subsequent Address Family ID: %d\n", mp.SubAddressFamilyID)
	s += fmt.Sprintf("Length of Next Hop Network Address: %d\n", mp.NextHopAddressLength)
	s += fmt.Sprintf("Next Hop Network Address: %s\n", messageHex(mp.NextHopAddress))
	s += fmt.Sprintf("NLRI: %s\n", messageHex(mp.NLRI))

	return s
}

func messageHex(b []byte) string {
	var s string
	s += "[ "
	for i := 0; i < len(b); i++ {
		s += fmt.Sprintf("%02x ", b[i])
	}
	s += " ]"

	return s
}
