package message

import (
	"encoding/binary"
	"encoding/json"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// produceStatsMessage proceduces message from BMP Statistic Message
func (p *producer) produceStatsMessage(msg bmp.Message) {
	if msg.PeerHeader == nil {
		glog.Errorf("perPeerHeader is missing, cannot construct Stats message")
		return
	}
	StatsMsg, ok := msg.Payload.(*bmp.StatsReport)
	if !ok {
		glog.Errorf("got invalid Payload type in bmp.StatsReport %+v", msg.Payload)
		return
	}
	if len(StatsMsg.StatsTLV) == 0 {
		b, _ := json.MarshalIndent(StatsMsg, "", "   ")
		glog.Errorf("stats message does not contain any tlv(stat) %s", string(b))
		return
	}

	m := Stats{
		RemoteASN:                   msg.PeerHeader.PeerAS,
		PeerRD:                      msg.PeerHeader.GetPeerDistinguisherString(),
		Timestamp:                   msg.PeerHeader.GetPeerTimestamp(),
		RouterHash:                  p.speakerHash,
		RouterIP:                    p.speakerIP,
		PeerType:                    uint8(msg.PeerHeader.PeerType),
		AdjRIBsInAfiSafi:            make(map[string]uint64),
		LocalRibAfiSafi:             make(map[string]uint64),
		AdjRIBsOutPostPolicyAfiSafi: make(map[string]uint64),
	}
	m.RemoteIP = msg.PeerHeader.GetPeerAddrString()
	m.RemoteBGPID = msg.PeerHeader.GetPeerBGPIDString()
	for _, tlv := range StatsMsg.StatsTLV {
		switch tlv.InformationType {
		case 0:
			m.RejectedPrefixes = binary.BigEndian.Uint32(tlv.Information)
		case 1:
			m.DuplicatePrefixs = binary.BigEndian.Uint32(tlv.Information)
		case 2:
			m.DuplicateWithDraws = binary.BigEndian.Uint32(tlv.Information)
		case 3:
			m.InvalidatedDueCluster = binary.BigEndian.Uint32(tlv.Information)
		case 4:
			m.InvalidatedDueAspath = binary.BigEndian.Uint32(tlv.Information)
		case 5:
			m.InvalidatedDueOriginatorId = binary.BigEndian.Uint32(tlv.Information)
		case 6:
			m.InvalidatedAsConfed = binary.BigEndian.Uint32(tlv.Information)
		case 7:
			m.AdjRIBsIn = binary.BigEndian.Uint64(tlv.Information)
		case 8:
			m.LocalRib = binary.BigEndian.Uint64(tlv.Information)
		case 9:
			m.AdjRIBsInAfiSafi[tlv.AfiSafi] = binary.BigEndian.Uint64(tlv.Information)
		case 10:
			m.LocalRibAfiSafi[tlv.AfiSafi] = binary.BigEndian.Uint64(tlv.Information)
		case 11:
			m.UpdatesAsWithdraw = binary.BigEndian.Uint32(tlv.Information)
		case 12:
			m.PrefixesAsWithdraw = binary.BigEndian.Uint32(tlv.Information)
		case 15:
			m.AdjRIBsOutPostPolicy = binary.BigEndian.Uint64(tlv.Information)
		case 17:
			m.AdjRIBsOutPostPolicyAfiSafi[tlv.AfiSafi] = binary.BigEndian.Uint64(tlv.Information)
		default:
			glog.Warningf("unprocessed stats type:%v", tlv.InformationType)
		}
	}
	//sm, _ := json.Marshal(&StatsMsg)
	//glog.Infof("STATUS MESSAGE: %s", sm)
	if err := p.marshalAndPublish(&m, bmp.StatsReportMsg, []byte(m.RouterHash), false); err != nil {
		glog.Errorf("failed to process peer Stats Report message with error: %+v", err)
		return
	}
}
