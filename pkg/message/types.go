package message

import (
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bgpls"
	"github.com/sbezverk/gobmp/pkg/prefixsid"
	"github.com/sbezverk/gobmp/pkg/sr"
	"github.com/sbezverk/gobmp/pkg/srv6"
)

// PeerStateChange defines a message format sent to as a result of BMP Peer Up or Peer Down message
type PeerStateChange struct {
	Key              string `json:"_key,omitempty"`
	ID               string `json:"_id,omitempty"`
	Rev              string `json:"_rev,omitempty"`
	Action           string `json:"action,omitempty"` // Action can be "up" or "down"
	Sequence         int    `json:"sequence,omitempty"`
	Hash             string `json:"hash,omitempty"`
	RouterHash       string `json:"router_hash,omitempty"`
	Name             string `json:"name,omitempty"`
	RemoteBGPID      string `json:"remote_bgp_id,omitempty"`
	RouterIP         string `json:"router_ip,omitempty"`
	Timestamp        string `json:"timestamp,omitempty"`
	RemoteASN        int32  `json:"remote_asn,omitempty"`
	RemoteIP         string `json:"remote_ip,omitempty"`
	PeerRD           string `json:"peer_rd,omitempty"`
	RemotePort       int    `json:"remote_port,omitempty"`
	LocalASN         int32  `json:"local_asn,omitempty"`
	LocalIP          string `json:"local_ip,omitempty"`
	LocalPort        int    `json:"local_port,omitempty"`
	LocalBGPID       string `json:"local_bgp_id,omitempty"`
	InfoData         []byte `json:"info_data,omitempty"`
	AdvCapabilities  string `json:"adv_cap,omitempty"`
	RcvCapabilities  string `json:"recv_cap,omitempty"`
	RemoteHolddown   int    `json:"remote_holddown,omitempty"`
	AdvHolddown      int    `json:"adv_holddown,omitempty"`
	BMPReason        int    `json:"bmp_reason,omitempty"`
	BMPErrorCode     int    `json:"bmp_error_code,omitempty"`
	BMPErrorSubCode  int    `json:"bmp_error_sub_code,omitempty"`
	ErrorText        string `json:"error_text,omitempty"`
	IsL3VPN          bool   `json:"is_l"`
	IsPrepolicy      bool   `json:"isprepolicy"`
	IsIPv4           bool   `json:"is_ipv4"`
	IsLocRIB         bool   `json:"is_locrib"`
	IsLocRIBFiltered bool   `json:"is_locrib_filtered"`
	TableName        string `json:"table_name,omitempty"`
}

// UnicastPrefix defines a message format sent as a result of BMP Route Monitor message
// which carries BGP Update with original NLRI information.
type UnicastPrefix struct {
	Key            string              `json:"_key,omitempty"`
	ID             string              `json:"_id,omitempty"`
	Rev            string              `json:"_rev,omitempty"`
	Action         string              `json:"action,omitempty"` // Action can be "add" or "del"
	Sequence       int                 `json:"sequence,omitempty"`
	Hash           string              `json:"hash,omitempty"`
	RouterHash     string              `json:"router_hash,omitempty"`
	RouterIP       string              `json:"router_ip,omitempty"`
	BaseAttributes *bgp.BaseAttributes `json:"base_attrs,omitempty"`
	PeerHash       string              `json:"peer_hash,omitempty"`
	PeerIP         string              `json:"peer_ip,omitempty"`
	PeerASN        int32               `json:"peer_asn,omitempty"`
	Timestamp      string              `json:"timestamp,omitempty"`
	Prefix         string              `json:"prefix,omitempty"`
	PrefixLen      int32               `json:"prefix_len,omitempty"`
	IsIPv4         bool                `json:"is_ipv4"`
	OriginAS       int32               `json:"origin_as,omitempty"`
	Nexthop        string              `json:"nexthop,omitempty"`
	IsNexthopIPv4  bool                `json:"is_nexthop_ipv4"`
	PathID         int32               `json:"path_id,omitempty"`
	Labels         []uint32            `json:"labels,omitempty"`
	IsPrepolicy    bool                `json:"isprepolicy"`
	IsAdjRIBIn     bool                `json:"is_adj_rib_in"`
	PrefixSID      *prefixsid.PSid     `json:"prefix_sid,omitempty"`
}

// LSNode defines a structure of LS Node message
type LSNode struct {
	Key                 string                      `json:"_key,omitempty"`
	ID                  string                      `json:"_id,omitempty"`
	Rev                 string                      `json:"_rev,omitempty"`
	Action              string                      `json:"action,omitempty"` // Action can be "add" or "del"
	Sequence            int                         `json:"sequence,omitempty"`
	Hash                string                      `json:"hash,omitempty"`
	RouterHash          string                      `json:"router_hash,omitempty"`
	RouterIP            string                      `json:"router_ip,omitempty"`
	PeerHash            string                      `json:"peer_hash,omitempty"`
	PeerIP              string                      `json:"peer_ip,omitempty"`
	PeerASN             int32                       `json:"peer_asn,omitempty"`
	Timestamp           string                      `json:"timestamp,omitempty"`
	IGPRouterID         string                      `json:"igp_router_id,omitempty"`
	RouterID            string                      `json:"router_id,omitempty"`
	ASN                 uint32                      `json:"asn,omitempty"`
	LSID                uint32                      `json:"ls_id,omitempty"`
	MTID                []uint16                    `json:"mt_id,omitempty"`
	OSPFAreaID          string                      `json:"ospf_area_id,omitempty"`
	ISISAreaID          string                      `json:"isis_area_id,omitempty"`
	Protocol            string                      `json:"protocol,omitempty"`
	ProtocolID          base.ProtoID                `json:"protocol_id,omitempty"`
	NodeFlags           uint8                       `json:"node_flags"`
	Name                string                      `json:"name,omitempty"`
	SRCapabilities      *sr.Capability              `json:"ls_sr_capabilities,omitempty"`
	SRAlgorithm         []int                       `json:"sr_algorithm,omitempty"`
	SRLocalBlock        *sr.LocalBlock              `json:"sr_local_block,omitempty"`
	SRv6CapabilitiesTLV *srv6.CapabilityTLV         `json:"srv6_capabilities_tlv,omitempty"`
	NodeMSD             []*base.MSDTV               `json:"node_msd,omitempty"`
	FlexAlgoDefinition  []*bgpls.FlexAlgoDefinition `json:"flex_algo_definition,omitempty"`
	IsPrepolicy         bool                        `json:"isprepolicy"`
	IsAdjRIBIn          bool                        `json:"is_adj_rib_in"`
}

// LSLink defines a structure of LS link message
type LSLink struct {
	Key                   string                   `json:"_key,omitempty"`
	ID                    string                   `json:"_id,omitempty"`
	Rev                   string                   `json:"_rev,omitempty"`
	Action                string                   `json:"action,omitempty"`
	Sequence              int                      `json:"sequence,omitempty"`
	Hash                  string                   `json:"hash,omitempty"`
	RouterHash            string                   `json:"router_hash,omitempty"`
	RouterIP              string                   `json:"router_ip,omitempty"`
	PeerHash              string                   `json:"peer_hash,omitempty"`
	PeerIP                string                   `json:"peer_ip,omitempty"`
	PeerASN               int32                    `json:"peer_asn,omitempty"`
	Timestamp             string                   `json:"timestamp,omitempty"`
	IGPRouterID           string                   `json:"igp_router_id,omitempty"`
	RouterID              string                   `json:"router_id,omitempty"`
	LSID                  uint32                   `json:"ls_id,omitempty"`
	Protocol              string                   `json:"protocol,omitempty"`
	ProtocolID            base.ProtoID             `json:"protocol_id,omitempty"`
	Nexthop               string                   `json:"nexthop,omitempty"`
	MTID                  uint16                   `json:"mt_id,omitempty"`
	LocalLinkID           uint32                   `json:"local_link_id,omitempty"`
	RemoteLinkID          uint32                   `json:"remote_link_id,omitempty"`
	LocalLinkIP           []string                 `json:"local_link_ip,omitempty"`
	RemoteLinkIP          []string                 `json:"remote_link_ip,omitempty"`
	IGPMetric             uint32                   `json:"igp_metric,omitempty"`
	AdminGroup            uint32                   `json:"admin_group,omitempty"`
	MaxLinkBW             uint32                   `json:"max_link_bw,omitempty"`
	MaxResvBW             uint32                   `json:"max_resv_bw,omitempty"`
	UnResvBW              []uint32                 `json:"unresv_bw,omitempty"`
	TEDefaultMetric       uint32                   `json:"te_default_metric,omitempty"`
	LinkProtection        uint16                   `json:"link_protection,omitempty"`
	MPLSProtoMask         uint8                    `json:"mpls_proto_mask,omitempty"`
	SRLG                  []uint32                 `json:"srlg,omitempty"`
	LinkName              string                   `json:"link_name,omitempty"`
	RemoteNodeHash        string                   `json:"remote_node_hash,omitempty"`
	LocalNodeHash         string                   `json:"local_node_hash,omitempty"`
	RemoteIGPRouterID     string                   `json:"remote_igp_router_id,omitempty"`
	RemoteRouterID        string                   `json:"remote_router_id,omitempty"`
	LocalNodeASN          uint32                   `json:"local_node_asn,omitempty"`
	RemoteNodeASN         uint32                   `json:"remote_node_asn,omitempty"`
	SRv6BGPPeerNodeSID    *srv6.BGPPeerNodeSID     `json:"srv6_bgp_peer_node_sid,omitempty"`
	SRv6ENDXSID           []*srv6.EndXSIDTLV       `json:"srv6_endx_sid,omitempty"`
	LSAdjacencySID        []*sr.AdjacencySIDTLV    `json:"ls_adjacency_sid,omitempty"`
	LinkMSD               []*base.MSDTV            `json:"link_msd,omitempty"`
	AppSpecLinkAttr       []*bgpls.AppSpecLinkAttr `json:"app_spec_link_attr,omitempty"`
	UnidirLinkDelay       uint32                   `json:"unidir_link_delay,omitempty"`
	UnidirLinkDelayMinMax []uint32                 `json:"unidir_link_delay_min_max,omitempty"`
	UnidirDelayVariation  uint32                   `json:"unidir_delay_variation,omitempty"`
	UnidirPacketLoss      uint32                   `json:"unidir_packet_loss,omitempty"`
	UnidirResidualBW      uint32                   `json:"unidir_residual_bw,omitempty"`
	UnidirAvailableBW     uint32                   `json:"unidir_available_bw,omitempty"`
	UnidirBWUtilization   uint32                   `json:"unidir_bw_utilization,omitempty"`
}

// L3VPNPrefix defines the structure of Layer 3 VPN message
type L3VPNPrefix struct {
	Key            string              `json:"_key,omitempty"`
	ID             string              `json:"_id,omitempty"`
	Rev            string              `json:"_rev,omitempty"`
	Action         string              `json:"action,omitempty"` // Action can be "add" or "del"
	Sequence       int                 `json:"sequence,omitempty"`
	Hash           string              `json:"hash,omitempty"`
	RouterHash     string              `json:"router_hash,omitempty"`
	RouterIP       string              `json:"router_ip,omitempty"`
	BaseAttributes *bgp.BaseAttributes `json:"base_attrs,omitempty"`
	PeerHash       string              `json:"peer_hash,omitempty"`
	PeerIP         string              `json:"peer_ip,omitempty"`
	PeerASN        int32               `json:"peer_asn,omitempty"`
	Timestamp      string              `json:"timestamp,omitempty"`
	Prefix         string              `json:"prefix,omitempty"`
	PrefixLen      int32               `json:"prefix_len,omitempty"`
	IsIPv4         bool                `json:"is_ipv4"`
	OriginAS       int32               `json:"origin_as,omitempty"`
	Nexthop        string              `json:"nexthop,omitempty"`
	ClusterList    string              `json:"cluster_list,omitempty"`
	IsNexthopIPv4  bool                `json:"is_nexthop_ipv4"`
	PathID         int32               `json:"path_id,omitempty"`
	Labels         []uint32            `json:"labels,omitempty"`
	IsPrepolicy    bool                `json:"isprepolicy"`
	IsAdjRIBIn     bool                `json:"is_adj_rib_in"`
	VPNRD          string              `json:"vpn_rd,omitempty"`
	VPNRDType      uint16              `json:"vpn_rd_type"`
	PrefixSID      *prefixsid.PSid     `json:"prefix_sid,omitempty"`
}

// LSPrefix defines a structure of LS Prefix message
type LSPrefix struct {
	Key                  string                        `json:"_key,omitempty"`
	ID                   string                        `json:"_id,omitempty"`
	Rev                  string                        `json:"_rev,omitempty"`
	Action               string                        `json:"action,omitempty"`
	Sequence             int                           `json:"sequence,omitempty"`
	Hash                 string                        `json:"hash,omitempty"`
	RouterHash           string                        `json:"router_hash,omitempty"`
	RouterIP             string                        `json:"router_ip,omitempty"`
	PeerHash             string                        `json:"peer_hash,omitempty"`
	PeerIP               string                        `json:"peer_ip,omitempty"`
	PeerASN              int32                         `json:"peer_asn,omitempty"`
	Timestamp            string                        `json:"timestamp,omitempty"`
	IGPRouterID          string                        `json:"igp_router_id,omitempty"`
	RouterID             string                        `json:"router_id,omitempty"`
	LSID                 uint32                        `json:"ls_id,omitempty"`
	ProtocolID           base.ProtoID                  `json:"protocol_id,omitempty"`
	Protocol             string                        `json:"protocol,omitempty"`
	Nexthop              string                        `json:"nexthop,omitempty"`
	LocalNodeHash        string                        `json:"local_node_hash,omitempty"`
	MTID                 uint16                        `json:"mt_id,omitempty"`
	OSPFRouteType        uint8                         `json:"ospf_route_type,omitempty"`
	IGPFlags             uint8                         `json:"igp_flags"`
	IGPRouteTag          []uint32                      `json:"route_tag,omitempty"`
	IGPExtRouteTag       []uint64                      `json:"ext_route_tag,omitempty"`
	OSPFFwdAddr          string                        `json:"ospf_fwd_addr,omitempty"`
	IGPMetric            uint32                        `json:"igp_metric,omitempty"`
	Prefix               string                        `json:"prefix,omitempty"`
	PrefixLen            int32                         `json:"prefix_len,omitempty"`
	IsPrepolicy          bool                          `json:"isprepolicy"`
	IsAdjRIBIn           bool                          `json:"is_adj_rib_in"`
	LSPrefixSID          []*sr.PrefixSIDTLV            `json:"ls_prefix_sid,omitempty"`
	PrefixAttrFlags      uint8                         `json:"prefix_attr_flags"`
	FlexAlgoPrefixMetric []*bgpls.FlexAlgoPrefixMetric `json:"flex_algo_prefix_metric,omitempty"`
	SRv6Locator          []*srv6.LocatorTLV            `json:"srv6_locator,omitempty"`
}

// LSSRv6SID defines a structure of LS SRv6 SID message
type LSSRv6SID struct {
	Key                  string                 `json:"_key,omitempty"`
	ID                   string                 `json:"_id,omitempty"`
	Rev                  string                 `json:"_rev,omitempty"`
	Action               string                 `json:"action,omitempty"`
	Sequence             int                    `json:"sequence,omitempty"`
	Hash                 string                 `json:"hash,omitempty"`
	RouterHash           string                 `json:"router_hash,omitempty"`
	RouterIP             string                 `json:"router_ip,omitempty"`
	PeerHash             string                 `json:"peer_hash,omitempty"`
	PeerIP               string                 `json:"peer_ip,omitempty"`
	PeerASN              int32                  `json:"peer_asn,omitempty"`
	Timestamp            string                 `json:"timestamp,omitempty"`
	IGPRouterID          string                 `json:"igp_router_id,omitempty"`
	LocalNodeASN         uint32                 `json:"local_node_asn,omitempty"`
	RouterID             string                 `json:"router_id,omitempty"`
	LSID                 uint32                 `json:"ls_id,omitempty"`
	OSPFAreaID           string                 `json:"ospf_area_id,omitempty"`
	ISISAreaID           string                 `json:"isis_area_id,omitempty"`
	Protocol             string                 `json:"protocol,omitempty"`
	Nexthop              string                 `json:"nexthop,omitempty"`
	LocalNodeHash        string                 `json:"local_node_hash,omitempty"`
	MTID                 uint16                 `json:"mt_id,omitempty"`
	OSPFRouteType        uint8                  `json:"ospf_route_type,omitempty"`
	IGPFlags             uint8                  `json:"igp_flags"`
	IGPRouteTag          uint8                  `json:"route_tag,omitempty"`
	IGPExtRouteTag       uint8                  `json:"ext_route_tag,omitempty"`
	OSPFFwdAddr          string                 `json:"ospf_fwd_addr,omitempty"`
	IGPMetric            uint32                 `json:"igp_metric,omitempty"`
	Prefix               string                 `json:"prefix,omitempty"`
	PrefixLen            int32                  `json:"prefix_len,omitempty"`
	IsPrepolicy          bool                   `json:"isprepolicy"`
	IsAdjRIBIn           bool                   `json:"is_adj_rib_in"`
	SRv6SID              []string               `json:"srv6_sid,omitempty"`
	SRv6EndpointBehavior *srv6.EndpointBehavior `json:"srv6_endpoint_behavior,omitempty"`
	SRv6BGPPeerNodeSID   *srv6.BGPPeerNodeSID   `json:"srv6_bgp_peer_node_sid,omitempty"`
	SRv6SIDStructure     *srv6.SIDStructure     `json:"srv6_sid_structure,omitempty"`
}

// EVPNPrefix defines the structure of EVPN message
type EVPNPrefix struct {
	Key            string              `json:"_key,omitempty"`
	ID             string              `json:"_id,omitempty"`
	Rev            string              `json:"_rev,omitempty"`
	Action         string              `json:"action,omitempty"` // Action can be "add" or "del"
	Sequence       int                 `json:"sequence,omitempty"`
	Hash           string              `json:"hash,omitempty"`
	RouterHash     string              `json:"router_hash,omitempty"`
	RouterIP       string              `json:"router_ip,omitempty"`
	BaseAttributes *bgp.BaseAttributes `json:"base_attrs,omitempty"`
	PeerHash       string              `json:"peer_hash,omitempty"`
	PeerIP         string              `json:"peer_ip,omitempty"`
	PeerASN        int32               `json:"peer_asn,omitempty"`
	Timestamp      string              `json:"timestamp,omitempty"`
	IsIPv4         bool                `json:"is_ipv4"`
	OriginAS       int32               `json:"origin_as,omitempty"`
	Nexthop        string              `json:"nexthop,omitempty"`
	ClusterList    string              `json:"cluster_list,omitempty"`
	IsNexthopIPv4  bool                `json:"is_nexthop_ipv4"`
	PathID         int32               `json:"path_id,omitempty"`
	Labels         []uint32            `json:"labels,omitempty"`
	IsPrepolicy    bool                `json:"isprepolicy"`
	IsAdjRIBIn     bool                `json:"is_adj_rib_in"`
	VPNRD          string              `json:"vpn_rd,omitempty"`
	VPNRDType      uint16              `json:"vpn_rd_type"`
	ESI            string              `json:"eth_segment_id,omitempty"`
	EthTag         []byte              `json:"eth_tag,omitempty"`
	IPAddress      string              `json:"ip_address,omitempty"`
	IPLength       uint8               `json:"ip_len,omitempty"`
	GWAddress      string              `json:"gw_address,omitempty"`
	MAC            string              `json:"mac,omitempty"`
	MACLength      uint8               `json:"mac_len,omitempty"`
	RouteType      uint8               `json:"route_type,omitempty"`
	// TODO Type 3 carries nlri 22
	// https://tools.ietf.org/html/rfc6514
	// Add to the message
}
