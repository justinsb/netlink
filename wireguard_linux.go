package netlink

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// WireguardGetDevice dumps a specific wireguard device.
func WireguardGetDevice(name string) (*WireguardConfiguration, error) {
	return pkgHandle.WireguardGetDevice(name)
}

// WireguardSetDevice configures a specific wireguard device.
func WireguardSetDevice(name string, replacePeers bool, conf *WireguardConfiguration) error {
	return pkgHandle.WireguardSetDevice(name, replacePeers, conf)
}

func (h *Handle) WireguardGetDevice(name string) (*WireguardConfiguration, error) {
	wgFamily, err := GenlFamilyGet(nl.WG_GENL_NAME)
	if err != nil {
		return nil, fmt.Errorf("GenlFamilyGet(%q) failed: %w", nl.WG_GENL_NAME, err)
	}

	msg := &nl.Genlmsg{
		Command: nl.WG_CMD_GET_DEVICE,
		Version: nl.WG_GENL_VERSION,
	}
	req := h.newNetlinkRequest(int(wgFamily.ID), unix.NLM_F_DUMP|unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	req.AddData(msg)
	req.AddData(nl.NewRtAttr(nl.WGDEVICE_A_IFNAME, nl.ZeroTerminated(name)))
	msgs, err := req.Execute(unix.NETLINK_GENERIC, 0)
	if err != nil {
		return nil, fmt.Errorf("netlink.Execute(WG_CMD_GET_DEVICE) failed: %w", err)
	}

	result := wgUnserialize(msgs)
	return &result, nil
}

func (h *Handle) WireguardSetDevice(name string, replacePeers bool, conf *WireguardConfiguration) error {
	wgFamily, err := GenlFamilyGet(nl.WG_GENL_NAME)
	if err != nil {
		return fmt.Errorf("GenlFamilyGet(%q) failed: %w", nl.WG_GENL_NAME, err)
	}

	msg := &nl.Genlmsg{
		Command: nl.WG_CMD_SET_DEVICE,
		Version: nl.WG_GENL_VERSION,
	}
	req := h.newNetlinkRequest(int(wgFamily.ID), unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	req.AddData(msg)
	req.AddData(nl.NewRtAttr(nl.WGDEVICE_A_IFNAME, nl.ZeroTerminated(name)))

	var flags uint32
	if replacePeers {
		flags |= nl.WGDEVICE_F_REPLACE_PEERS
	}
	req.AddData(nl.NewRtAttr(nl.WGDEVICE_A_FLAGS, nl.Uint32Attr(flags)))

	req.AddData(nl.NewRtAttr(nl.WGDEVICE_A_PRIVATE_KEY, conf.PrivateKey))
	req.AddData(nl.NewRtAttr(nl.WGDEVICE_A_LISTEN_PORT, nl.Uint16Attr(conf.ListenPort)))
	req.AddData(nl.NewRtAttr(nl.WGDEVICE_A_FWMARK, nl.Uint32Attr(conf.FwMark)))

	peerData, err := serializePeers(conf.Peers)
	if err != nil {
		return err
	}
	req.AddData(peerData)

	msgs, err := req.Execute(unix.NETLINK_GENERIC, 0)
	if err != nil {
		return fmt.Errorf("netlink.Execute(WG_CMD_SET_DEVICE) failed: %w", err)
	}

	log.Printf("WG_CMD_SET_DEVICE returned %+v", msgs)
	return nil
}

func wgUnserialize(msgs [][]byte) (result WireguardConfiguration) {
	for _, msg := range msgs {
		result.unserialize(msg)
	}
	return result
}

type WgPrivateKey []byte

func (k WgPrivateKey) String() string {
	return base64.StdEncoding.EncodeToString(k)
}

func ParseWireguardPrivateKey(k string) (WgPrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(k)
	if err != nil {
		return nil, fmt.Errorf("could not parse private key (not valid base64)")
	}
	if len(b) != nl.WG_KEY_LEN {
		return nil, fmt.Errorf("private key did not have expected length %d", nl.WG_KEY_LEN)
	}
	return WgPrivateKey(b), nil
}

type WgPublicKey []byte

func (k WgPublicKey) String() string {
	return base64.StdEncoding.EncodeToString(k)
}

func ParseWireguardPublicKey(k string) (WgPublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(k)
	if err != nil {
		return nil, fmt.Errorf("could not parse public key (not valid base64)")
	}
	if len(b) != nl.WG_KEY_LEN {
		return nil, fmt.Errorf("public key %q did not have expected length %d", k, nl.WG_KEY_LEN)
	}
	return WgPublicKey(b), nil
}

type WireguardConfiguration struct {
	Nfgenmsg *nl.Nfgenmsg

	IfIndex uint32
	IfName  string

	PrivateKey WgPrivateKey
	PublicKey  WgPublicKey

	ListenPort uint16
	FwMark     uint32

	Peers []WireguardPeer
}

type WireguardPeer struct {
	PublicKey                    WgPublicKey
	PersistentKeepAliveInterface uint16

	ProtocolVersion uint32

	RxBytes uint64
	TxBytes uint64

	LastHandshakeTime time.Time

	AllowedIPs []net.IPNet

	Endpoint WireguardSockAddr
}

type WireguardSockAddr struct {
	IP   net.IP
	Port uint16
}

func (result *WireguardConfiguration) unserialize(msg []byte) {
	result.Nfgenmsg = nl.DeserializeNfgenmsg(msg)

	for attr := range nl.ParseAttributes(msg[4:]) {
		switch attr.Type {
		case nl.WGDEVICE_A_IFINDEX:
			result.IfIndex = native.Uint32(attr.Value)
		case nl.WGDEVICE_A_IFNAME:
			result.IfName = nl.BytesToString(attr.Value)
		case nl.WGDEVICE_A_PRIVATE_KEY:
			result.PrivateKey = attr.Value
		case nl.WGDEVICE_A_PUBLIC_KEY:
			result.PublicKey = attr.Value
		case nl.WGDEVICE_A_LISTEN_PORT:
			result.ListenPort = native.Uint16(attr.Value)
		case nl.WGDEVICE_A_FWMARK:
			result.FwMark = native.Uint32(attr.Value)
		case nl.WGDEVICE_A_PEERS | nl.NLA_F_NESTED:
			peers := parsePeers(attr.Value)
			result.Peers = append(result.Peers, peers...)
		default:
			log.Printf("unknown wireguard attribute from kernel: %+v %v", attr, attr.Type&nl.NLA_TYPE_MASK)
		}
	}
}

func parsePeers(msg []byte) (peers []WireguardPeer) {
	attrs := nl.ParseAttributes(msg)
	for attr := range attrs {
		switch attr.Type {
		case 0 | nl.NLA_F_NESTED:
			peer := parsePeer(attr.Value)
			peers = append(peers, peer)

		default:
			log.Printf("unknown wireguard peers attribute from kernel: %+v %v", attr, attr.Type&nl.NLA_TYPE_MASK)
		}
	}
	return
}

func parsePeer(msg []byte) (peer WireguardPeer) {
	attrs := nl.ParseAttributes(msg)
	for attr := range attrs {
		switch attr.Type {
		case nl.WGPEER_A_PUBLIC_KEY:
			peer.PublicKey = attr.Value
		case nl.WGPEER_A_PRESHARED_KEY:
			// Skip
		case nl.WGPEER_A_ENDPOINT:
			peer.Endpoint = parseSockAddr(attr.Value)
		case nl.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL:
			peer.PersistentKeepAliveInterface = native.Uint16(attr.Value)
		case nl.WGPEER_A_RX_BYTES:
			peer.RxBytes = native.Uint64(attr.Value)
		case nl.WGPEER_A_TX_BYTES:
			peer.TxBytes = native.Uint64(attr.Value)
		case nl.WGPEER_A_PROTOCOL_VERSION:
			peer.ProtocolVersion = native.Uint32(attr.Value)
		case nl.WGPEER_A_LAST_HANDSHAKE_TIME:
			if len(attr.Value) == 16 {
				sec := native.Uint64(attr.Value[0:8])
				nsec := native.Uint64(attr.Value[8:16])
				peer.LastHandshakeTime = time.Unix(int64(sec), int64(nsec))
			} else {
				log.Printf("unknown format for WGPEER_A_LAST_HANDSHAKE_TIME: %+v", attr)
			}
		case nl.WGPEER_A_ALLOWEDIPS | nl.NLA_F_NESTED:
			peer.AllowedIPs = parseAllowedIPs(attr.Value)
		default:
			log.Printf("unknown wireguard peer attribute from kernel: %+v %v", attr, attr.Type&nl.NLA_TYPE_MASK)
		}
	}
	return
}

func parseAllowedIPs(msg []byte) (cidrs []net.IPNet) {
	attrs := nl.ParseAttributes(msg)
	for attr := range attrs {
		switch attr.Type {
		case 0 | nl.NLA_F_NESTED:
			cidr := parseAllowedIP(attr.Value)
			cidrs = append(cidrs, cidr)

		default:
			log.Printf("unknown wireguard allowed-ip-list attribute from kernel: %+v %v", attr, attr.Type&nl.NLA_TYPE_MASK)
		}
	}
	return
}

func parseAllowedIP(msg []byte) (cidr net.IPNet) {
	//var family uint16
	var ipaddr []byte
	var mask int
	attrs := nl.ParseAttributes(msg)
	for attr := range attrs {
		switch attr.Type {
		case nl.WGALLOWEDIP_A_FAMILY:
			//family = native.Uint16(attr.Value)
		case nl.WGALLOWEDIP_A_IPADDR:
			ipaddr = attr.Value
		case nl.WGALLOWEDIP_A_CIDR_MASK:
			mask = int(attr.Value[0])
		default:
			log.Printf("unknown wireguard allowed-ip attribute from kernel: %+v %v", attr, attr.Type&nl.NLA_TYPE_MASK)
		}
	}

	cidr.IP = net.IP(ipaddr)
	cidr.Mask = net.CIDRMask(mask, len(ipaddr)*8)

	return
}

func parseSockAddr(msg []byte) (addr WireguardSockAddr) {
	family := native.Uint16(msg[0:2])
	if family == unix.AF_INET {
		addr.Port = binary.BigEndian.Uint16(msg[2:4])
		addr.IP = net.IP(msg[4:8])
		return
	}

	log.Printf("unknown sock addr family %v in %v", family, msg)
	return
}

func (a *WireguardSockAddr) serialize() ([]byte, error) {
	if ipv4 := a.IP.To4(); ipv4 != nil {
		b := make([]byte, 16, 16)
		native.PutUint16(b[0:2], unix.AF_INET)
		binary.BigEndian.PutUint16(b[2:4], a.Port)
		copy(b[4:8], ipv4)
		return b, nil
	}

	return nil, fmt.Errorf("unhandled IP in %+v", a)
}

func serializePeers(peers []WireguardPeer) (*nl.RtAttr, error) {
	data := nl.NewRtAttr(nl.WGDEVICE_A_PEERS|int(nl.NLA_F_NESTED), nil)

	for _, peer := range peers {
		peerData := nl.NewRtAttr(int(nl.NLA_F_NESTED), nil)
		if err := peer.writeTo(peerData); err != nil {
			return nil, err
		}
		data.AddChild(peerData)
	}
	return data, nil
}

func (p *WireguardPeer) writeTo(attr *nl.RtAttr) error {
	attr.AddRtAttr(nl.WGPEER_A_PUBLIC_KEY, p.PublicKey)

	var flags uint32
	flags |= nl.WGPEER_F_REPLACE_ALLOWEDIPS
	attr.AddRtAttr(nl.WGPEER_A_FLAGS, nl.Uint32Attr(flags))

	endpointData, err := p.Endpoint.serialize()
	if err != nil {
		return err
	}
	attr.AddRtAttr(nl.WGPEER_A_ENDPOINT, endpointData)

	allowedIPs := nl.NewRtAttr(nl.WGPEER_A_ALLOWEDIPS|int(nl.NLA_F_NESTED), nil)

	for _, allowedIP := range p.AllowedIPs {
		allowedIPData := nl.NewRtAttr(int(nl.NLA_F_NESTED), nil)

		ipv4 := allowedIP.IP.To4()
		if ipv4 != nil {
			cidrMaskLength, _ := allowedIP.Mask.Size()
			allowedIPData.AddRtAttr(nl.WGALLOWEDIP_A_FAMILY, nl.Uint16Attr(unix.AF_INET))
			allowedIPData.AddRtAttr(nl.WGALLOWEDIP_A_CIDR_MASK, nl.Uint8Attr(uint8(cidrMaskLength)))
			allowedIPData.AddRtAttr(nl.WGALLOWEDIP_A_IPADDR, ipv4)
			allowedIPs.AddChild(allowedIPData)
			continue
		}

		ipv6 := allowedIP.IP.To16()
		if ipv6 != nil {
			cidrMaskLength, _ := allowedIP.Mask.Size()
			allowedIPData.AddRtAttr(nl.WGALLOWEDIP_A_FAMILY, nl.Uint16Attr(unix.AF_INET6))
			allowedIPData.AddRtAttr(nl.WGALLOWEDIP_A_CIDR_MASK, nl.Uint8Attr(uint8(cidrMaskLength)))
			allowedIPData.AddRtAttr(nl.WGALLOWEDIP_A_IPADDR, ipv6)
			allowedIPs.AddChild(allowedIPData)
			continue
		}

		return fmt.Errorf("unhandled ip address type %v", allowedIP.IP)
	}

	attr.AddChild(allowedIPs)

	return nil
}

func (p *WireguardPeer) SetPublicKey(key string) error {
	publicKey, err := ParseWireguardPublicKey(key)
	if err != nil {
		return fmt.Errorf("ParseWireguardPublicKey(%q) failed: %w", key, err)
	}
	p.PublicKey = publicKey
	return nil
}

func (p *WireguardPeer) SetEndpoint(endpoint string) error {
	host, portString, err := net.SplitHostPort(endpoint)
	if err != nil {
		return fmt.Errorf("SplitHostPort(%q) failed: %w", endpoint, err)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("LookupIP(%q) failed: %w", host, err)
	}
	ip := ips[0]
	port, err := net.LookupPort("tcp", portString)
	if err != nil {
		return fmt.Errorf("LookupPort(%q) failed: %w", portString, err)
	}
	p.Endpoint = WireguardSockAddr{
		IP:   ip,
		Port: uint16(port),
	}
	return nil
}

func (p *WireguardPeer) AddAllowedIP(cidr string) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("ParseCIDR(%q) failed: %w", cidr, err)
	}
	p.AllowedIPs = append(p.AllowedIPs, *ipnet)
	return nil
}
