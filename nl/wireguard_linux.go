package nl

// All the following constants are coming from:
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/wireguard.h
// That file also includes a nice description of the commands.

const (
	WG_CMD_GET_DEVICE = 0
	WG_CMD_SET_DEVICE = 1
)

const WG_GENL_NAME = "wireguard"
const WG_GENL_VERSION = 1

const WG_KEY_LEN = 32

const (
	WGDEVICE_A_UNSPEC      = 0
	WGDEVICE_A_IFINDEX     = 1
	WGDEVICE_A_IFNAME      = 2
	WGDEVICE_A_PRIVATE_KEY = 3
	WGDEVICE_A_PUBLIC_KEY  = 4
	WGDEVICE_A_FLAGS       = 5
	WGDEVICE_A_LISTEN_PORT = 6
	WGDEVICE_A_FWMARK      = 7
	WGDEVICE_A_PEERS       = 8
)

const (
	WGPEER_A_UNSPEC                        = 0
	WGPEER_A_PUBLIC_KEY                    = 1
	WGPEER_A_PRESHARED_KEY                 = 2
	WGPEER_A_FLAGS                         = 3
	WGPEER_A_ENDPOINT                      = 4
	WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL = 5
	WGPEER_A_LAST_HANDSHAKE_TIME           = 6
	WGPEER_A_RX_BYTES                      = 7
	WGPEER_A_TX_BYTES                      = 8
	WGPEER_A_ALLOWEDIPS                    = 9
	WGPEER_A_PROTOCOL_VERSION              = 10
)

const (
	WGALLOWEDIP_A_UNSPEC    = 0
	WGALLOWEDIP_A_FAMILY    = 1
	WGALLOWEDIP_A_IPADDR    = 2
	WGALLOWEDIP_A_CIDR_MASK = 3
)

const (
	WGDEVICE_F_REPLACE_PEERS = 1
)

const (
	WGPEER_F_REMOVE_ME          = 1
	WGPEER_F_REPLACE_ALLOWEDIPS = 2
	WGPEER_F_UPDATE_ONLY        = 4
)
