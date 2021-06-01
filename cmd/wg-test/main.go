package main

import (
	"context"
	"fmt"
	"os"

	"github.com/vishvananda/netlink"
)

func main() {
	ctx := context.Background()
	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("LinkList failed: %w", err)
	}

	for _, link := range links {
		fmt.Printf("%s %s\n", link.Attrs().Name, link.Type())
		switch link.Type() {
		case "wireguard":
			wg := link.(*netlink.Wireguard)
			fmt.Printf("  %+v\n", wg)
			result, err := netlink.WireguardGetDevice(wg.Name)
			if err != nil {
				return fmt.Errorf("WireguardGetDevice(%q) failed: %w", wg.Name, err)
			}
			fmt.Printf("      %+v\n", result)
			for _, peer := range result.Peers {
				fmt.Printf("          %+v\n", peer)
				for _, allowedIP := range peer.AllowedIPs {
					fmt.Printf("            AllowedIP: %s\n", allowedIP.String())
				}
			}

			privateKey, err := netlink.ParseWireguardPrivateKey(os.Getenv("WG_PRIVATE_KEY"))
			if err != nil {
				return fmt.Errorf("parsePrivateKey failed: %w", err)
			}

			peer := netlink.WireguardPeer{}
			if err := peer.SetPublicKey("EPLh6pVel06dND8cE4Prix9GP4hGLYNhQhn5mSN2yzM="); err != nil {
				return err
			}
			if err := peer.SetEndpoint("86.106.143.236:51820"); err != nil {
				return err
			}
			if err := peer.AddAllowedIP("0.0.0.0/0"); err != nil {
				return err
			}
			if err := peer.AddAllowedIP("::/0"); err != nil {
				return err
			}
			peers := []netlink.WireguardPeer{peer}
			if err := netlink.WireguardSetDevice(wg.Name, true, &netlink.WireguardConfiguration{
				PrivateKey: privateKey,
				ListenPort: 0, // Auto-select
				FwMark:     0, // Clear any existing fwmark
				Peers:      peers,
			}); err != nil {
				return fmt.Errorf("WireguardSetDevice(%q) failed: %w", wg.Name, err)
			}
		}
	}

	return nil
}
