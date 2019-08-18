package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// getIPAddr uses shell commands to get the IP address of a device
func getIPv4Addr() (net.IP, error) {
	// TODO This works but only gets one IPv4 addr that isn't 127.0.0.1
	// this seems really fragile and bug prone
	cmd := "ifconfig | grep \"inet \" | grep -v 127.0.0.1 | cut -d\\  -f2"
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		return nil, fmt.Errorf("Cannot run bash command: %v - %v", cmd, err)
	}

	return net.ParseIP(strings.TrimSpace(string(out))), nil
}

// listenIncoming listens for incoming packets and prints out IPv4 Layer data
func listenIncoming(iface string, ip net.IP) {
	var handle *pcap.Handle
	var err error

	// create a handle to interface iface
	if handle, err = pcap.OpenLive(iface, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	}

	// create a packet source to listen to handle
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
			ipv4 := ipv4Layer.(*layers.IPv4)

			if ipv4.DstIP.Equal(ip) {
				srcIP := ipv4.SrcIP.String()

				hostName, err := net.LookupAddr(srcIP)
				if err != nil {
					log.Printf("Could not lookup addr %s: %v", srcIP, err)
					continue
				}
				fmt.Printf("Received packet from %s\n", hostName)
			}
		}
	}
}

func main() {
	localIP, err := getIPv4Addr()
	if err != nil {
		log.Fatalf("Could not get ip addr: %v", err)
	}

	netInterface := os.Args[1]
	// listen for incoming packets until the program is interrupted
	listenIncoming(netInterface, localIP)
}
