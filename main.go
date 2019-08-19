package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	apiKey = os.Getenv("IP_API_KEY")
)

// IPDetails contain details about the IP addr
type IPDetails struct {
	IP           net.IP `json:"ip"`
	Country      string `json:"country_name"`
	Continent    string `json:"continent_name"`
	State        string `json:"state_prov"`
	City         string `json:"city"`
	ISP          string `json:"isp"`
	Organization string `json:"organization"`
}

// getIPAddr uses shell commands to get the IP address of a device
func getIPv4Addr() (net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Panicln("Could not get interface addrs")
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			v4 := ipnet.IP.To4()
			// skip ip6 and loopback addr
			if v4 == nil || v4[0] == 127 {
				continue
			}
			return v4, nil
		}

	}
	return nil, fmt.Errorf("Could not find local IP address")
}

// listenIncoming listens for incoming packets and prints out IPv4 Layer data
func listenIncoming(iface string, ip net.IP, count int) {
	var handle *pcap.Handle
	var err error
	known := make(map[string]IPDetails)

	// create a handle to interface iface
	if handle, err = pcap.OpenLive(iface, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	}

	// create a packet source to listen to handle
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	i := 0
	for i < count {
		var packet gopacket.Packet
		packet = <-packetSource.Packets()
		// handle packet and look up destination iP information
		err = handlePacket(packet, known)
		if err != nil {
			log.Printf("Could not handle packet: %v", err)
		}
		i++
	}
}

// getIPDetails finds geolocation information for an IP from ipgeolocation.io
// if it finds an IP it's already retrieved information for it won't call the API again
func getIPDetails(ip net.IP, known map[string]IPDetails) (IPDetails, error) {
	var ipdetail IPDetails

	// if the details have already been stored, return them right away
	if ipdetail, ok := known[ip.String()]; ok {
		return ipdetail, nil
	}
	url := fmt.Sprintf("https://api.ipgeolocation.io/ipgeo?apiKey=%s&fields=continent_name,country_name,state_prov,city,isp,organization&ip=%s", apiKey, ip.String())
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("error calling API %s: %v\n", url, err)
		return ipdetail, err
	}
	// marshall json response into ipdetails struct
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("error reading response body: %v", err)
	}

	err = json.Unmarshal(body, &ipdetail)
	if err != nil {
		log.Printf("Could not unmarshal json: %v", err)
		return ipdetail, err
	}
	known[ip.String()] = ipdetail

	return ipdetail, nil
}

// handlePacket gets IP details for the sender of the packet
func handlePacket(p gopacket.Packet, k map[string]IPDetails) error {
	ip, err := getIPv4Addr()
	if err != nil {
		log.Printf("Could not retrieve local IP addr: %v", err)
		return err
	}

	if ipv4Layer := p.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)
		//TODO: Figure out how to exclude packets from private network 192.168*, etc.

		if ipv4.DstIP.Equal(ip) {
			if isPrivate(ipv4.SrcIP) {
				// log.Printf("%s is private, moving on", ipv4.SrcIP)
				return nil
			}
			ipdetails, err := getIPDetails(ipv4.SrcIP, k)
			if err != nil {
				log.Printf("Could not retrieve IP addr details for %s: %v", ipv4.SrcIP, err)
				return err
			}
			fmt.Println(ipdetails)
		}
	}
	return nil
}

func isPrivate(ip net.IP) bool {
	private := false

	privateRanges := []string{
		"172.16.0.0/12",
		"10.0.0.0/8",
		"192.168.0.0/16",
	}
	for _, cidr := range privateRanges {
		_, subnet, _ := net.ParseCIDR(cidr)
		if subnet.Contains(ip) {
			private = true
		}
	}
	return private
}

func main() {
	localIP, err := getIPv4Addr()
	log.Printf("Started listener, local ip is %v", localIP)
	if err != nil {
		log.Fatalf("Could not get local ip address: %v", err)
	}

	netInterface := os.Args[1]
	// listen for incoming packets until the program is interrupted
	listenIncoming(netInterface, localIP, 200)
}
