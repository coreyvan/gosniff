package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"

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
func listenIncoming(iface string, ip net.IP, count int) {
	var handle *pcap.Handle
	var err error

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
		err = handlePacket(packet)
		if err != nil {
			log.Printf("Could not handle packet: %v", err)
		}
		i++
	}
}

func getIPDetails(ip net.IP) (IPDetails, error) {
	var ipdetail IPDetails
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

	return ipdetail, nil
}

func handlePacket(p gopacket.Packet) error {
	ip, err := getIPv4Addr()
	if err != nil {
		log.Printf("Could not retrieve local IP addr: %v", err)
		return err
	}
	log.Printf("Handling packet, ip is %v\n", ip)
	if ipv4Layer := p.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)
		//TODO: Figure out how to exclude packets from private network 192.168*, etc.
		if ipv4.DstIP.Equal(ip) {
			ipdetails, err := getIPDetails(ipv4.SrcIP)
			if err != nil {
				log.Printf("Could not retrieve IP addr details for %s: %v", ipv4.SrcIP, err)
				return err
			}
			fmt.Println(ipdetails)
		}
	}
	return nil
}

func main() {
	log.Printf("Started listening, api key = %v", apiKey)
	localIP, err := getIPv4Addr()
	if err != nil {
		log.Fatalf("Could not get ip addr: %v", err)
	}

	netInterface := os.Args[1]
	// listen for incoming packets until the program is interrupted
	listenIncoming(netInterface, localIP, 10)
}
