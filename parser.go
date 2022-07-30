// Parse a tcpdump capture file, output a json file of statistics.
package main

import (
	"flag"
	"fmt"

	"github.com/gidoBOSSftw5731/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	input = flag.String("input", "", "Capture file to parse")
)

type stats struct {
	data map[string]int64
}

func newStats() *stats {
	s := make(map[string]int64)
	return &stats{data: s}
}

func (s *stats) add(w string) {
	s.data[w]++
}

func main() {
	flag.Parse()

	handle, err := pcap.OpenOffline(*input)
	if err != nil {
		log.Fatalf("failed opening input file: %v", err)
	}
	defer handle.Close()

	data := newStats()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	// Following examples from:
	//   https://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket
	for packet := range packetSource.Packets() {
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethLayer != nil {
			// TODO(morrowc): Collect stats on types of ethernet source/destionations.
			var ePacket *layers.Ethernet
			var ok bool
			if ePacket, ok = ethLayer.(*layers.Ethernet); !ok {
				log.Infof("failed to decode the ethernet packet contents: %v", err)
			}
			sMac := ePacket.SrcMAC
			dMac := ePacket.DstMAC
			eType := ePacket.EthernetType
			switch eType {
			case layers.EthernetTypeARP:
				fmt.Printf("Ether data: %v %v\n", sMac, dMac)
			case layers.EthernetTypeIPv4:
				fmt.Println("IPv4 decode here")
			case layers.EthernetTypeIPv6:
				fmt.Println("IPv6 decode here")
			}
		}
		/*
			saddr := packet.TransportLayer().SrcIP
			daddr := packet.TransportLayer().DstIP
			proto := packet.TransportLayer().Protocol
			data.add(proto)
			afi := "inet"
			if strings.Contains(saddr, ":") {
				afi = "inet6"
			}
			data.add(afi)
			switch {
			case afi == "inet" && daddr == "255.255.255.255":
				data.add("bcast")
			case afi == "inet" && strings.HasPrefix(daddr, "224."):
				data.add("mcast")
			case afi == "inet6" && strings.HasPrefix(daddr, "ff02::"):
				data.add("mcast")
		*/
	}
	fmt.Printf("Stats: %+v\n", data)
}
