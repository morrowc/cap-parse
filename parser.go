// Parse a tcpdump capture file, output a json file of statistics.
package main

import (
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/google/gopacket"
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
	for packet := range packetSource.Packets() {
		saddr := packet.NetworkLayer().SrcIP
		daddr := packet.NetworkLayer().DstIP
		proto := packet.NetworkLayer().Protocol
		data.add(proto)
		afi := "inet"
		if strings.Contains(saddr, ":") {
			afi = "inet6"
		}
		data.add(afi)
		switch {
		case afi == 4 && daddr == "255.255.255.255":
			data.add("bcast")
		case afi == 4 && strings.HasPrefix(daddr, "224."):
			data.add("mcast")
		case afi == 6 && strings.HasPrefix(daddr, "ff02::"):
			data.add("mcast")
		}
	}
	fmt.Printf("Stats: %+v\n", data)
}
