/*

ptp_message_count

== DESCRIPTION ==

A command-line tool, written in Go, to monitor and diagnose PTP traffic
on an IP network. It counts messages received over a given time period,
displaying a summary of each type and the source addresses sending them.

== USAGE ==

Example:
  ./ptp_message_count -I eth0

A full description of command-line options will be given by running:
  ./ptp_message_count -h

As this program relies on packet capture from privileged ports, it must
be granted elevated permissions, or be run as the root user, otherwise
'permission denied' errors will result.

== AUTHOR ==

Nick Prater <info@npbroadcast.com>

== LICENCE ==

Copyright (C) 2025 NP Broadcast Limited

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see <https://www.gnu.org/licenses/>.

*/

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/ipv4"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

const VERSION = "1.3"

// PTP multicast addresses
// alt1, alt2 and alt3 addresses are used by PTPv1 for alternate domains
var ptpAddresses = []string{
	"224.0.0.107", // Peer Delay Messages
	"224.0.1.129", // General Messages
	"224.0.1.130", // alt1
	"224.0.1.131", // alt2
	"224.0.1.132"} // alt3

// PTP ports
var ptpPorts = []int{
	319, // Event Messages
	320} // General Messages

/* PTP Message Types:
0: "Sync",
1: "Delay_Req",
2: "Pdelay_Req",
3: "Pdelay_Resp",
8: "Follow_Up",
9: "Delay_Resp",
10: "Pdelay_Resp_Follow_Up",
11: "Announce",
12: "Signalling",
13: "Management",
*/

type ptpAnnounce struct {
	p1                  uint8
	p2                  uint8
	grandmasterIdentity []byte
	stepsRemoved        uint16
}

func main() {

	// Command Line Arguments
	var (
		displayInterval      time.Duration
		filterDomain         int
		interfaceName        string
		maxSummaries         int
		packetFilter         string
		showAnnounceMessages bool
		showHelp             bool
		showVersion          bool
		summariseSource      bool
		v1only               bool
		v2only               bool
	)
	flag.BoolVar(&showAnnounceMessages, "a", false, "Display announce messages")
	flag.IntVar(&maxSummaries, "c", 0, "Stop after `count` summaries have been reported. Continues forever if a value of 0 is specified (default).")
	flag.IntVar(&filterDomain, "d", -1, "Only process messages for the specified PTP `domain` (0-255). All messages will be processed if a negative value is specified.")
	flag.BoolVar(&showHelp, "h", false, "Display usage summary and exit")
	flag.StringVar(&packetFilter, "F", "", "Apply an additional `BPF filter string` to input. For example `-F \"src 10.0.0.1\"` will process only messages from ip address 10.0.0.1")
	flag.StringVar(&interfaceName, "I", "", "Network `interface` from which to capture traffic [required]")
	flag.DurationVar(&displayInterval, "i", (5 * time.Second), "Time `interval` to capture for each summary report e.g. 1s, 5m, etc.")
	flag.BoolVar(&summariseSource, "s", false, "Summarise source of messages, ordered by IP address")
	flag.BoolVar(&showVersion, "V", false, "Display version and exit")
	flag.BoolVar(&v1only, "v1only", false, "Monitor only PTPv1 traffic")
	flag.BoolVar(&v2only, "v2only", false, "Monitor only PTPv2 traffic")
	flag.Parse()

	if showVersion {
		fmt.Printf("ptp_message_count %s\n", VERSION)
		os.Exit(0)
	}

	// Check mandatory arguments are provided
	if interfaceName == "" || showHelp {
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Locate specified interface
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		log.Fatalf("Failed to find interface %s: %v", interfaceName, err)
	}
	fmt.Printf("Monitoring PTP messages on network interface %s\n", interfaceName)
	fmt.Printf("Reporting summary statistics every %v\n", displayInterval)

	if v1only {
		fmt.Println("Listening only to PTPv1 messages")
	}
	if v2only {
		fmt.Println("Listening only to PTPv2 messages")
	}

	if filterDomain >= 0 {
		fmt.Printf("Listening only to messages for PTP domain %d\n", filterDomain)
	}

	// Subscribe to PTP traffic
	listeners := startListeners(iface)
	defer closeListeners(listeners)

	// Iitialise packet capture
	pcapHandle := startPacketCapture(interfaceName, packetFilter)
	defer stopPacketCapture(pcapHandle)
	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())

	// Variables to track PTP message counts and rates
	var (
		messageCount    = 0
		summaryCount    = 0
		startTime       = time.Now()
		lastDisplayTime = startTime
		messageTypes    = make(map[uint8]int)
		domainMessages  = make(map[uint8]int)
		sourceAddresses = make(map[string]int)
		announceSources = make(map[string]int)
		v1PacketCount   = 0
		v2PacketCount   = 0
	)

	fmt.Println("Press Ctrl+C to stop\n")

	// Process packets
	for packet := range packetSource.Packets() {
		// Check if packet contains UDP layer
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			applicationLayer := packet.ApplicationLayer()
			if applicationLayer != nil {
				payload := applicationLayer.Payload()
				// PTP message header is 34 bytes
				if len(payload) >= 34 {

					// PTP version is the second nibble of the second byte
					ptpVersion := (payload[1] & 0x0f)

					// PTP domain 5th byte of the header
					ptpDomain := payload[4]
					if (filterDomain >= 0) && (int(ptpDomain) != filterDomain) {
						continue
					}
					domainMessages[ptpDomain]++

					if (v1only && ptpVersion != 1) || (v2only && ptpVersion != 2) {
						continue
					}

					if ptpVersion == 1 {
						v1PacketCount++
					} else if ptpVersion == 2 {
						v2PacketCount++
					} else {
						fmt.Printf("Unexpected PTP version %d\n", ptpVersion)
					}

					// Extract source IP address
					var sourceAddress net.IP
					if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
						ip, _ := ipv4Layer.(*layers.IPv4)
						sourceAddress = ip.SrcIP
					} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
						ip, _ := ipv6Layer.(*layers.IPv6)
						sourceAddress = ip.SrcIP
					}

					// Message type is the second nibble of the first byte
					msgType := (payload[0] & 0x0f)
					messageTypes[msgType]++
					messageCount++
					sourceAddresses[sourceAddress.String()]++

					if msgType == 11 {
						announceSources[sourceAddress.String()]++
						if showAnnounceMessages {
							announce, err := decodeAnnounceMessage(payload)
							if err == nil {
								fmt.Printf("PTPv%d announce message from %-15v  GM:%x p1:%-3d p2:%-3d steps:%-2d\n",
									ptpVersion,
									sourceAddress,
									announce.grandmasterIdentity,
									announce.p1,
									announce.p2,
									announce.stepsRemoved)
							} else {
								fmt.Println(err)
							}
						}
					}
				} else {
					fmt.Printf("WARNING: Invalid PTP message. Expected at least 34 bytes but only %d bytes received\n", len(payload))
				}
			}

			// Display rate statistics every displayInterval
			currentTime := time.Now()
			if timeElapsed := currentTime.Sub(lastDisplayTime); timeElapsed >= displayInterval {
				summaryCount++
				period := float64(timeElapsed.Seconds())

				fmt.Printf("PTP messages: %4d, %7.2f msgs/sec\n", messageCount, (float64(messageCount) / period))
				fmt.Printf(" v1 messages: %4d, %7.2f msgs/sec\n", v1PacketCount, (float64(v1PacketCount) / period))
				fmt.Printf(" v2 messages: %4d, %7.2f msgs/sec\n", v2PacketCount, (float64(v2PacketCount) / period))

				summariseType(messageTypes, period)
				printDomains(domainMessages, period)
				printAnnounceSources(announceSources)

				if summariseSource {
					printSourceSummary(sourceAddresses)
				}

				lastDisplayTime = currentTime
				messageCount = 0
				v1PacketCount = 0
				v2PacketCount = 0
				announceSources = make(map[string]int)
				domainMessages = make(map[uint8]int)
				fmt.Println()

				if maxSummaries > 0 && summaryCount >= maxSummaries {
					fmt.Printf("Finished reporting after %d summaries\n", summaryCount)
					os.Exit(0)
				}
			}
		}
	}
}

func startListeners(iface *net.Interface) []*ipv4.PacketConn {
	listeners := createListeners(ptpPorts)

	// Join multicast groups in each listener, so that traffic flows for us to capture
	for _, address := range ptpAddresses {
		ip := net.ParseIP(address)

		for index, listener := range listeners {
			err := listener.JoinGroup(iface, &net.UDPAddr{IP: ip})
			if err != nil {
				log.Fatalf("Failed to join multicast group %v on port %v: %v", ip, ptpPorts[index], err)
			}
		}
	}

	fmt.Printf(
		"Subscribed to multicast groups %s on ports %s\n",
		strings.Join(ptpAddresses, ", "),
		strings.Join(intSliceToStringSlice(ptpPorts), ", "))

	return listeners
}

func createListeners(ports []int) []*ipv4.PacketConn {
	listeners := make([]*ipv4.PacketConn, 0, len(ports))

	for _, port := range ports {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
		if err != nil {
			log.Fatalf("Failed to create UDP listener for port %v : %v", port, err)
		}

		listener := ipv4.NewPacketConn(conn)
		listeners = append(listeners, listener)
	}

	return listeners
}

func closeListeners(listeners []*ipv4.PacketConn) {
	for _, listener := range listeners {
		listener.Close()
	}
}

func startPacketCapture(interfaceName string, packetFilter string) *pcap.Handle {
	pcapHandle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	filterString := fmt.Sprintf("udp and (port %s) and (host %s)",
		strings.Join(intSliceToStringSlice(ptpPorts), " or port "),
		strings.Join(ptpAddresses, " or host "))
	if len(packetFilter) > 0 {
		fmt.Printf("Applying additional BPF filter: %s\n", packetFilter)
		filterString = fmt.Sprintf("%s and (%s)", filterString, packetFilter)
	}

	err = pcapHandle.SetBPFFilter(filterString)
	if err != nil {
		log.Println(err)
		log.Fatalf("filter string: \"%s\"", filterString)
	}

	return pcapHandle
}

func stopPacketCapture(pcapHandle *pcap.Handle) {
	pcapHandle.Close()
}

func intSliceToStringSlice(intSlice []int) []string {
	stringSlice := make([]string, 0, len(intSlice))
	for _, intValue := range intSlice {
		stringValue := fmt.Sprintf("%d", intValue)
		stringSlice = append(stringSlice, stringValue)
	}
	return stringSlice
}

func summariseType(messageTypes map[uint8]int, period float64) {
	fmt.Println("Message type:")

	keys := make([]uint8, 0, len(messageTypes))
	for k := range messageTypes {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})

	for _, msgType := range keys {
		typeName := getPTPMessageTypeName(msgType)
		count := messageTypes[msgType]
		fmt.Printf("  Type %2d : %-10s : %5d messages, %6.2f msgs/sec\n", msgType, typeName, count, (float64(count) / period))
		messageTypes[msgType] = 0
	}
}

func printDomains(domainMessages map[uint8]int, period float64) {
	fmt.Println("PTP Domains:")

	keys := make([]uint8, 0, len(domainMessages))
	for k := range domainMessages {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})

	for _, domain := range keys {
		count := domainMessages[domain]
		fmt.Printf("  Domain %3d : %5d messages, %6.2f msgs/sec\n", domain, count, (float64(count) / period))
	}
}

func printAnnounceSources(announceSources map[string]int) {
	if len(announceSources) == 0 {
		return
	}

	fmt.Println("Announce messages received from:")
	keys := make([]string, 0, len(announceSources))
	for k := range announceSources {
		keys = append(keys, k)
	}

	sort.Slice(keys, func(i, j int) bool {
		iIP := net.ParseIP(keys[i])
		jIP := net.ParseIP(keys[j])
		return bytes.Compare(iIP, jIP) < 0
	})

	for _, address := range keys {
		fmt.Printf("  %s\n", address)
	}
}

func printSourceSummary(sourceAddresses map[string]int) {
	fmt.Println("Message source:")

	addressKeys := make([]string, 0, len(sourceAddresses))
	for k := range sourceAddresses {
		addressKeys = append(addressKeys, k)
	}

	sort.Slice(addressKeys, func(i, j int) bool {
		iIP := net.ParseIP(addressKeys[i])
		jIP := net.ParseIP(addressKeys[j])
		return bytes.Compare(iIP, jIP) < 0
	})

	for _, address := range addressKeys {
		count := sourceAddresses[address]
		if count == 0 {
			continue
		}
		fmt.Printf("  %-15s : %4d messages\n", address, count)
		sourceAddresses[address] = 0
	}
}

func decodeAnnounceMessage(payload []byte) (ptpAnnounce, error) {

	minBytes := 64
	if len(payload) < minBytes {
		err := errors.New(fmt.Sprintf("Invalid announce message. Expected minimum %d bytes, got %d", minBytes, len(payload)))
		return ptpAnnounce{}, err
	}

	steps := binary.BigEndian.Uint16(payload[61:63])

	return ptpAnnounce{
			p1:                  payload[47],
			p2:                  payload[52],
			grandmasterIdentity: payload[53:61],
			stepsRemoved:        steps},
		nil
}

// getPTPMessageTypeName returns the name of a PTP message type
func getPTPMessageTypeName(msgType uint8) string {
	switch msgType {
	case 0:
		return "Sync"
	case 1:
		return "Delay_Req"
	case 2:
		return "Pdelay_Req"
	case 3:
		return "Pdelay_Resp"
	case 8:
		return "Follow_Up"
	case 9:
		return "Delay_Resp"
	case 10:
		return "Pdelay_Resp_Follow_Up"
	case 11:
		return "Announce"
	case 12:
		return "Signaling"
	case 13:
		return "Management"
	default:
		return "Unknown"
	}
}
