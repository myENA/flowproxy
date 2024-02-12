package tproxy

import (
	"context"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/myENA/flowproxy/common"
	"github.com/myENA/flowproxy/flow/netflow"
	"log"
	"os"
	"sync"
	"testing"
	"time"
)

const (
	// The same default as tcpdump.
	defaultSnapLen               = 65507
	timeout        time.Duration = -1 * time.Second
	deviceName     string        = "enp0s8"
)

//Generate dummy netflow packets(800 packets)
//This func will listen to a device and save 800 packets into a file for testing purposes
func TestGenerateNetflowPackets(t *testing.T) {
	packetCount := 0
	// Open output pcap file and write header
	f, _ := os.Create("netflow-dummy-packets/dummyNetflowV9Packets.pcap")
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(1024, layers.LinkTypeEthernet)
	defer f.Close()

	// Open the device for capturing
	handle, err := pcap.OpenLive(deviceName, 65507, false, pcap.BlockForever)
	if err != nil {
		fmt.Printf("Error opening device %s: %v", deviceName, err)
		os.Exit(1)
	}
	defer handle.Close()

	var filter string
	filter = fmt.Sprintf("udp and port %d", 8877)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Only capturing UDP port %d packets on device %s.\n", 8877, deviceName)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		packetCount++

		// Only capture 800 and then stop
		if packetCount > 1000 {
			break
		}
	}
}

func GetGeneratedNetflowPackets(version int) ([]gopacket.Packet, error) {
	// Open file instead of device
	var handle *pcap.Handle
	var err error
	if version == 9 {
		handle, err = pcap.OpenOffline("netflow-dummy-packets/dummyNetflowV9Packets.pcap")
	} else {
		handle, err = pcap.OpenOffline("netflow-dummy-packets/dummyNetflowV5Packets.pcap")
	}
	if err != nil {
		return GetGeneratedNetflowPackets(version)
	}
	defer handle.Close()

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := []gopacket.Packet{}
	for packet := range packetSource.Packets() {
		packets = append(packets, packet)
	}
	if len(packets) == 0 {
		return GetGeneratedNetflowPackets(version)
	}
	return packets, nil
}

func GetNetflowV9Packet() (gopacket.Packet, error) {
	packets, err := GetGeneratedNetflowPackets(9)
	if err != nil {
		return nil, err
	}
	return packets[0], nil
}

func GetNetflowV5Packet() (gopacket.Packet, error) {
	packets, err := GetGeneratedNetflowPackets(5)
	if err != nil {
		return nil, err
	}
	return packets[0], nil
}

func TestIsValidNetflow(t *testing.T) {
	packetV9, err := GetNetflowV9Packet()
	if err != nil {
		t.Error("Failed getting dummy netflow packet.")
	}
	packetV5, err := GetNetflowV5Packet()
	if err != nil {
		t.Error("Failed getting dummy netflow packet.")
	}
	testCases := []struct {
		name     string
		input    gopacket.Packet
		expected bool
	}{
		{
			name:     "netflow v9 packet",
			input:    packetV9,
			expected: true,
		},
		{
			name:     "netflow v5 packet",
			input:    packetV5,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			udpLayer := tc.input.Layer(layers.LayerTypeUDP)
			payload := udpLayer.LayerPayload()
			result, _ := netflow.IsValidNetFlow(payload, 9)
			if result != tc.expected {
				t.Errorf("Expected %v but got %v", tc.expected, result)
			}
		})
	}
}

func TestAddingDevice(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "check added device",
			input:    "192.168.56.100",
			expected: true,
		},
		{
			name:     "check not added device",
			input:    "192.168.56.105",
			expected: false,
		},
	}

	deviceManager := netflow.DeviceManager{
		Devices: make(map[string]netflow.DeviceDetails),
	}
	deviceManager.AddDevice("192.168.56.100")

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := deviceManager.LookupDevice(tc.input)
			if result != tc.expected {
				t.Errorf("Expected %v but got %v", tc.expected, result)
			}
		})
	}
}

func TestParseNetflowWithNoRateLimits(t *testing.T) {
	wg := &sync.WaitGroup{}
	ctx, _ := context.WithCancel(context.Background())

	proxyChan := make(chan gopacket.Packet, bufferSize)
	dataChan := make(chan gopacket.Packet, bufferSize)

	rStats := RecordStat{
		Netflow9: Netflow9{
			TotalFlows:   0,
			LastFlows:    0,
			DataRead:     0,
			DataSent:     0,
			TemplateSent: 0,
			OptionSent:   0,
		},
		Ipfix: Ipfix{
			Pkts:         0,
			DataRead:     0,
			DataSent:     0,
			TemplateSent: 0,
			OptionSent:   0,
		},
		OtherPkts: 0,
		TotalPkts: 0,
		LastPkts:  0,
	}

	packetsV9, err := GetGeneratedNetflowPackets(9)
	if err != nil {
		t.Error("Failed gettting generated netflow packets!")
	}

	wg.Add(1)
	go parseNetflow(ctx, wg, proxyChan, dataChan, &rStats, 0, false)

	for _, packet := range packetsV9 {
		proxyChan <- packet
	}
	for {
		if len(proxyChan) == 0 {
			break
		}
	}
	time.Sleep(40 * time.Second) // wait for packets to be processed
	if rStats.Netflow9.DataRead > rStats.Netflow9.DataSent {
		t.Error("Not all the packets have been sent.")
	}
}

func TestParseNetflowWithGeneralRateLimit(t *testing.T) {
	wg := &sync.WaitGroup{}
	ctx, _ := context.WithCancel(context.Background())

	proxyChan := make(chan gopacket.Packet, bufferSize)
	dataChan := make(chan gopacket.Packet, bufferSize)

	rStats := RecordStat{
		Netflow9: Netflow9{
			TotalFlows:   0,
			LastFlows:    0,
			DataRead:     0,
			DataSent:     0,
			TemplateSent: 0,
			OptionSent:   0,
		},
		Ipfix: Ipfix{
			Pkts:         0,
			DataRead:     0,
			DataSent:     0,
			TemplateSent: 0,
			OptionSent:   0,
		},
		OtherPkts: 0,
		TotalPkts: 0,
		LastPkts:  0,
	}

	packetsV9, err := GetGeneratedNetflowPackets(9)
	if err != nil {
		t.Error("Failed gettting generated netflow packets!")
	}

	wg.Add(1)
	go parseNetflow(ctx, wg, proxyChan, dataChan, &rStats, 100, false)

	for _, packet := range packetsV9 {
		proxyChan <- packet
	}
	for {
		if len(proxyChan) == 0 {
			break
		}
	}
	time.Sleep(40 * time.Second) // wait for packets to be processed
	if rStats.Netflow9.DataSent > 100 {
		t.Errorf("The rate limit is 100. %d packets have been sent", rStats.Netflow9.DataSent)
	}
	if rStats.Netflow9.DataSent < 100 {
		t.Errorf("The rate limit is 100. %d packets have been sent", rStats.Netflow9.DataSent)
	}
}

func TestParseNetflowWithCustomRateLimits(t *testing.T) {
	wg := &sync.WaitGroup{}
	ctx, _ := context.WithCancel(context.Background())

	proxyChan := make(chan gopacket.Packet, bufferSize)
	dataChan := make(chan gopacket.Packet, bufferSize)

	rStats := RecordStat{
		Netflow9: Netflow9{
			TotalFlows:   0,
			LastFlows:    0,
			DataRead:     0,
			DataSent:     0,
			TemplateSent: 0,
			OptionSent:   0,
		},
		Ipfix: Ipfix{
			Pkts:         0,
			DataRead:     0,
			DataSent:     0,
			TemplateSent: 0,
			OptionSent:   0,
		},
		OtherPkts: 0,
		TotalPkts: 0,
		LastPkts:  0,
	}

	packetsV9, err := GetGeneratedNetflowPackets(9)
	if err != nil {
		t.Error("Failed gettting generated netflow packets!")
	}

	common.InitCustomRateLimits("netflow-dummy-packets/rateLimitsTestData.yaml")

	wg.Add(1)
	go parseNetflow(ctx, wg, proxyChan, dataChan, &rStats, 100, false)

	for _, packet := range packetsV9 {
		proxyChan <- packet
	}
	for {
		if len(proxyChan) == 0 {
			break
		}
	}
	time.Sleep(40 * time.Second) // wait for packets to be processed
	if rStats.Netflow9.DataSent > 120 {
		t.Errorf("The rate limit is 100 and the custom rate is 20. %d packets have been sent instead of 120.", rStats.Netflow9.DataSent)
	}
	if rStats.Netflow9.DataSent < 120 {
		t.Errorf("The rate limit is 100 and the custom rate is 20. %d packets have been sent instead of 120.", rStats.Netflow9.DataSent)
	}
}
