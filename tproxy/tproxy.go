// Proxy is used to accept flows and relay them to multiple targets

package tproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/myENA/flowproxy/common"
	"github.com/myENA/flowproxy/flow/netflow"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const udpMaxBufferSize = 65507
const bufferSize = 1024

type RecordStat struct {
	Netflow9  `json:"netflow9"`
	Ipfix     `json:"ipfix"`
	OtherPkts uint64 `json:"otherPkts"`
	TotalPkts uint64 `json:"totalPkts"`
	LastPkts  uint64 `json:"lastPkts"`
}

type Netflow9 struct {
	TotalFlows   uint64 `json:"totalFlows,omitempty"`
	LastFlows    uint64 `json:"lastFlows,omitempty"`
	DataRead     uint64 `json:"dataRead,omitempty"`
	DataSent     uint64 `json:"dataSent,omitempty"`
	TemplateSent uint64 `json:"templateSent,omitempty"`
	OptionSent   uint64 `json:"optionSent,omitempty"`
}

type Ipfix struct {
	Pkts         uint64 `json:"pkts,omitempty"`
	DataRead     uint64 `json:"dataRead,omitempty"`
	DataSent     uint64 `json:"dataSent,omitempty"`
	TemplateSent uint64 `json:"templateSent,omitempty"`
	OptionSent   uint64 `json:"optionSent,omitempty"`
}

func prettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}

// worker is the goroutine used to create workers
func worker(id int, ctx context.Context, device string, destIPAddr string, port int, wg *sync.WaitGroup, workerChan <-chan gopacket.Packet) {
	defer wg.Done()
	var snapshotLen int32 = udpMaxBufferSize
	promiscuous := false
	var timeout time.Duration = pcap.BlockForever
	var handle *pcap.Handle
	// Convert given IP String to net.IP type
	// Weak test to avoid localhost
	if destIPAddr == "127.0.0.1" {
		fmt.Printf("Worker [%2d] sending to localhost isn't currently supported. Exiting!\n", id)
		return
	}
	destIP := net.ParseIP(destIPAddr)
	destMac, err := common.LookupMACAddr(destIP)
	if err != nil {
		fmt.Printf("Worker [%2d] Couldn't find destination MAC address. Exiting! Error: %s\n", id, err)
		return
	}
	// Create UDP listener
	// Open device
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	log.Printf("Worker [%2d] Sending flows at %s:%d destination mac: %s\n",
		id, destIPAddr, port, destMac)
	//Infinite loop to keep slinging until we receive context done.
	for {
		select {
		case <-ctx.Done(): //Caught the signal to be done.... time to wrap it up
			log.Printf("Worker [%2d] exiting due to signal\n", id)
			return
		case packet := <-workerChan:
			// DEBUG
			// length := len(packet.Data())
			// log.Printf("Worker [%2d] sending packet to %s:%d with length: %d\n", id, device, port, length)
			// END DEBUG
			// send packet here.
			buffer := gopacket.NewSerializeBuffer()
			options := gopacket.SerializeOptions{
				ComputeChecksums: true,
				FixLengths:       true,
			}
			ethLayer := packet.Layer(layers.LayerTypeEthernet)
			eth, _ := ethLayer.(*layers.Ethernet)

			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
					udp, _ := udpLayer.(*layers.UDP)
					ip.DstIP = destIP
					eth.DstMAC = destMac
					udp.DstPort = layers.UDPPort(port)

					if err = udp.SetNetworkLayerForChecksum(ip); err != nil {
						fmt.Printf("Checksum error: %s\n", err.Error())
						return
					}
					// copy over the payload
					payloadLayer := packet.Layer(gopacket.LayerTypePayload)
					payload, _ := payloadLayer.(*gopacket.Payload)
					if err = gopacket.SerializeLayers(buffer, options,
						eth,
						ip,
						udp,
						payload,
					); err != nil {
						fmt.Printf("Serialize error: %s\n", err.Error())
						return
					}
					outPacket := buffer.Bytes()
					if err = handle.WritePacketData(outPacket); err != nil {
						fmt.Printf("Error while sending: %s\n", err.Error())
						return
					}
				}
			}
		}
	}
}

// replicator is used to take payloads off the dataChan and pass it to each worker's channel for sending
func replicator(ctx context.Context, wg *sync.WaitGroup, dataChan <-chan gopacket.Packet, targets []chan gopacket.Packet, verbose bool) {
	defer wg.Done()
	// Start the loop and check context for done, otherwise listen for packets
	for {
		select {
		case <-ctx.Done():
			log.Println("Replicator exiting due to signal")
			return
		// Validated received and needs to be passed on to workers
		case packet := <-dataChan:
			for _, target := range targets {
				target <- packet
			}
		}
	}
}

// proxyListener is used to pull packets off the wire and put the byte payload on the data chan
func proxyListener(ctx context.Context, wg *sync.WaitGroup, device string, port int, proxyChan chan<- gopacket.Packet, verbose bool) {
	defer wg.Done()
	// Create UDP listener
	var (
		snapshotLen int32 = udpMaxBufferSize
		promiscuous bool  = false
		err         error
		timeout     time.Duration = pcap.BlockForever
		handle      *pcap.Handle
	)
	// Open device
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter
	var filter string
	filter = fmt.Sprintf("udp and port %d", port)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Only capturing UDP port %d packets on device %s.\n", port, device)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Start the loop and check context for done, otherwise listen for packets
	for {
		select {
		case <-ctx.Done():
			log.Println("Proxy Listener exiting due to signal")
			return
		default:
			for packet := range packetSource.Packets() {
				// Do something with a packet here.
				//fmt.Println(packet)
				proxyChan <- packet
			}
		}
	}
}

// statsPrinter prints out the status every 10 seconds.
func statsPrinter(ctx context.Context, wg *sync.WaitGroup, rStats *RecordStat) {
	defer wg.Done()
	var (
		diffPkts  uint64 = 0
		diffFlows uint64 = 0
		fps       uint64 = 0
		pps       uint64 = 0
	)
	for {
		select {
		case <-ctx.Done():
			//log.Println("statsPrinter exiting due to signal")
			return
		case <-time.After(time.Second * 10):
			diffPkts = rStats.TotalPkts - rStats.LastPkts
			diffFlows = rStats.Netflow9.TotalFlows - rStats.Netflow9.LastFlows
			fps = diffFlows / 10
			pps = diffPkts / 10
			rStats.LastPkts = rStats.TotalPkts
			rStats.Netflow9.LastFlows = rStats.Netflow9.TotalFlows
			log.Printf("NFv9 Packets: %d IPFIX Packets: %d Other Packets: %d Total Pkts: %d pps: %d",
				rStats.Netflow9.TotalFlows, rStats.Ipfix.Pkts, rStats.OtherPkts, rStats.TotalPkts, pps)
			log.Printf("NFv9 Flows Data Read: %d Data Sent: %d Template: %d OptionTemplate: %d fps: %d\n",
				rStats.Netflow9.DataRead, rStats.Netflow9.DataSent,
				rStats.Netflow9.TemplateSent, rStats.Netflow9.OptionSent, fps)
		}
	}
}

// parseNetflow reads packet and determine if it is Netflow v9 or IPFIX then puts valid packets on the chan for sending
// and discards others.
func parseNetflow(ctx context.Context, wg *sync.WaitGroup, proxyChan <-chan gopacket.Packet, dataChan chan<- gopacket.Packet, rStats *RecordStat, rate int, verbose bool) {
	defer wg.Done()
	var rateLimit bool = false
	if rate > 0 {
		rateLimit = true
	}
	// Start up Device Manager to track template packets and use those templates to decode data packets
	deviceManager := netflow.DeviceManager{
		Devices: make(map[string]netflow.DeviceDetails),
	}
	// Start the loop
	for {
		// Check to see if context is done and return, otherwise pull payloads and write
		select {
		case <-ctx.Done():
			log.Println("Netflow parser exiting due to signal")
			fmt.Println(prettyPrint(deviceManager))
			return
		case packet := <-proxyChan:
			// Decode first uint16 and see if it is a version 9
			rStats.TotalPkts++
			var srcIP net.IP
			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				srcIP = ip.SrcIP
			} else {
				if ipLayer = packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
					ip, _ := ipLayer.(*layers.IPv6)
					srcIP = ip.SrcIP
				}
			}

			hasCustomRateLimit, customRateLimit := common.HasCustomRateLimit(srcIP.String())

			udpLayer := packet.Layer(layers.LayerTypeUDP)
			payload := udpLayer.LayerPayload()
			ok9, err9 := netflow.IsValidNetFlow(payload, 9)
			if err9 != nil {
				log.Printf("Skipping packet due to issue parsing: %v", err9)
			}
			// Valid Netflow Packet.  Let's see if there is a device in deviceManager and if not add it
			if deviceManager.LookupDevice(srcIP.String()) {
				deviceManager.SeenDevice(srcIP.String())
			} else {
				deviceManager.AddDevice(srcIP.String())
				if hasCustomRateLimit {
					deviceManager.SetSampleRate(srcIP.String(), customRateLimit)
				} else if rateLimit {
					deviceManager.SetSampleRate(srcIP.String(), rate)
				}
			}
			templateManager := deviceManager.GetTemplateManager(srcIP.String())
			if ok9 {
				// Netflow v9 Packet send it on
				dataCount, templateCount, optionCount, _ := netflow.InspectFlowPacket(payload, &templateManager)
				rStats.Netflow9.TotalFlows = rStats.Netflow9.TotalFlows + dataCount + templateCount + optionCount
				deviceManager.UpdateStats(srcIP.String(), dataCount, templateCount, optionCount)
				if dataCount > 0 {
					rStats.Netflow9.DataRead = rStats.Netflow9.DataRead + dataCount
				}
				if templateCount > 0 {
					rStats.Netflow9.TemplateSent = rStats.Netflow9.TemplateSent + templateCount
				}
				if optionCount > 0 {
					rStats.Netflow9.OptionSent = rStats.Netflow9.OptionSent + optionCount
				}
				// determine sampling and decide to send the packet or not
				if templateCount > 0 || optionCount > 0 {
					//Always send template and options
					dataChan <- packet
					continue
				}
				if hasCustomRateLimit {
					if deviceManager.CheckSampleRate(srcIP.String(), int(dataCount)) {
						rStats.Netflow9.DataSent = rStats.Netflow9.DataSent + dataCount
						dataChan <- packet
					}
				} else if rateLimit {
					if deviceManager.CheckSampleRate(srcIP.String(), int(dataCount)) {
						rStats.Netflow9.DataSent = rStats.Netflow9.DataSent + dataCount
						dataChan <- packet
					}
				} else {
					// always send it
					rStats.Netflow9.DataSent = rStats.Netflow9.DataSent + dataCount
					dataChan <- packet
				}
			} else {
				ok10, err10 := netflow.IsValidNetFlow(payload, 10)
				if err10 != nil {
					log.Printf("Skipping packet due to issue parsing: %v", err10)
				}
				if ok10 {
					// IPFIX Packet send it on
					rStats.Ipfix.Pkts++
					dataChan <- packet
				} else {
					// Not a Netflow v9 Packet... skip
					rStats.OtherPkts++
				}
			}
		case <-time.After(time.Second * 30):
			log.Printf("No flow packets received for 30s...waiting")
		}
	}
}

// Run Replay. Kicks off the replay of netflow packets from a db.
func Run(device string, port int, rate int, verbose bool, outfile string, targets []string) {
	wg := &sync.WaitGroup{}
	ctx, cancel := context.WithCancel(context.Background())
	// Create channels
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
	// Create dedicated channel per target <= 10
	workers := len(targets)
	if workers > 10 {
		log.Println("Can't have more than 10 Targets")
		os.Exit(1)
	}
	workerChans := make([]chan gopacket.Packet, workers)
	// start workers
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		id := w + 1
		workerChan := make(chan gopacket.Packet, bufferSize)
		workerChans[w] = workerChan
		target := targets[w]
		targetIP, targetPort, err := net.SplitHostPort(target)
		if err != nil {
			log.Fatalf("Issue parsing target: %v\n", err)
		}
		targetPortInt, err := strconv.Atoi(targetPort)
		if err != nil {
			log.Fatalf("Issue parsing target port: %v\n", err)
		}
		go worker(id, ctx, device, targetIP, targetPortInt, wg, workerChan)
	}

	// Start parseNetflow and replicator first
	wg.Add(1)
	go statsPrinter(ctx, wg, &rStats)
	wg.Add(1)
	go parseNetflow(ctx, wg, proxyChan, dataChan, &rStats, rate, verbose)
	wg.Add(1)
	go replicator(ctx, wg, dataChan, workerChans, verbose)

	// Finally, start up proxyListener
	go proxyListener(ctx, wg, device, port, proxyChan, verbose)

	// Wait for a SIGINT (perhaps triggered by user with CTRL-C)
	// Run cleanup when signal is received
	signalChan := make(chan os.Signal, 1)
	cleanupDone := make(chan bool)
	signal.Notify(signalChan, os.Interrupt, os.Kill, os.Signal(syscall.SIGTERM), os.Signal(syscall.SIGHUP))

	go func() {
		for {
			select {
			case <-signalChan:
				log.Printf("\rReceived signal, shutting down...\n\n")
				cancel()
				cleanupDone <- true
			case <-ctx.Done():
				fmt.Println(prettyPrint(rStats))
				cleanupDone <- true
			}
		}
	}()
	<-cleanupDone
	wg.Wait()
	close(signalChan)
	close(cleanupDone)
	return
}
