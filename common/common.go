package common

import (
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/mostlygeek/arp"
	"gopkg.in/yaml.v2"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

type CustomDeviceRateLimits struct {
	RateLimits []CustomDeviceRateLimit `yaml:"rateLimits"`
}

type CustomDeviceRateLimit struct {
	DeviceIp  string `yaml:"deviceIp"`
	RateLimit int    `yaml:"rateLimit"`
}

var customDeviceRateLimits CustomDeviceRateLimits

func CryptoRandomNumber(max int64) int64 {
	n, err := crand.Int(crand.Reader, big.NewInt(max))
	if err != nil {
		panic(fmt.Errorf("crypto number failed to read bytes %v", err))
	}
	return n.Int64()
}

// RandomNum Generates a random number between the given min and max
func RandomNum(min, max int) int {
	return int(CryptoRandomNumber(int64(max-min))) + min
}

func BinaryReader(reader *bytes.Reader, dests ...interface{}) error {
	for _, dest := range dests {
		err := binary.Read(reader, binary.BigEndian, dest)
		if err != nil {
			return err
		}
	}
	return nil
}

func LookupMACAddr(ipAddr net.IP) (macAddr net.HardwareAddr, e error) {
	// check if ipAddr is local
	// find all devices
	devices, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, device := range devices {
		//DEBUG
		//fmt.Printf("device: %s mac: %s\n", device.Name, device.HardwareAddr)
		addresses, _ := device.Addrs()
		for _, address := range addresses {
			//DEBUG
			//fmt.Printf("\taddress: %s\n", address)
			deviceIPAddr, _, _ := net.ParseCIDR(address.String())
			if deviceIPAddr != nil {
				if ipAddr.Equal(deviceIPAddr) {
					// found IP locally, grab the interface and return it
					return device.HardwareAddr, nil
				}
			} else {
				deviceIPAddr = net.ParseIP(address.String())
				if ipAddr.Equal(deviceIPAddr) {
					return device.HardwareAddr, nil
				}
			}
		}
	}
	// give ipAddr was not found locally, so lets move on to ARP
	// ping first to force the OS to resolve mac address
	cmd := exec.Command("ping", "-c", "1", ipAddr.String())
	err = cmd.Run()
	if err != nil {
		log.Printf("Failed to ping %s: %s", ipAddr, err)
		return nil, err
	}
	mac := arp.Search(ipAddr.String())
	if runtime.GOOS == "darwin" {
		mac = DarwinMACFormat(mac)
	}
	macParsed, err := net.ParseMAC(mac)
	if err != nil {
		fmt.Printf("Error parsing destination MAC: %s - %s\n", mac, err)
		return nil, err
	}
	return macParsed, nil
}

// DarwinMACFormat fixes the issue that macOS returns oddly formatted arp -a results
func DarwinMACFormat(macString string) string {
	var group int
	var builder strings.Builder
	for i := 0; i < len(macString); i++ {
		r := macString[i]
		if r == ':' {
			for chars := group; chars < 2; chars++ {
				builder.WriteString("0")
			}
			builder.WriteString(macString[i-group : i])
			builder.WriteString(":")
			group = 0
			continue
		}
		group++
	}
	for chars := group; chars < 2; chars++ {
		builder.WriteString("0")
	}
	builder.WriteString(macString[len(macString)-group:])
	return builder.String()
}

func InitCustomRateLimits(rateLimitPath string) error {
	var customRateLimits CustomDeviceRateLimits
	configFileName := rateLimitPath
	source, err := os.ReadFile(configFileName)
	if err != nil {
		fmt.Println("failed reading custom device rate limits")
		return err
	}
	err = yaml.Unmarshal(source, &customRateLimits)
	if err != nil {
		log.Fatalf("error: %v", err)
		fmt.Println("failed unmarshal the custom rate limits")
		return err
	}
	customDeviceRateLimits = customRateLimits
	return nil
}

func HasCustomRateLimit(ip string) (bool, int) {
	for _, customRate := range customDeviceRateLimits.RateLimits {
		if strings.HasSuffix(customRate.DeviceIp, "/24") {
			_, ipv4Net, err := net.ParseCIDR(customRate.DeviceIp)
			if err != nil {
				return false, 0
			}
			if ipv4Net.Contains(net.ParseIP(ip)) {
				return true, customRate.RateLimit
			} else {
				return false, 0
			}
		}
		if customRate.DeviceIp == ip {
			return true, customRate.RateLimit
		}
	}
	return false, 0
}
