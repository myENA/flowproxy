package main

import (
	"flag"
	"fmt"
	"github.com/myENA/flowproxy/proxy"
	"github.com/myENA/flowproxy/tproxy"
	"os"
)

const (
	version = "main" // semantic version
)

// targetFlags is used to allow for multiple targets to be passed for proxy
type targetFlags []string

// String is used to return a string form of targets passed to proxy
func (i *targetFlags) String() string {
	var output string
	var target string
	first := true

	for _, target = range *i {
		if first {
			output = target
			first = false
		} else {
			output = output + ", " + target
		}
	}
	return output
}

// Set is used to put multiple targets into a slice
func (i *targetFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func main() {
	// Proxy SubCommand setup
	proxyCmd := flag.NewFlagSet("proxy", flag.ExitOnError)
	proxyCmd.Usage = func() {
		printHelpHeader()
		fmt.Println("Proxy is used to accept flows and relay them to multiple targets")
		fmt.Println()
		fmt.Fprintf(proxyCmd.Output(), "Usage of %s:\n", os.Args[0])
		fmt.Println()
		proxyCmd.PrintDefaults()
	}
	var proxyTargetsFlags targetFlags
	proxyIP := proxyCmd.String("ip", "127.0.0.1", "ip address proxy should listen on")
	proxyPort := proxyCmd.Int("port", 9995, "proxy listen udp port")
	proxyCmd.Var(&proxyTargetsFlags, "target", "Can be passed multiple times in IP:PORT format")
	proxyVerbose := proxyCmd.Bool("verbose", false, "Whether to log every flow received. Warning can be a lot")

	// Tproxy SubCommand setup
	tproxyCmd := flag.NewFlagSet("tproxy", flag.ExitOnError)
	tproxyCmd.Usage = func() {
		printHelpHeader()
		fmt.Println("Tproxy is used to accept flows and relay them transparently to multiple targets")
		fmt.Println()
		fmt.Fprintf(tproxyCmd.Output(), "Usage of %s:\n", os.Args[0])
		fmt.Println()
		tproxyCmd.PrintDefaults()
	}
	var tproxyTargetsFlags targetFlags
	tproxyDevice := tproxyCmd.String("device", "eth0", "the device the proxy should use")
	tproxyPort := tproxyCmd.Int("port", 9995, "the udp port the proxy should use")
	tproxyCmd.Var(&tproxyTargetsFlags, "target", "Can be passed multiple times in IP:PORT format")
	tproxyRate := tproxyCmd.Int("rate", 0, "sample rate to be used for sending flows along."+
		"If 0 all flows will be sent.")
	tproxyOutfile := tproxyCmd.String("outfile", "", "file to write statistics and information to.")
	tproxyVerbose := tproxyCmd.Bool("verbose", false, "Whether to log every flow received. "+
		"Warning can be a lot")

	// Start parsing command line args
	if len(os.Args) < 2 {
		printHelpHeader()
		fmt.Println("expected 'proxy', 'tproxy' or 'version' subcommands")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "proxy":
		printHelpHeader()
		err := proxyCmd.Parse(os.Args[2:])
		if err != nil {
			panic(fmt.Errorf("error parsing args: %v\n", err))
		}
		fmt.Printf("proxy listening on %s:%d verbose: %v\n", *proxyIP, *proxyPort, *proxyVerbose)
		for t := 0; t < len(proxyTargetsFlags); t++ {
			fmt.Printf("target: %s\n", proxyTargetsFlags[t])
		}
		proxy.Run(*proxyIP, *proxyPort, *proxyVerbose, proxyTargetsFlags)
		//os.Exit(0)
	case "tproxy":
		printHelpHeader()
		err := tproxyCmd.Parse(os.Args[2:])
		if err != nil {
			panic(fmt.Errorf("error parsing args: %v\n", err))
		}
		for t := 0; t < len(proxyTargetsFlags); t++ {
			fmt.Printf("target: %s\n", proxyTargetsFlags[t])
		}
		tproxy.Run(*tproxyDevice, *tproxyPort, *tproxyRate, *tproxyVerbose, *tproxyOutfile, tproxyTargetsFlags)
	case "version":
		printHelpHeader()
		fmt.Printf("Version: %s\n", version)
	case "help":
		printGenericHelp()
	default:
		printGenericHelp()
		fmt.Println("expected 'proxy' or 'version' subcommands")
		os.Exit(2)
	}

	// Setup and run Single
	os.Exit(0)
}

// printHelpHeader Generates the help header
func printHelpHeader() {
	fmt.Println("<---flowproxy--->")
}

// printGenericHelp prints out the top-level generic help
func printGenericHelp() {
	printHelpHeader()
	fmt.Printf("Version: %s\n", version)
	fmt.Println()
	fmt.Println("to print more details pass '-help' after the subcommand")
	fmt.Println()
	fmt.Println("Proxy is used to accept flows and relay them to multiple targets")
	fmt.Println()
}
