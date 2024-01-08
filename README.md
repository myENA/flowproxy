# flowproxy
Intelligent Flow Proxy

## Usage

```shell
Tproxy is used to accept flows and relay them transparently to multiple targets

  -device string
    	the device the proxy should use (default "eth0")
  -outfile string
    	file to write statistics and information to.
  -port int
    	the udp port the proxy should use (default 9995)
  -rate int
    	sample rate to be used for sending flows along.If 0 all flows will be sent.
  -target value
    	Can be passed multiple times in IP:PORT format
  -verbose
    	Whether to log every flow received. Warning can be a lot
```

## Examples
```shell
# run flowproxy using transparent proxy listening for udp packets on device en8 and port 9995.
# Target upstream collector 10.1.1.200 on port 9997 with a sample rate of 4096
flowproxy tproxy -device en8 -port 9995 -target 10.1.1.200:9997 -rate 4096
```