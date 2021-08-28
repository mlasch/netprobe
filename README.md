# netprobe

Bandwithd-style traffic counter with influxdb backend. Captures network traffic statistics
using libpcap and stores the packet's metadata in influxdb. Network traffic can
be analyzed by IP version, transport protocol and direction. Destination addresses
are not stored to protect user privacy.

Traffic statistics can be filtered by
 * source MAC address
 * source IPv4/IPv6
 * transport protocol, see protocols(5)
 * flow direction in/out

## how to use
`netprobe` needs special permissions to sniff the network.
To run it with user permission `cap_net_raw` needs to be set.

```
$ sudo setcap cap_net_raw=ep netprobe
```

```
netprobe 0.1 ( https://github.com/mlasch/netprobe )
Usage:
	-i, --interface		Network interface
	-u, --url		URL containing server, port, database and token
	-m, --measurement	Measurement Name
	    --nop		No actual insert (no operation)
	    --verbose
	    --version		Print program version
```

```
./netprobe -i eth0 -u http://localhost:5000/write/<token> -m bla
```

## build

### requirements

 * libpcap-dev
 * libcurl4-openssl-dev

### build

```
mkdir cmake-build && cd cmake-build
cmake -GNinja ..
cmake --build .
```
