# netprobe

Bandwithd-style traffic counter with influxdb backend. Captures network traffic
using libpcap and stores the packet's metadata in influxdb.

## how to use

```
Usage:
	-i, --interface		Network interface
	-u, --url		URL containing server, port, database and token
	-p, --path		Path
	    --nop		No actual insert (no operation)
	    --verbose

```

## requirements

libpcap-dev
libcurl4-openssl-dev
