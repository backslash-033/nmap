# To test
```bash
# Lots of verbose
tcpdump -i lo -vvv -X tcp port 80
# Less verbose
tcpdump -i lo tcp port 80

```

# Scans & results
## SYN SCAN
Also called half-open / stealth scan
Sends a SYN packet, the first step in the TCP three-way handshake
1. Nmap sends a SYN Packet
2. Target responds with:
	- SYN/ACK: the port is OPEN
	- RST: the port is CLOSED
	- Nothing: the port is FILTERED
3. If received SYN/ACK, Nmap sends a RST packet to close the connection (opt)

## NULL SCAN
Sends a packet with no flags set (unusual for TCP packets)
1. Nmap sends a NULL Packet (no flags)
2. Target responds with:
	- RST: the port is CLOSED
	- Nothing: the port is OPEN or FILTERED

## ACK SCAN
Sends a packet with the ACK flag set, simulating an already established connection.
Used to map out firewall rulesets, determining whether ports are filtered (stateful forewalls) or unfiltered.
Used to check filtering status.
1. Nmap sends a ACK Packet
2. Target responds with:
	- RST: the port is UNFILTERED
	- Nothing: the port is FILTERED

## FIN SCAN
Sends a packet with the FIN flag set, typically used to gracefully end a connection.
1. Nmap sends a FIN Packet
2. Target responds with:
	- RST: the port is CLOSED
	- Nothing: the port is OPEN or FILTERED

## XMAS SCAN
Sends an unusual packet. Called XMAS because of its look.
1. Nmap sends a FIN, PSH, URG Packet
2. Target responds with:
	- RST: the port is CLOSED
	- Nothing: the port is OPEN or FILTERED

## UDP SCAN
Sends an UDP packet.
1. Nmap sends a UDP Packet
2. Target responds with:
	- ICMP Port Unreachable message: the port is CLOSED
	- Nothing: the port is OPEN or FILTERED
	- UDP Response: the port is OPEN and a service responds
