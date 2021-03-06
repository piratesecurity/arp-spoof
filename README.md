# arp-spoof
Project :An automated approach for preventing ARP spoofing attack using static ARP entries

   Address Resolution Protocol (ARP) is a protocol for mapping an Internet Protocol address (IP address) to a physical
machine address (MAC) that is recognized in the local network. ARP is a stateless protocol, so it is vulnerable to certain threats making it less reliable. ARP spoofing is the most dangerous attack that poses a threat to LANs. ARP
Spoofing is the technique used to maliciously influence the contents of the ARP cache on a local network host. This
attack may allow an attacker to intercept data frames on LAN, modify the traffic or stop the traffic altogether. This
attack may be used to launch either Denial of Service (DoS) attacks or Man in the Middle attacks (MITM).

   Static ARP entries is considered as the most effective way to prevent ARP spoofing. Every host in the local network
will have a protected non-spoofed ARP cache, which takes the form of a table containing the matched sets of MAC and
IP addresses. Each device on the network manages its own ARP cache table. A device’s ARP cache can contain both static
and dynamic entries. Here, we propose a scalable technique to prevent ARP spoofing attacks, which automatically
configures static ARP entries. This technique operates in both Static and DHCP based addressing schemes. This can work in
large-scale networks without any overhead on the administrator. In addition, the technique doesn’t require special
hardware to be deployed, as any host can work as ARP server.

