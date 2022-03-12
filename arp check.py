from scapy.all import rdpcap



pkts= rdpcap('captured.pcap') #import the captured pcap
ipadr=['192.168.1.1','192.168.1.111','192.168.1.112'] #set up a ip address map 
macadr=['08:00:27:8a:a4:0b','08:00:27:2c:ee:e6','08:00:27:06:b6:1f']#set up a mac address map

for p in pkts:
 if p.haslayer('IP'): #select packets has IP layer in captured pcap
   for index, ip in enumerate(ipadr): #Traverse the whole elements in ip address map
    if (ip==p['IP'].src) & (macadr[index]!=p['Ether'].src):#if the ip sourse of packets equals to one of ip address map and mac source of packets doesnt equals to corresponding mac address of ip address
     print('MAC address of IP '+ip+' changes from '+macadr[index]+' to '+p['Ether'].src)#print mac address of ***(IP address) changed from *** to ***
     macadr[index]=p['Ether'].src #editing the new mac address to current mac adress map