# PF-Packet-Filter
 Port Knocking to allow ssh access authentication from any remote ip.
 
 

Setting up Pf to listen to Port Knocking to allow ssh access should be easy enough. 
Lets do this, lets say if you hit four ports, 22222 then 12345, then 12345 again and then 34125,
in that order will allow ssh authentication from that remote ip.


## Pf Port Knocking 

### Ports
# These are the ports to knock in order
  portknock1=22222
  portknock2=12345
  portknock3=34125

### Tables ###
# These are the tables which will hold the ips who are in the processes of port
# knocking or who have successfully port knocked and are allowed to ssh to port
# 22.
  table <portknock1> persist
  table <portknock2> persist
  table <portknock3> persist

### Translation and Filtering ###
# Use Pf with synproxy to keep state on the ports. Add the ip to the overload
# table if the remote ips hits the right port. Once the remote ip hits all the
# ports in order then grant the ability to connect through sshd
 pass in on $ExtIf inet proto tcp from any to $ExtIf port $portknock1 synproxy state (max-src-conn 1, overload <portknock1>)
 pass in on $ExtIf inet proto tcp from <portknock1> to $ExtIf port $portknock2 synproxy state (max-src-conn 2, overload <portknock2>)
 pass in on $ExtIf inet proto tcp from <portknock2> to $ExtIf port $portknock3 synproxy state (max-src-conn 1, overload <portknock3>)

# This is the rule to allow successfully port knock'd ips to the sshd daemon
 pass in on $ExtIf inet proto tcp from <portknock3> to $ExtIf port ssh

That should be it. Since the ips in the tables portknock1 and portknock2 are temporary we will clean them out every 5 minutes. Then the ips in portknock3 are cleared out every hour.

*/5 * * * * root /sbin/pfctl -q -t portknock1 -T expire 60
*/5 * * * * root /sbin/pfctl -q -t portknock2 -T expire 60
00  * * * * root /sbin/pfctl -q -t portknock3 -T expire 600

Now, to open up ssh access to your remote ip you will execute "telnet server_ip 22222", then "telnet server_ip 12345",
 "telnet server_ip 12345" again and finally "telnet server_ip 34125".
 The server_ip is the ip address of your firewall running Pf. 
 If you telnet to all the ports in order Pf will add your remote ip to the portknock3 table.
 Then just "ssh username@server_ip" and Pf will allow ssh authentication to your machine.
 You may to think about adding more ports or even hitting the same port many times to defeat port scanning.
 
 thanks to calomel.org and OpenBSD.org 
