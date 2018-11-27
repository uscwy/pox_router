INTRODUCTION
------------
This is an implementation of router controller in OpenFlow tutorial

Change with_flow_mod to 0 in router.py if you don't need flow mod

IP packets process:
If dst_ip is router, pass it to icmp handler.
If dst ip is not router, need to check arp table and route table.
If dst ip doesn't match route table, then reply ICMP unreachable packet to src ip.
If dst ip match route table but not in arp table, router need to send arp request to find where dst ip is, at the same time put the original ICMP packet into a buffer. When receive arp reply, then send the buffered ICMP packet to dst ip.   

ARP process:
When receive a ARP request, add an entry into arp table, then add a flow rule (match dst_ip = protosrc in arp packet) with action (modify dst_mac and output port).  
When receive a ARP reply, add arp entry into arp table, then process arp message queue (buffered packets).

ICMP process:
If dst_ip is router, reply ICMP echo directly.


   switch.py    Controller implementation of learning switch
   router.py    Controller implementation of router
   mytopo.py    Topology description


HOW TO RUN
------------
#run learning switch
copy switch.py to pox/pox/misc directory
#then run controller in one terminal
./pox.py log.level --DEBUG misc.router.py
#create network in another termianl
sudo mn --topo single,3 --mac --switch ovsk --controller remote


#run router
copy router.py to pox/pox/misc directory
#run controller in one terminal:
./pox.py log.level --DEBUG misc.router.py
#create network in another terminal:
sudo mn --custom mytopo.py --topo mytopo –mac –-controller remote




