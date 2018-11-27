INTRODUCTION
------------
This is an implementation of Advanced Topology section in OpenFlow tutorial

We use dpid as switch identification to support multi-switch controller, separating route table, arp table, mac table according to dpid. Each switch has its own tables.

This controller need to support both L2 switching and L3 routing.
When receiving packet, first handle it using act_like_switch function which use mac table to set flow rules, and then pass packet to act_like_router function which use arp and route table to set flow rules.


   adv_router.py    Controller implementation of router/switch
   mytopo.py        Topology description


HOW TO RUN
------------
#copy adv_router.py to pox/pox/misc directory
cd pox
#run controller in one terminal:
./pox.py log.level --DEBUG misc.adv_router.py
#create network in another terminal:
sudo mn --custom mytopo.py --topo mytopo –mac –-controller remote

