INTRODUCTION
------------
This is an implementation of firewall based on OpenFlow tutorial

We use OFP_DEFAULT_PRIORITY + 100 to set firewall rules, which is the highest priority in the flow table. Each incoming packet will first try to match this firewall rule. It would be dropped if matched, otherwise go to next rule.

   own_router.py    Multi-switch controller for own topology (mytopo.py)
   firwall.py       Firewall implementation for own topology (mytopo.py)
   mytopo.py        Topology description


HOW TO RUN
------------
#copy own_router.py and firwall.py to pox/pox/misc directory
cd pox
#run controller in one terminal:
./pox.py log.level --DEBUG misc.own_router.py
#create network in another terminal:
sudo mn --custom mytopo.py --topo mytopo –mac –-controller remote

#run firewall
./pox.py log.level --DEBUG misc.firewall.py


