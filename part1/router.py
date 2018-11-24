import struct
from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

def getpacket(event):
  return event.parsed,event.ofp,event.dpid
route =[['10.0.1.100/24', '10.0.1.100', 's1-eth1', '10.0.1.1', 1],
        ['10.0.2.100/24', '10.0.2.100', 's1-eth2', '10.0.2.1', 2],
        ['10.0.3.100/24', '10.0.3.100', 's1-eth3', '10.0.3.1', 3]]
gateways = ['10.0.1.1','10.0.2.1','10.0.3.1']
class MyRouter (object):
  def __init__ (self, fakeways=[], arp_unkown=False):
    core.openflow.addListeners(self)
    self.connection={}
    self.arp_table={}
    self.route_table={}
    self.mac_to_port={}
    self.ip_to_port={}
    self.arp_queue={}
    self.fakeways={}
    self.mac={}
  def _handle_ConnectionDown(self,event):
    dpid=event.dpid
    log.debug("switch %s has been closed", str(dpid))
    self.connection[dpid]={}
    self.arp_table[dpid]={}
    self.route_table[dpid]={}
    self.mac_to_port[dpid]={}
    self.ip_to_port[dpid]={}
    self.arp_queue[dpid]={}

  def _handle_ConnectionUp(self,event):
    dpid=event.dpid
    log.debug("switch %s has come up.", str(dpid))
    self.connection[dpid] = event.connection

    self.mac_to_port[dpid] = {}
    self.arp_table[dpid] = {}
    self.route_table[dpid] = route
    self.arp_queue[dpid] = {}
    self.ip_to_port[dpid]={}
    self.mac[dpid] = EthAddr("00:00:11:00:00:"+str(10+dpid))
    self.fakeways[dpid]=gateways
#    self.set_switch_mac(dpid)

  def set_switch_mac(self, dpid):

    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match(dl_dst=self.mac[dpid])
    msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
    msg.priority = 1
    self.connection[dpid].send(msg)

  def send_arp_queue(self,dpid,ip):
    ip = str(ip)
    if ip not in self.arp_queue[dpid]: return
    for (buffid, inport) in self.arp_queue[dpid][ip]:
      msg = of.ofp_packet_out(buffer_id=buffid, in_port=inport)
      msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arp_table[dpid][ip]))
      msg.actions.append(of.ofp_action_output(port = self.ip_to_port[dpid][ip]))
      self.connection[dpid].send(msg)
      log.debug("send arp queue dst=%s to port %d",ip,self.ip_to_port[dpid][ip])
    self.arp_queue[dpid][ip]=[]
  
  def add_arp_queue(self, dstip, dpid,  packet_in):
    if dstip not in self.arp_queue[dpid]:
      self.arp_queue[dpid][dstip]=[]
    log.debug("add queue %s buffer_id=%s",dstip,str(packet_in.buffer_id))
    self.arp_queue[dpid][dstip].append((packet_in.buffer_id, packet_in.in_port))


  def find_route(self, dstip, dpid):
    for rte in self.route_table[dpid]:
      net,mask = rte[0].split('/')
      net1 = net.split('.')
      net2 = str(dstip).split('.')
      #print (net1, net2)
      if net1[0]==net2[0] and net1[1]==net2[1] and net1[2]==net2[2]:
        return rte
    return None

  def resend_packet (self, packet_in, out_port, dpid):
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection[dpid].send(msg)


  def act_like_hub (self, event):
    packet,packet_in,dpid=getpacket(event)
    self.resend_packet(packet_in, of.OFPP_ALL, dpid)

    # Note that if we didn't get a valid buffer_id, a slightly better
    # implementation would check that we got the full data before
    # sending it (len(packet_in.data) should be == packet_in.total_len)).


  def act_like_switch (self, event):
    packet,packet_in,dpid = getpacket(event)
    smac = str(packet.src)
    dmac = str(packet.dst)
    self.mac_to_port[dpid][smac] = packet_in.in_port

    if dmac in self.mac_to_port[dpid]:
      # Send packet out the associated port
      out_port=self.mac_to_port[dpid][dmac]
      self.resend_packet(packet_in, out_port, dpid)


      log.debug("switch "+str(dpid)+" port "+str(out_port)+" flow "+smac)

      msg = of.ofp_flow_mod()
      
      # Set fields to match received packet
      msg.match = of.ofp_match.from_packet(packet)
      msg.idle_timeout = 120
      msg.actions.append(of.ofp_action_output(port=out_port))
      #< Set other fields of flow_mod (timeouts? buffer_id?) >
      #
      #< Add an output action, and send -- similar to resend_packet() >
      self.connection[dpid].send(msg)
    else:
      # Flood the packet out everything but the input port
      # This part looks familiar, right?
      self.resend_packet(packet_in, of.OFPP_ALL, dpid)

  def send_arp_reply(self, event):
    packet,packet_in,dpid = getpacket(event)
    arp = packet.find('arp')
    a = pkt.arp()
    a.opcode = a.REPLY
    a.protodst = arp.protosrc
    a.protosrc = arp.protodst
    a.hwdst = packet.src
    a.hwsrc = self.mac[dpid]
    e=pkt.ethernet(type=packet.ARP_TYPE, src=a.hwsrc, dst=a.hwdst)
    e.set_payload(a)
    msg = of.ofp_packet_out()
    msg.data = e.pack()
    msg.actions.append(of.ofp_action_output(port=packet_in.in_port))
    self.connection[dpid].send(msg)
    log.debug("arp reply (%s %s) to %s",str(a.protosrc),str(a.hwsrc),str(a.hwdst))

  def send_arp_req(self, packet, dpid):
    rte = self.find_route(packet.next.dstip, dpid)
    if rte==None: return
    a = pkt.arp()
    a.opcode = a.REQUEST
    a.protodst = packet.next.dstip
    a.protosrc = IPAddr(rte[3])
    a.hwtype = a.HW_TYPE_ETHERNET
    a.prototype = a.PROTO_TYPE_IP
    a.hwlen = 6
    a.hwdst = pkt.ETHER_BROADCAST
    a.hwsrc = self.mac[dpid]
    e=pkt.ethernet(type=packet.ARP_TYPE, src=a.hwsrc, dst=pkt.ETHER_BROADCAST)
    e.set_payload(a)
    msg = of.ofp_packet_out()
    msg.data = e.pack()
    msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
    msg.in_port = rte[4]
    self.connection[dpid].send(msg)
    log.debug("send arp req (%s) port %s",str(a.protodst),str(msg.in_port))

  def handle_arp(self,event):
    packet,packet_in,dpid=getpacket(event)
    a=packet.find('arp')
    if a.prototype != a.PROTO_TYPE_IP or a.hwtype != a.HW_TYPE_ETHERNET:
      log.debug("unknown arp")
      return
    sip=str(a.protosrc)
    smac=str(a.hwsrc)
    if sip in self.arp_table[dpid]:
      if self.arp_table[dpid][sip] != smac:
        log.debug("arp rewrite for "+(smac)+" to "+(sip)) 
    else:
      log.debug("add arp entry: mac="+(smac)+" ip="+(sip))
    self.arp_table[dpid][sip]=smac
    self.ip_to_port[dpid][sip]=packet_in.in_port
    out_port=packet_in.in_port

    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match(dl_type=pkt.ethernet.IP_TYPE, nw_dst=sip)
    #msg.idle_timeout = 120
    msg.actions.append(of.ofp_action_dl_addr.set_dst(a.hwsrc))
    msg.actions.append(of.ofp_action_dl_addr.set_src(self.mac[dpid]))
    msg.actions.append(of.ofp_action_output(port=out_port))
    self.connection[dpid].send(msg)
    log.debug("recv arp from (%s, %s)", sip, smac)
    log.debug("add flow entry (ip=%s) port %d", sip, out_port)    
    self.send_arp_queue(dpid, sip)
    if a.opcode == a.REPLY:
      return

    dip=str(a.protodst)
    if dip in self.fakeways[dpid]:
      return self.send_arp_reply(event)
    elif self.find_route(dip,dpid) == None:
      return self.send_unreachable(event)
    #elif a.opcode == a.REQUEST:
      #return self.resend_packet(packet_in, of.OFPP_FLOOD)
    else:
      log.debug("unknown arp packet, opcode="+str(a.opcode))

  def send_unreachable(self,event):
    packet,packet_in,dpid=getpacket(event)
    icmp=pkt.icmp()
    ip = packet.find('ipv4')
    rte = self.find_route(ip.srcip, dpid)
    if rte == None: return
    dstip = ip.dstip
    payload = ip.pack()
    payload = payload[:ip.hl * 4 + 8]
    payload = struct.pack("!HH", 0, 0) + payload
    icmp.payload = payload
    icmp.type=pkt.TYPE_DEST_UNREACH
    ip = pkt.ipv4()
    ip.protocol = ip.ICMP_PROTOCOL
    ip.srcip = IPAddr(rte[3])
    ip.dstip = packet.find('ipv4').srcip
    ip.payload = icmp

    eth=pkt.ethernet()
    eth.src = packet.dst
    eth.dst = packet.src
    eth.type = eth.IP_TYPE
    eth.payload = ip
    self.resend_packet(eth.pack(), packet_in.in_port, dpid)
    log.debug("%s is unreachable to %s", str(dstip), str(ip.dstip))
 
  def handle_icmp(self,event):
    packet,packet_in,dpid=getpacket(event)
    dstip=str(packet.find('ipv4').dstip)
    srcip=str(packet.find('ipv4').srcip)
    log.debug("recv icmp dst=%s src=%s", dstip, srcip)    
    if self.find_route(dstip, dpid) == None:
      rte=self.find_route(srcip, dpid)
      return self.send_unreachable(event, rte)

    i=packet.find('icmp')
    if i.type==pkt.TYPE_ECHO_REQUEST:
      icmp=pkt.icmp()
      icmp.payload = i.payload
      icmp.type=pkt.TYPE_ECHO_REPLY
      ip = pkt.ipv4()
      ip.protocol = ip.ICMP_PROTOCOL
      ip.srcip = packet.find('ipv4').dstip
      ip.dstip = packet.find('ipv4').srcip
      ip.payload = icmp      

      eth=pkt.ethernet()
      eth.src = packet.dst
      eth.dst = packet.src
      eth.type = eth.IP_TYPE
      eth.payload = ip
      self.resend_packet(eth.pack(), packet_in.in_port, dpid)
      log.debug("send icmp reply to %s port %d",str(ip.dstip), packet_in.in_port) 

  def act_like_router(self, event):
    packet,packet_in,dpid=getpacket(event)
    arp=packet.find('arp')

    if packet.dst != pkt.ETHER_BROADCAST and packet.dst != self.mac[dpid]:
        log.debug("unknown packet from %s" % (packet_in.in_port))
        return
    if arp: return self.handle_arp(event)
    
    ip = packet.find('ipv4')
    icmp=packet.find('icmp')
    if ip and (str(ip.dstip) not in self.fakeways[dpid]):
      dstip = str(ip.dstip)
      if self.find_route(dstip, dpid) == None:
        return self.send_unreachable(event)
      else:
        self.add_arp_queue(dstip, dpid, packet_in)
        return self.send_arp_req(packet,  dpid)

    if icmp: return self.handle_icmp(event)

    log.debug("unspported packet from %s" % (packet_in.in_port))
    #self.act_like_switch(event)

  def _handle_PacketIn (self, event):

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    # Comment out the following line and uncomment the one after
    # when starting the exercise.
    #self.act_like_hub(event)
    #self.act_like_switch(event)
    self.act_like_router(event)


def launch ():
  """
  Starts the component
  """
  core.registerNew(MyRouter)

