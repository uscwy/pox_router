import struct
from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

def getpacket(event):
  return event.parsed,event.ofp,event.dpid
class MyModule (object):
  def __init__ (self):
    core.openflow.addListeners(self)
    self.mac_to_port={}
    self.connection={}

  def _handle_ConnectionDown(self,event):
    dpid=event.dpid
    log.debug("switch %s has been closed", str(dpid))
    self.connection[dpid]={}
    self.mac_to_port[dpid]={}

  def _handle_ConnectionUp(self,event):
    dpid=event.dpid
    log.debug("switch %s has come up.", str(dpid))
    self.connection[dpid] = event.connection

    self.mac_to_port[dpid] = {}

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


    if packet.dst != pkt.ETHER_BROADCAST and dmac in self.mac_to_port[dpid]:
      # Send packet out the associated port
      out_port=self.mac_to_port[dpid][dmac]
      self.resend_packet(packet_in, out_port, dpid)


      log.debug("flow %s -> %s to port %d", smac, dmac, out_port)
      msg = of.ofp_flow_mod()

      
      # Set fields to match received packet
      msg.match = of.ofp_match.from_packet(packet)
      #< Set other fields of flow_mod (timeouts? buffer_id?) >
      #
      #< Add an output action, and send -- similar to resend_packet() >
      msg.actions.append(of.ofp_action_output(port=out_port))
      self.connection[dpid].send(msg)
    else:
      # Flood the packet out everything but the input port
      # This part looks familiar, right?
      log.debug("flood %s->%s", smac,dmac)
      self.resend_packet(packet_in, of.OFPP_ALL, dpid)

    #if packet.dst != pkt.ETHER_BROADCAST:
    #  msg.match = of.ofp_match.from_packet(packet)
    #  msg.actions.append(of.ofp_action_output(port=out_port))
    #  self.connection[dpid].send(msg)

  def _handle_PacketIn (self, event):

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    # Comment out the following line and uncomment the one after
    # when starting the exercise.
    #self.act_like_hub(event)
    self.act_like_switch(event)


def launch ():
  """
  Starts the component
  """
  core.registerNew(MyModule)

