from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.ipv6 import ipv6
from pox.lib.addresses import IPAddr, EthAddr
import time
import csv

log = core.getLogger()

_flood_delay = 0

class Firewall(object):
  def __init__ (self, connection, transparent):
    self.connection = connection
    self.transparent = transparent

    # Our table
    self.macToPort = {}

    # Our firewall table in the form of Dictionary
    self.firewall = {}

    # Add a Couple of Rules Static entries
    # Two type of rules: (srcip,dstip) or (dstip,dstport)
    with open('firewall-policies.csv', mode='r') as csv_file:
      csv_reader = csv.DictReader(csv_file)
      for row in csv_reader:
        m = 0
        sip = 0
        dip = 0
        if(row['mac']!='0'):
          m=EthAddr(row['mac'])
        if(row['srcip']!='0'):
          sip= IPAddr(row['srcip'])
        if(row['dstip']!='0'):
          dip= IPAddr(row['dstip'])
        self.AddRule(dpid_to_str(connection.dpid),m, sip, dip, int(row['dstport']))

      #print(f'Added rule: \t Source mac: {row["name"]} works in the {row["department"]} department, and was born in {row["birthday month"]}.')
    #self.AddRule(dpid_to_str(connection.dpid), EthAddr('00:00:00:00:00:02'), 0, 0, 0)
    #self.AddRule(dpid_to_str(connection.dpid), 0, IPAddr('10.0.0.1'), IPAddr('10.0.0.4'),0)
    #self.AddRule(dpid_to_str(connection.dpid), 0, 0, IPAddr('10.0.0.3'), 80)
    # We want to hear PacketIn messages, so we listen
    # to the connection
    #log.info("Firewall rules installed on %s", dpid_to_str(connection.dpid))
    connection.addListeners(self)

    # We just use this to know when to log a helpful message
    self.hold_down_expired = _flood_delay == 0

  def AddRule (self, dpidstr, macstr, srcipstr, dstipstr, dstport,value=True):
      if srcipstr == 0 and dstipstr == 0:
        self.firewall[(dpidstr,macstr)] = True
        log.debug("Adding L2-firewall rule of Src(%s) in %s", macstr, dpidstr)
      elif dstport == 0:
        self.firewall[(dpidstr,srcipstr,dstipstr)] = True
        log.debug("Adding L3-firewall rule of %s -> %s in %s", srcipstr, dstipstr, dpidstr)
      elif srcipstr == 0:
        self.firewall[(dpidstr,dstipstr,dstport)] = True
        log.debug("Adding L4-firewall rule of Dst(%s,%s) in %s", dstipstr, dstport, dpidstr)
      else:
        self.firewall[(dpidstr,srcipstr,dstipstr,dstport)] = True
        log.debug("Adding firewall rule of %s -> %s,%s in %s", srcipstr, dstipstr, dstport, dpidstr)

  # function that allows deleting firewall rules from the firewall table
  def DeleteRule (self, dpidstr, macstr, srcipstr, dstipstr, dstport):
     try:
       if srcipstr == 0 and dstipstr == 0:
         del self.firewall[(dpidstr,macstr)]
         log.debug("Deleting L2-firewall rule of Src(%s) in %s", macstr, dpidstr)
       elif dstport == 0:
         del self.firewall[(dpidstr,srcipstr,dstipstr)]
         log.debug("Deleting L3-firewall rule of %s -> %s in %s", srcipstr, dstipstr, dpidstr)
       elif srcipstr == 0:
         del self.firewall[(dpidstr,dstipstr,dstport)]
         log.debug("Deleting L4-firewall rule of Dst(%s,%s) in %s", dstipstr, dstport, dpidstr)
       else:
         del self.firewall[(dpidstr,srcipstr,dstipstr,dstport)]
         log.debug("Deleting firewall rule of %s -> %s,%s in %s", srcipstr, dstipstr, dstport, dpidstr)
     except KeyError:
       log.error("Cannot find Rule %s(%s) -> %s,%s in %s", srcipstr, macstr, dstipstr, dstport, dpidstr)

  # check if packet is compliant to rules before proceeding
  def CheckRule (self, dpidstr, macstr, srcipstr, dstipstr, dstport):
    # Source Link blocked
    try:
      entry = self.firewall[(dpidstr, macstr)]
      log.info("L2-Rule Src(%s) block found in %s: DROP", macstr, dpidstr)
      return entry
    except KeyError:
      pass
      #log.debug("Rule Src(%s) NOT found in %s: L2-Rule NOT found", macstr, dpidstr)

    # Host to Host blocked
    try:
      entry = self.firewall[(dpidstr, srcipstr, dstipstr)]
      log.info("L3-Rule (%s x->x %s) found in %s: DROP", srcipstr, dstipstr, dpidstr)
      return entry
    except KeyError:
      pass
      #log.debug("Rule (%s -> %s) NOT found in %s: L3-Rule NOT found", srcipstr, dstipstr, dpidstr)

    # Destination Process blocked
    try:
      entry = self.firewall[(dpidstr, dstipstr, dstport)]
      log.info("L4-Rule Dst(%s,%s)) found in %s: DROP", dstipstr, dstport, dpidstr)
      return entry
    except KeyError:
      pass
      #log.debug("Rule Dst(%s,%s) NOT found in %s: L4-Rule NOT found", dstipstr, dstport, dpidstr)
    #print("No rules stoppin me :)")
    return False

  def _handle_PacketIn (self, event):
    """
    Handle packet in messages from the switch to implement above algorithm.
    """

    packet = event.parsed
    inport = event.port
    #print(packet)
    def flood (message = None):
      """ Floods the packet """
      msg = of.ofp_packet_out()
      if time.time() - self.connection.connect_time >= _flood_delay:
        # Only flood if we've been connected for a little while...

        if self.hold_down_expired is False:
          # Oh yes it is!
          self.hold_down_expired = True
          log.info("%s: Flood hold-down expired -- flooding", dpid_to_str(event.dpid))

        if message is not None: log.debug(message)
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        pass
        #log.info("Holding down flood for %s", dpid_to_str(event.dpid))
      msg.data = event.ofp
      msg.in_port = event.port
      self.connection.send(msg)

    def drop (duration = None):
      """
      Drops this packet and optionally installs a flow to continue
      dropping similar ones for a while
      """
      if duration is not None:
        if not isinstance(duration, tuple):
          duration = (duration,duration)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
      elif event.ofp.buffer_id is not None:
        msg = of.ofp_flow_mod() #creats a flow modification message
        msg.match = of.ofp_match.from_packet(event.parsed, event.port)
        msg.match.dl_dst = None
        msg.idle_timeout = 120
        msg.hard_timeout = 120
        msg.priority = 65535 #priority at which a rule will match, higher is better.
        msg.command = of.OFPFC_MODIFY
        msg.flags = of.OFPFF_CHECK_OVERLAP
        msg.data = event.ofp
        self.connection.send(msg)# send the message to the OpenFlow switch

    self.macToPort[packet.src] = event.port # 1

    # Get the DPID of the Switch Connection
    dpidstr = dpid_to_str(event.connection.dpid)
    #log.debug("Connection ID: %s" % dpidstr)

    if isinstance(packet.next, ipv4):
      log.debug("%i IP %s => %s , in switch %s", inport, packet.next.srcip,packet.next.dstip,dpidstr)
      segmant = packet.find('tcp')
      if segmant is None:
        segmant = packet.find('udp')
      if segmant is not None:
        # Check the Firewall Rules in MAC, IPv4 and TCP Layer
        if self.CheckRule(dpidstr, packet.src, packet.next.srcip, packet.next.dstip, segmant.dstport) == True:
          drop()
          return
      else:
        # Check the Firewall Rules in MAC and IPv4 Layer
        if self.CheckRule(dpidstr, packet.src, packet.next.srcip, packet.next.dstip, 0) == True:
          drop()
          return
    elif isinstance(packet.next, arp):
      # Check the Firewall Rules in MAC Layer
      if self.CheckRule(dpidstr, packet.src, 0, 0, 0) == True:
        drop()
        return
      a = packet.next
      log.debug("%i ARP %s %s => %s", inport, {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode, 'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst))
    elif isinstance(packet.next, ipv6):
      # Do not handle ipv6 packets
      return

    if not self.transparent: # 2
      if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
        drop() # 2a
        return

    if packet.dst.is_multicast:
      flood() # 3a
    else:
      if packet.dst not in self.macToPort: # 4
        flood("Port for %s unknown -- flooding" % (packet.dst,)) # 4a
      else:
        port = self.macToPort[packet.dst]
        if port == event.port: # 5
          # 5a
          log.warning("Same port for packet from %s -> %s on %s.%s.  Drop." % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
          drop(10)
          return
        # 6
        log.debug("installing flow for %s.%i -> %s.%i" % (packet.src, event.port, packet.dst, port))
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp # 6a
        self.connection.send(msg)

class firewall (object):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  def __init__ (self, transparent):
    core.openflow.addListeners(self)
    self.transparent = transparent

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    Firewall(event.connection, self.transparent)


def launch (transparent=False, hold_down=_flood_delay):
  """
  Starts firewall
  """
  print("Starting firewall....")
  print("Importing Rules from firewall-policies.csv......")

  try:
    global _flood_delay
    _flood_delay = int(str(hold_down), 10)
    assert _flood_delay >= 0
  except:
    raise RuntimeError("Expected hold-down to be a number")

  core.registerNew(firewall, str_to_bool(transparent))
