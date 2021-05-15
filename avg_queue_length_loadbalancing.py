from pox.core import core
import pox
import thread
log = core.getLogger("iplb")

from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.revent import EventRemove
from pox.lib.util import str_to_bool, dpid_to_str, str_to_dpid
from time import sleep, time
from subprocess import *
import re
import time
# include as part of the betta branch
from pox.openflow.of_json import *
import pox.openflow.libopenflow_01 as of
import random

FLOW_IDLE_TIMEOUT = 5
FLOW_MEMORY_TIMEOUT =  60* 5
UPDATE_DATA_TRANSFERRED = 14
qavg1=0
qavg2=0


class MemoryEntry (object):
  
  def __init__ (self, server, first_packet, client_port):
    self.server = server
    self.first_packet = first_packet
    self.client_port = client_port
    self.refresh()

  def refresh (self):
    self.timeout = time.time() + FLOW_MEMORY_TIMEOUT

  @property
  def is_expired (self):
    return time.time() > self.timeout

  @property
  def key1 (self):
    ethp = self.first_packet
    ipp = ethp.find('ipv4')
    tcpp = ethp.find('tcp')

    return ipp.srcip,ipp.dstip,tcpp.srcport,tcpp.dstport

  @property
  def key2 (self):
    ethp = self.first_packet
    ipp = ethp.find('ipv4')
    tcpp = ethp.find('tcp')

    return self.server,ipp.srcip,tcpp.dstport,tcpp.srcport

class iplb (object):
  
  def __init__ (self, connection, algorithm, service_ip, weights,servers):
    self.service_ip = IPAddr(service_ip)
    self.servers = [IPAddr(a) for a in servers]
    self.con = connection
    self.mac = self.con.eth_addr
    self.live_servers = {} # IP -> MAC,port
    self.algorithm = algorithm
    self.weights = weights

    try:
      self.log = log.getChild(dpid_to_str(self.con.dpid))
    except:
      # Be nice to Python 2.6 (ugh)
      self.log = log

    self.outstanding_probes = {} # IP -> expire_time

    # How quickly do we probe?
    self.probe_cycle_time = 5

    # Last update in the map of data transferred.
    self.last_update = time.time()
    for server in self.servers:
      print "server ",server

   
    # Variables used in round-robin algorithm.
    self.round_robin_index = 0
    self.round_robin_pck_sent = 0

    # How long do we wait for an ARP reply before we consider a server dead?
    self.arp_timeout = 3

    # We remember where we directed flows so that if they start up again,
    # we can send them to the same server if it's still up.  Alternate
    # approach: hashing.
    self.memory = {} # (srcip,dstip,srcport,dstport) -> MemoryEntry

    self._do_probe() # Kick off the probing

    # As part of a gross hack, we now do this from elsewhere
    #self.con.addListeners(self)

    # Allow user to change algorithm and weights at any time.
    core.Interactive.variables['change_algorithm'] = self._change_algorithm
    core.Interactive.variables['change_weights'] = self._change_weights

  def _change_algorithm(self, algorithm):
    """
    Change the algorithm for load balancing.
    """
    if algorithm not in ALGORITHM_LIST:
      log.error("Algorithm %s is not allowed, allowed algorithms: %s", 
        algorithm, ALGORITHM_LIST.keys())
    else:
      self.algorithm = algorithm
      log.info("Setting algorithm to %s.", self.algorithm)

  def _change_weights(self, weights):
    """
    Change the weights for each server in the balancing.
    """
    if type(weights) is not dict:
      log.error("Weigths should be a dictionary { IP: WEIGHT }.")
    elif sorted(weights.keys()) != sorted(self.weights.keys()):
      log.error("Weights needs to contains all servers")
    else:
      self.weights = { IPAddr(ip): weight for ip, weight in weights.items() }
      log.info("Setting weights to %s.", self.weights)

  def _do_expire (self):
    """
    Expire probes and "memorized" flows
    Each of these should only have a limited lifetime.
    """
    t = time.time()

    # Expire probes
    for ip,expire_at in self.outstanding_probes.items():
      if t > expire_at:
        self.outstanding_probes.pop(ip, None)
        if ip in self.live_servers:
          self.log.warn("Server %s down", ip)
          del self.live_servers[ip]
          # Delete each entry in the table.
          del self.weights[ip]
          # Set the count of packet for round robin as 0.
          self.round_robin_pck_sent = 0

    # Expire old flows
    c = len(self.memory)
    self.memory = {k:v for k,v in self.memory.items()
                   if not v.is_expired}
    if len(self.memory) != c:
      self.log.debug("Expired %i flows", c-len(self.memory))

  def _do_probe (self):
    """
    Send an ARP to a server to see if it's still up
    """
    self._do_expire()

    server = self.servers.pop(0)
    self.servers.append(server)

    r = arp()
    r.hwtype = r.HW_TYPE_ETHERNET
    r.prototype = r.PROTO_TYPE_IP
    r.opcode = r.REQUEST
    r.hwdst = ETHER_BROADCAST
    r.protodst = server
    r.hwsrc = self.mac
    r.protosrc = self.service_ip
    e = ethernet(type=ethernet.ARP_TYPE, src=self.mac,
                 dst=ETHER_BROADCAST)
    e.set_payload(r)
    #self.log.debug("ARPing for %s", server)
    msg = of.ofp_packet_out()
    msg.data = e.pack()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    msg.in_port = of.OFPP_NONE
    self.con.send(msg)

    self.outstanding_probes[server] = time.time() + self.arp_timeout

    core.callDelayed(self._probe_wait_time, self._do_probe)

  @property
  def _probe_wait_time (self):
    """
    Time to wait between probes
    """
    r = self.probe_cycle_time / float(len(self.servers))
    r = max(.25, r) # Cap it at four per second
    return r

  def _pick_server (self, key, inport):
    """
    Pick a server for a (hopefully) new connection
    """
    self.log.debug("Balancing done by the %s algorithm.", self.algorithm)
    return ALGORITHM_LIST[self.algorithm](self)

  def _handle_PacketIn (self, event):
    inport = event.port
    packet = event.parsed

    def drop ():
      if event.ofp.buffer_id is not None:
        # Kill the buffer
        msg = of.ofp_packet_out(data = event.ofp)
        self.con.send(msg)
      return None

    tcpp = packet.find('tcp')
    if not tcpp:
      arpp = packet.find('arp')
      if arpp:
        # Handle replies to our server-liveness probes
        if arpp.opcode == arpp.REPLY:
          if arpp.protosrc in self.outstanding_probes:
            # A server is (still?) up; cool.
            del self.outstanding_probes[arpp.protosrc]
            if (self.live_servers.get(arpp.protosrc, (None,None))
                == (arpp.hwsrc,inport)):
              # Ah, nothing new here.
              pass
            else:
              # Ooh, new server.
              self.live_servers[arpp.protosrc] = arpp.hwsrc,inport
            #  self.data_transferred[arpp.protosrc] = 0
              if arpp.protosrc not in self.weights.keys():
                self.weights[arpp.protosrc] = 1
              self.log.info("Server %s up", arpp.protosrc)
        return

      # Not TCP and not ARP.  Don't know what to do with this.  Drop it.
      return drop()

    # It's TCP.
    ipp = packet.find('ipv4')


    if ipp.srcip in self.servers:
      # It's FROM one of our balanced servers.
      # Rewrite it BACK to the client

      key = ipp.srcip,ipp.dstip,tcpp.srcport,tcpp.dstport
      entry = self.memory.get(key)

      if entry is None:
        # We either didn't install it, or we forgot about it.
        self.log.debug("No client for %s", key)
        return drop()

      # Refresh time timeout and reinstall.
      entry.refresh()
      #self.log.debug("Install reverse flow for %s", key)

      # Install reverse table entry
      mac,port = self.live_servers[entry.server]

      actions = []
      actions.append(of.ofp_action_dl_addr.set_src(self.mac))
      actions.append(of.ofp_action_nw_addr.set_src(self.service_ip))
      actions.append(of.ofp_action_output(port = entry.client_port))
      match = of.ofp_match.from_packet(packet, inport)

      msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                            idle_timeout=FLOW_IDLE_TIMEOUT,
                            hard_timeout=of.OFP_FLOW_PERMANENT,
                            data=event.ofp,
                            actions=actions,
                            match=match)
      
      self.con.send(msg)

    elif ipp.dstip == self.service_ip:
      # Ah, it's for our service IP and needs to be load balanced
      # Do we already know this flow?
      key = ipp.srcip,ipp.dstip,tcpp.srcport,tcpp.dstport
      entry = self.memory.get(key)
      if entry is None or entry.server not in self.live_servers:
        # Don't know it (hopefully it's new!)
        if len(self.live_servers) == 0:
          self.log.warn("No servers!")
          return drop()

        # Pick a server for this flow
        server = self._pick_server(key, inport)
        self.log.debug("Directing traffic to %s", server)
        entry = MemoryEntry(server, packet, inport)
        self.memory[entry.key1] = entry
        self.memory[entry.key2] = entry

      # Update timestamp
      entry.refresh()

      # Set up table entry towards selected server
      mac,port = self.live_servers[entry.server]

      actions = []
      actions.append(of.ofp_action_dl_addr.set_dst(mac))
      actions.append(of.ofp_action_nw_addr.set_dst(entry.server))
      actions.append(of.ofp_action_output(port = port))
      match = of.ofp_match.from_packet(packet, inport)

      msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                            idle_timeout=FLOW_IDLE_TIMEOUT,
                            hard_timeout=of.OFP_FLOW_PERMANENT,
                            data=event.ofp,
                            actions=actions,
                            match=match)
      
      self.con.send(msg)

def round_robin_alg (balancer):
  """
  Select the next server for load balancing using the round-robin algorithm.
  """
  length = len(balancer.live_servers.keys())
  if balancer.round_robin_index >= length:
    balancer.round_robin_index = 0
  server_selected = list(balancer.live_servers.keys())[balancer.round_robin_index]
  balancer.round_robin_pck_sent = balancer.round_robin_pck_sent + 1
  
  if balancer.round_robin_pck_sent == balancer.weights[server_selected]:
    balancer.round_robin_index += 1
    balancer.round_robin_pck_sent = 0

  return server_selected

def random_alg (balancer):
  """
  Select a random server for load balancer.
  """
  return random.choice(balancer.live_servers.keys())


def monitor_qlen_alg(balancer,interval_sec=1):
    global qavg2,qavg1
    server_selected = list(balancer.live_servers.keys())[1]
    pat_queued =re.compile(r'backlog\s[^\s]+\s([\d]+)p')

    cmd1 = "tc -s qdisc show dev s1-eth1"
    cmd2 = "tc -s qdisc show dev s1-eth2"

    p1 = Popen(cmd1, shell=True, stdout=PIPE)
    p2 = Popen(cmd2, shell=True, stdout=PIPE)

    output1 = p1.stdout.read()
    output2 = p2.stdout.read()

    matches1 = pat_queued.findall(output1)
    matches2 = pat_queued.findall(output2)
    if (matches1 and len(matches1))and (matches2 and len(matches2))  > 1:
     iq1=matches1[1]
     iq2= matches2[1]
     qavg1=0.5*qavg1+int(iq1)*0.5

     qavg2=0.5*qavg2+int(iq2)*0.5
 
    print "qavg1",qavg1,"qavg2",qavg2
    if  (qavg1==0.0 or qavg1 < qavg2 ):

        server_selected = list(balancer.live_servers.keys())[0]
    elif (qavg2==0.0 or qavg2< qavg1):
        server_selected = list(balancer.live_servers.keys())[1]

    return server_selected
 
# List of algorithms allowed in the load balancer.
ALGORITHM_LIST = { 
  'round-robin': round_robin_alg, 
 
  'random': random_alg,
  'monitor_qlen':monitor_qlen_alg 
}

# Remember which DPID we're operating on (first one to connect)
_dpid = None

def launch (ip,servers, weights_val = [], dpid = None, algorithm = 'monitor_qlen'):
  global _dpid
  global _algorithm

  if dpid is not None:
    _dpid = str_to_dpid(dpid)

  if algorithm not in ALGORITHM_LIST:
    log.error("Algorithm %s is not allowed, allowed algorithms: %s", 
      algorithm, ALGORITHM_LIST.keys())
    exit(1)

  # Getting the servers IP.
  servers = servers.replace(","," ").split()
  servers = [IPAddr(x) for x in servers]

  # Parsing the weights for each server.
  weights = {}
  if len(weights_val) is 0:
    weights_val = ""
    for x in servers:
      weights_val += "1,"

  weights_val = weights_val.replace(",", " ").split()

  if len(weights_val) is not len(servers):
    log.error("Weights array is not the same length than servers array")
    exit(1)

  for i in range(len(servers)):
    weights[servers[i]] = int(weights_val[i])

  # Getting the controller IP.
  ip = IPAddr(ip)

  # We only want to enable ARP Responder *only* on the load balancer switch,
  # so we do some disgusting hackery and then boot it up.
  from proto.arp_responder import ARPResponder
  old_pi = ARPResponder._handle_PacketIn

  def new_pi (self, event):
    if event.dpid == _dpid:
      # Yes, the packet-in is on the right switch
      return old_pi(self, event)
  ARPResponder._handle_PacketIn = new_pi

  # Hackery done.  Now start it.
  from proto.arp_responder import launch as arp_launch
  arp_launch(eat_packets=False,**{str(ip):True})

  import logging
  logging.getLogger("proto.arp_responder").setLevel(logging.WARN)

  def _handle_ConnectionUp (event):
    global _dpid
    if _dpid is None:
      _dpid = event.dpid

    if _dpid != event.dpid:
      log.warn("Ignoring switch %s", event.connection)
    else:
      if not core.hasComponent('iplb'):
        # Need to initialize first...
  
        core.registerNew(iplb, event.connection, algorithm, 
          IPAddr(ip), weights, servers)

        log.info("IP Load Balancer Ready.")
      log.info("Load Balancing on %s", event.connection)

      # Gross hack
      core.iplb.con = event.connection
      event.connection.addListeners(core.iplb)


  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)

  from pox.lib.recoco import Timer

  # Send the flow stats to all the switches connected to the controller.
  def _timer_func ():
    for connection in core.openflow._connections.values():
      connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
  # Request flow stats every FLOW_IDLE_TIMEOUT second.
  Timer(FLOW_IDLE_TIMEOUT, _timer_func, recurring=True) 
