from pox.core import core
from pox.openflow import *
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import EthAddr, IPAddr
log = core.getLogger()
import time
import random
import threading
import datetime
import matplotlib.pyplot as plt
import numpy as np

#This is our dictionary for the counter for our servers. 
dictReq ={}
# This is our main class for the balancer
class LoadBalancer(object):
	global dictReq
	def __init__(self, service_ip, server_ips = [],weights=[],flag=0): #initialize 10.1.2.3 and servers
		core.openflow.addListeners(self)# hear Packet in, so we listen to connection		
		#Initialization of different dicitonaries and other stuff
		self.macToPort = {} 								#table to store ip mac and ouport after request
		self.client_table={} 								# dictionary to handle clients in LB
		self.lb_map={}
		self.lb_real_ip=service_ip 							# the real ip of LB
		self.server_ips=server_ips 							# a list holds the input servers 
		self.total_servers=len(server_ips) 					#the length of the servers 
		self.flag=flag
		self.total_weight = sum(weights) # Change to set equal to sum of weight
		self.current_weight = 0
		self.weights = weights # Store weights here according to ascending order of ip for all server ips
		self.current_sends = [0 for i in range(self.total_servers)]
		self.current_server_index = 0

	#Connect the controller with the switch and flood servers with arp requests.
	def _handle_ConnectionUp(self, event): 					#new switch connection
		self.lb_mac = EthAddr("0A:00:00:00:00:01") 			#fake mac of load balancer
		self.connection = event.connection
		self.ethernet_broad=EthAddr("ff:ff:ff:ff:ff:ff") 	#broadcast MAC to transmit to all possible interfaces 
		for ip in self.server_ips:
			selected_server_ip= ip
			self.send_proxied_arp_request(self.connection,selected_server_ip) # here will flood ARP requests to all serveres to match Ips with mac and ports 
	

	# The plot work is done here, after we quit mininet.	
	def _handle_ConnectionDown (self, event): 
		N = self.total_servers
		# count1 = dictReq['10.0.0.5']
		# count2 = dictReq['10.0.0.6']
		# count3 = dictReq['10.0.0.7']
		# count4 = dictReq['10.0.0.8']

		#Counter = (count1, count2, count3, count4)
		std = (0, 0, 0, 0)

		ind = np.arange(N)  # the x locations for the groups
		width = 0.5       # the width of the bars

		fig, ax = plt.subplots()
		rects1 = ax.bar(ind, dictReq.values(), width, color='r', yerr=std)

		# add some text for labels, title and axes ticks
		ax.set_ylabel('Requests')
		ax.set_xlabel('IPs')
		ax.set_title('Request per server ip')
		ax.set_xticks(ind + width / 2)
		ax.set_xticklabels(dictReq.keys())

		# upload the file to the directory we are in.
		fig.savefig("graph.png")
		plt.show()


	# Here we update the mapping dict with the new random server.
	def update_lb_mapping_random(self, client_ip): 					#update load balancing map
		if client_ip in self.client_table.keys():
			print(dictReq)
			random_server=random.choice(self.macToPort.keys())
			log.info("Redirecting to Server  %s "% random_server)
			dictReq.update({str(random_server):(dictReq[str(random_server)] + 1)})
			self.lb_map[client_ip]=random_server			#pass to a dictionary the random server and the client ip


	def update_lb_mapping(self, client_ip): 					#update load balancing map
	
	# To change here
		if client_ip in self.client_table.keys():
			if self.current_weight == self.total_weight:
				self.current_sends = [0 for i in range(self.total_servers)]
				self.current_weight = 0
			while (self.current_sends[self.current_server_index] >= self.weights[self.current_server_index]):
				self.current_server_index = (self.current_server_index + 1) % self.total_servers
			
			self.current_weight += 1
			self.current_sends[self.current_server_index] += 1
			server = self.server_ips[self.current_server_index]
			self.current_server_index = (self.current_server_index + 1) % self.total_servers
			log.info(" Redirected to  %s "% server)
			dictReq.update({str(server):(dictReq[str(server)] + 1)})
			self.lb_map[client_ip]=server			#pass to a dictionary the random server and the client ip


	#An ARP reply packet is created and proxied with packet out from the controller		
	def send_proxied_arp_reply(self, packet, connection, outport, requested_mac):
		#reply to ARP request
		r=arp();
		r.hwtype = r.HW_TYPE_ETHERNET 	#type of hardware tyr
		r.prototype = r.PROTO_TYPE_IP 	#protocol type
		r.hwlen = 6  					#hardware address length 6 bytes and mac=ipv6 
		r.protolen = r.protolen 		#the ipv4 length 
		r.opcode = r.REPLY				# the packet has Reply type 

		r.hwdst = packet.src  
		r.hwsrc =requested_mac				#fake mac
		
		r.protosrc = packet.payload.protodst 
		r.protodst = packet.payload.protosrc

		e = ethernet(type=packet.ARP_TYPE, src=requested_mac, dst=packet.src)
		e.set_payload(r)
		
		msg = of.ofp_packet_out()
		msg.data = e.pack()
		#send the message through the client outport 
		msg.actions.append(of.ofp_action_output(port =of.OFPP_IN_PORT)) # in which port clients can hear 
		msg.in_port = outport
		connection.send(msg)
		

	#Send ARP reqs flood to know  macth ip mac port of servers  		
	def send_proxied_arp_request(self, connection, ip):
											#construct the arp packet
		ar=arp() 							#type of packet
		ar.hwtype = ar.HW_TYPE_ETHERNET 	#type of hardware tyr
		ar.prototype = ar.PROTO_TYPE_IP 	#protocol type
		ar.hwlen = 6  						#hardware addrese length 6 bytes and mac=ipv6 
		ar.protolen = ar.protolen 			#the ipv4 length 
		ar.opcode = ar.REQUEST
		ar.hwdst = self.ethernet_broad 		# broadcast to all possible  interfaces
		ar.protodst = ip 					#ip dest to send 
		ar.hwsrc = self.lb_mac 				#fake mac address
		ar.protosrc = self.lb_real_ip 		# the real ip of the address

											# packet has inside it the r packet 
		e = ethernet(type=ethernet.ARP_TYPE, src=self.lb_mac, dst=self.ethernet_broad)
		e.set_payload(ar) 					# take the previous packet and put it into th message data
		
		msg = of.ofp_packet_out() 			# send packet out cause we dont need an entry in the flow table 
		msg.data = e.pack()			
		msg.actions.append(of.ofp_action_nw_addr(of.OFPAT_SET_NW_DST,ip)) 	# send to this ip 
		msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD)) 		# flood to all ports
		
		connection.send(msg)
		

	# Install the flow rule from the client to the server.
	def install_flow_rule_client_to_server(self,event, connection, outport, client_ip, 
						server_ip, buffer_id=of.NO_BUFFER):				
		self.install_flow_rule_server_to_client(connection, event.port, server_ip,client_ip)
		
		msg=of.ofp_flow_mod() 				# the way the message will be send 
		msg.idle_timeout=3
		msg.hard_timeout=1				# if not this link not used afte 10sec delete  rule from flow
		msg.command=of.OFPFC_ADD			# tell the switch to add rule 
		msg.buffer_id=buffer_id				#set the buffer
		
											# what data will have the packet in 
											# match the message
		msg.match.dl_type=ethernet.IP_TYPE	# match the type to be IP type		
		msg.match.nw_src=client_ip 			# match the msg network source ip for the rule
		msg.match.nw_dst=self.lb_real_ip	# match the msg  networkdst ip  for the rule 

		msg.actions.append(of.ofp_action_dl_addr.set_src(self.lb_mac)) 		#from which mac the msg will be send (fake mac)
		msg.actions.append(of.ofp_action_dl_addr.set_dst(self.macToPort[server_ip].get('server_mac'))) #the servers eth address
		
		msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip)) 		# will send he packet to this server ip 		
		
		msg.actions.append(of.ofp_action_output(port=outport)) 				#the port which the packet will pass 
		
		self.connection.send(msg)

		#log.info("Install flow rule from Client: %s -------> Server: %s"%(client_ip,server_ip))


	# Install the flow rule from the server to the client.
	def install_flow_rule_server_to_client(self, connection, outport, server_ip, 
						client_ip, buffer_id=of.NO_BUFFER):
		msg=of.ofp_flow_mod()
		msg.command=of.OFPFC_ADD
		
		msg.match.dl_type=ethernet.IP_TYPE 	# match the type to be IP type		
		msg.match.nw_src=server_ip			# match the msg network source ip 
		msg.match.nw_dst=client_ip			# match the msg  networkdst ip 
		msg.idle_timeout=10 				# if not this link not used afte 10sec delete rule from flow
		msg.buffer_id= buffer_id			# set the buffer id field
		
		msg.actions.append(of.ofp_action_dl_addr.set_src(self.lb_mac)) 					#from which mac the msg will be send (fake mac)
		msg.actions.append(of.ofp_action_dl_addr.set_dst(self.client_table[client_ip].get('client_mac'))) 		#respond to the clients mac address
		
		msg.actions.append(of.ofp_action_nw_addr.set_src(self.lb_real_ip)) 				#respond with the ip of the lb 
		msg.actions.append(of.ofp_action_nw_addr.set_dst(client_ip)) 					# will send he packet to this client ip 		
		
		msg.actions.append(of.ofp_action_output(port=outport))							#the port which the packet will pass 
		
		self.connection.send(msg)
		#log.info("Flow rule from Server: %s -------> Client: %s"%(server_ip,client_ip))


	# Handles packets that are coming in
	def _handle_PacketIn(self, event):
			packet = event.parsed
			connection = event.connection
			inport = event.port					#the port that is coming the packet
			if packet.type == packet.ARP_TYPE:
				response=packet.payload			# dicapsulate the incoming packet
				if response.opcode==response.REPLY:																#take the reply and pass it to the dictionary
					if response.protosrc not in self.macToPort.keys(): 											# check if the arps reply ips is in the dictionary and if not insert it
						self.macToPort[IPAddr(response.protosrc)]={'server_mac':EthAddr(response.hwsrc),'port':inport}					
			
				elif response.opcode==response.REQUEST: 														#if we have an arp req the LB should know what to do 				
					
					if response.protosrc not in self.macToPort.keys()and response.protosrc not in self.client_table.keys():
						self.client_table[response.protosrc]={'client_mac':EthAddr(packet.payload.hwsrc),'port':inport}		#insert client's ip  mac and port to a forwarding table
										
					if (response.protosrc in self.client_table.keys()and response.protodst == self.lb_real_ip): 			#if request source is client and not server and dest is LB 
						#log.info("Client %s send ARP req to switch %s"%(response.protosrc,response.protodst))
						self.send_proxied_arp_reply(packet,connection,inport,self.lb_mac)						#send the arp rely to the ip we want
					
					elif response.protosrc in self.macToPort.keys() and response.protodst in self.client_table.keys(): # Server send ARP reqs to clients to learn their MAC
						#log.info("Server %s  send ARP req to client"%response.protosrc)
						self.send_proxied_arp_reply(packet,connection,inport,self.lb_mac)
					else:
						log.info("Invalid ARP req")
			elif packet.type == packet.IP_TYPE:
				#Set up route client to server
				if (packet.next.dstip== self.lb_real_ip) and (packet.next.srcip not in self.macToPort.keys()) :		#check if the dest is the switch ip  and source not a server 
					msg=of.ofp_packet_out()
					msg.buffer_id = event.ofp.buffer_id
					if self.flag!=0:
						self.update_lb_mapping(packet.next.srcip)														# take source ip of the packet (the host) and update mapping
					else:
						self.update_lb_mapping_random(packet.next.srcip)
					client_ip=packet.payload.srcip
					server_ip=self.lb_map.get(packet.next.srcip)
					outport=int(self.macToPort[server_ip].get('port'))
					self.install_flow_rule_client_to_server(event,connection, outport, client_ip,server_ip)
					e = ethernet(type=ethernet.IP_TYPE, src=self.lb_mac, dst=self.macToPort[server_ip].get('server_mac'))
					e.set_payload(packet.next)
					msg.data=e.pack()
					msg.in_port=inport
					msg.actions.append(of.ofp_action_dl_addr.set_src(self.lb_mac)) 		#from which mac the msg will be send (fake mac)
					msg.actions.append(of.ofp_action_dl_addr.set_dst(self.macToPort[server_ip].get('server_mac'))) #the servers eth address
			
					msg.actions.append(of.ofp_action_nw_addr.set_src(client_ip))		#which client will send the packet 
					msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip)) 		# will send he packet to this server ip 		
					msg.actions.append(of.ofp_action_output(port=outport))	
					connection.send(msg)
					
				#Set up reverse
				elif packet.next.dstip in self.client_table.keys() : #server to client
					if packet.next.srcip in self.macToPort.keys(): 
						server_ip=packet.next.srcip #take the source packe from the message
						client_ip=self.lb_map.keys()[list(self.lb_map.values()).index(packet.next.srcip)]
						outport=int(self.client_table[client_ip].get('port'))
						self.install_flow_rule_server_to_client(connection, outport, server_ip,client_ip)
						
						# packet out cause otherwise i will loose one packet the other way is to use buffer id 
						e = ethernet(type=ethernet.IP_TYPE, src=self.lb_mac, dst=self.macToPort[server_ip].get('server_mac'))
						e.set_payload(packet.next)
						
						msg=of.ofp_packet_out()
						msg.buffer_id = event.ofp.buffer_id
						msg.data=e.pack()
						msg.in_port=inport
						
						msg.actions.append(of.ofp_action_dl_addr.set_src(self.lb_mac)) 					#from which mac the msg will be send (fake mac)
						msg.actions.append(of.ofp_action_dl_addr.set_dst(self.client_table[client_ip].get('client_mac'))) 		#respond to the clients mac address
			
						msg.actions.append(of.ofp_action_nw_addr.set_src(self.lb_real_ip)) 				#respond with the ip of the lb 
						msg.actions.append(of.ofp_action_nw_addr.set_dst(client_ip)) 					# will send he packet to this client ip 		
			
						msg.actions.append(of.ofp_action_output(port=outport))							#the port which the packet will pass 
			
						self.connection.send(msg)
			else:
				#log.info("Unknown Packet type: %s" % packet.type)
				return
			return


#launch application with following arguments:	
#ip: public service ip, servers: ip addresses of servers (in string format)
def launch(ip, servers,weights="",mode=""): 
	log.info("Loading Simple Load Balancer module")
	server_ips = servers.replace(","," ").split()
	flag=0
	weights = weights.replace(","," ").split()
	weights = [int(x) for x in weights]
	if(mode!="random"):
		flag=1
		
		if(len(server_ips)!=len(weights)):
			print("Please provide corresponding weights too")
			return
		#print(weights)
		wt = [(server_ips[i],weights[i]) for i in range(len(server_ips))]
		wt.sort()
		for i in range(len(wt)):
			server_ips[i],weights[i]=wt[i]
	
	for i in server_ips:
		dictReq[i]=0
	
	server_ips = [IPAddr(x) for x in server_ips]
	service_ip = IPAddr(ip)
	core.registerNew(LoadBalancer, service_ip, server_ips,weights,flag)