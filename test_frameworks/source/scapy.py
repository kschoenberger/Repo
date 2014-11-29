#! /usr/bin/env python
from time import *
from scapy.all import *
from collections import defaultdict

fileToAnalyze = "traffic2"

# Open log-File
file=open('/home/user/Desktop/ANTA/%s_analyse.log' % fileToAnalyze, 'w+')

# Print Header
lt = localtime()
year, month, day = lt[0:3]
hour, min = lt[3:5]
print >> file, 'Analyzed file: %s.pcap' % fileToAnalyze
print >> file, 'Date: %02i.%02i.%04i' % (day, month, year)
print >> file, 'Time: %02i:%02i\n\n\n' % (hour, min)

# Start Timer
begin = time.time()
loadTime = 0

# Loading Dump
dump = rdpcap('/home/user/Desktop/ANTA/%s.pcap' % fileToAnalyze) 
n = len(dump)
loadTime = time.time() - begin

# Set Counters
tcpP = 0
udpP = 0
httpP = 0
dnsqP = 0
dnsrP = 0
notIP = 0

# Define 2-dim list for Connection Summary ( conn[ConnectionID][quellIP, destIP, quellPort, destPort, #totalPackets, #HTTP, #DNS] )
conn = []

# Run packets

for i in range (0,n):

	# Test if Packet has IP layer

	if (not (dump[i].haslayer('IP'))):
		notIP = notIP + 1
		continue

	# Get Data for Connection Summary

	m = len(conn)
	found = 0

	for j in range(0,m):
		if dump[i][IP].src == conn[j][0] and dump[i][IP].dst == conn[j][1] and dump[i].sport == conn[j][2] and dump[i].dport == conn[j][3]:
			conn[j][4] = conn[j][4] + 1
			found = 1
			if dump[i].haslayer('HTTP'):
				conn[j][5] = conn[j][5] + 1
			elif dump[i].haslayer('DNS'):
				conn[j][6] = conn[j][6] + 1

	if found == 0:	
		if dump[i].haslayer('HTTP'):
			conn.append([dump[i][IP].src, dump[i][IP].dst, dump[i].sport, dump[i].dport, 1, 1, 0])
		elif dump[i].haslayer('DNS'):
			conn.append([dump[i][IP].src, dump[i][IP].dst, dump[i].sport, dump[i].dport, 1, 0, 1])
		else:
			conn.append([dump[i][IP].src, dump[i][IP].dst, dump[i].sport, dump[i].dport, 1, 0, 0])


	# Get HTTP Records

	if dump[i].proto == 6:
		tcpP = tcpP + 1
	elif dump[i].proto == 17:
		udpP = udpP + 1

	if dump[i].dport == 80 and dump[i][TCP].options == []: 
		
		httpP = httpP + 1

		#opt = (dump[i][Raw].load).split('\n')
		#for i in range(0,4):
		#	del opt[2]
		#del opt[len(opt) - 1]
		#print >> file, '\n'.join(opt)
		print >> file, dump[i][Raw].load

	# Get DNS Queries

	if dump[i].dport == 53 or dump[i].sport == 53:
		
		if dump[i][DNS].ancount == 0:

			dnsqP = dnsqP + 1

			print >> file, 'DNS-Query: ', dump[i]['DNS Question Record'].qname

		else:

			dnsrP = dnsrP + 1

			print >> file, 'DNS-Response:'			

			for j in range(0, dump[i][DNS].ancount):
					
				type = 'error'
				rclass = 'error'

				if dump[i]['DNS Resource Record'][j].type == 1:
					type = 'IN'
				if dump[i]['DNS Resource Record'][j].rclass == 1:
					rclass = 'A'
				print >> file, dump[i]['DNS Resource Record'][j].rrname, type, rclass, dump[i]['DNS Resource Record'][j].rdata

			print >> file, '\n'

# print Connection Summary

print >> file, 'Connection Summary:\n'

n = len(conn)
for i in range(0,n):
	print >> file, 'Connection %i:\n' % (i+1), conn[i][0], ':', conn[i][2], '  -->  ', conn[i][1], ':', conn[i][3], '\nTotal Packets: %i\nHTTP-Packets: %i\nDNS-Packets: %i\n' % (conn[i][4], conn[i][5], conn[i][6])

# print Summary

print >> file, '\n\nTime used to load dump:', loadTime, '\nTotal Time used:', (time.time() - begin), 'sec\nTotal TCP-Packets:', tcpP, '\nTotal UDP-Packets:', udpP, '\nTotal Packets without IP-Layer:', notIP, '\nHTTP Requests:', httpP, '\nDNS Queries:', dnsqP, '\nDNS Responses:', dnsrP
