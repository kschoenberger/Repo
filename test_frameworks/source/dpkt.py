#! /usr/bin/env python
############
## Project: ANTA - ANANAS Network Traffic Analysis
##          Testing dpkt for its suitability
##
## This is a simply a test program to check whether dpkt could potentially be used in ANANAS.
## It also serves as a playground for the author to acquire some knowledge on Python.
## It's an atrocity (the code, not Python).
## Author: Johann Stockinger
############
############
## Issues:
##      Overflow/IndexError:    When parsing large files these two errors occur on some packets. It is currently
##                              unknown why this happens. These packets are simply ignored for now.
##
##      TCP stream reassembly:  For now, there is no reassembly on TCP packets. This may lead to errors when
##                              parsing HTTP responses. Perhaps an external library has to be used?
##
##      TCP SYN/FIN:            TCP connection states are currently not really looked at (e.g: if handshakes actually
##                              occur and whether they succeed).
##
##      Output:                 Currently the only output is simply written to a log file. The goal is to make
##                              the output as generic as possible, something along the lines of: put an empty XML
##                              document in - get a filled XML document out.
##                              Note: ALL prints/output functions are to test this program! They will not be
##                              implemented in the final version!
##
##      IPv6:                   Due to the fact that this was primarily developed and tested on a Windows system
##                              on which inet_pton isn't supported, IPv6 was only partially tested. On Unix systems
##                              there were some issues with null bytes when passing the IPv6 address to inet_pton, it
##                              needs more testing on Unix/IPv6 though.
##
##		Map IP-addresses:	    Mapping of IP-addresses to countries is not yet implemented.
############

import dpkt
import socket
import time
from urllib import unquote
from collections import defaultdict
import platform


def parse_file(pcap):
    """
    Parses the entire file, packet by packet
    """
    time_start = time.clock()   # Start of analysis as time.clock

    counter = 0                 # Total number of packets
    counter_arp = 0             # Total number of ARP packets
    counter_ip = 0              # Total number of IP packets
    counter_tcp = 0             # Total number of TCP packets
    counter_udp = 0             # Total number of UDP packets
    counter_conn_est = 0        # Total number of established TCP connections
    counter_conn_fin = 0        # Total number of finished TCP connections
    counter_dns = 0             # Total number of DNS packets
    counter_http = 0            # Total number of HTTP packets
    counter_icmp = 0            # Total number of ICMP packets

    conns = defaultdict(int)            # Dictionary of established connections
    dns_queries = defaultdict(int)      # Dictionary of DNS queries
    dns_responses = defaultdict(int)    # Dictionary of DNS responses

    try:
        for ts, buf in pcap:

            ###### LAYER 2 (ETHERNET) STARTS HERE

            eth = dpkt.ethernet.Ethernet(buf)   # Get the packets Ethernet data

            counter += 1                # Increment total packet counter
            date = time.ctime(ts)       # Get time and date of packet
            packet_length = len(buf)    # Get length of packet

            src_mac = format_mac_address(buf[6:12])     # Get and format source MAC address
            dst_mac = format_mac_address(buf[0:6])      # Get and format destination MAC address

            # Check if packet is ARP
            if eth.type == dpkt.ethernet.ETH_TYPE_ARP:
                counter_arp += 1    # Increment ARP counter
                arp_type = parse_arp(eth)      # Parse the packet's ARP portion

                # These prints are for testing purposes only
                print_packet_eth(counter, date, packet_length, src_mac, dst_mac)
                print_packet_arp(arp_type)
                continue

            # Check if packet actually has an IP layer, break current iteration if it does not
            if eth.type != dpkt.ethernet.ETH_TYPE_IP and eth.type != dpkt.ethernet.ETH_TYPE_IP6:
                continue

            ##### LAYER 3 (IP) STARTS HERE

            counter_ip += 1     # Increment IP counter
            ip = eth.data       # Get the packets IP data
            ip6 = False         # Flag is set if IPv6 is used

            src_ip = 0      # Source IP address
            dst_ip = 0      # Destination IP address
            if eth.type == dpkt.ethernet.ETH_TYPE_IP:   # Check if packet is IPv4
                src_ip = socket.inet_ntoa(ip.src)       # Get and convert source IP into a readable string
                dst_ip = socket.inet_ntoa(ip.dst)       # Get and convert destination IP into a readable string
            elif eth.type == dpkt.ethernet.ETH_TYPE_IP6:               # Check if packet is IPv6
                ip6 = True                                             # Set IPv6 flag
                try:                                                       # NOTE: inet_pton has issues on Windows!
                    src_ip = socket.inet_pton(socket.AF_INET6, ip.src)     # Get source IPv6
                    dst_ip = socket.inet_pton(socket.AF_INET6, ip.dst)     # Get destination IPv6
                except TypeError:                                          # If null bytes are present
                    src_ip = "<conversion error>"                          # This needs to be fixed
                    dst_ip = "<conversion error>"
                except AttributeError as e:
                    if platform.platform().startswith('Windows'):   # If platform is Windows, inet_pton is unsupported
                        print "\nError in packet #" + str(counter) + " - IPv6 is unsupported on Windows"
                    else:                                           # This shouldn't happen
                        print "\nUnspecified AttributeError in packet #" + str(counter)
                        print e
                    continue

            #Check if packet is ICMP
            if ip.p == dpkt.ip.IP_PROTO_ICMP or ip.p == dpkt.ip.IP_PROTO_ICMP6:
                counter_icmp += 1                              # Increment ICMP counter
                icmp_type, icmp_code = parse_icmp(ip.data)     # Get ICMP type and code

                # These prints are for testing purposes only
                print_packet_eth(counter, date, packet_length, src_mac, dst_mac)
                print_packet_ip(src_ip, dst_ip)
                print_packet_icmp(icmp_type, icmp_code)
                continue

            ## MAP IP TO COUNTRY:
            # www.hostip.info
            # http://www.hostip.info/dl/index.html
            #####

            # Check if packet actually has a transport layer, break current iteration if it does not
            if ip.p != dpkt.ip.IP_PROTO_UDP and ip.p != dpkt.ip.IP_PROTO_TCP:
                continue

            # Check if packet is UDP
            if ip.p == dpkt.ip.IP_PROTO_UDP:

                ##### LAYER 4 (UDP) STARTS HERE

                counter_udp += 1        # Increment UDP counter
                udp = ip.data           # Get the packets UDP data

                # Create a tuple to use in the conns dict
                address_tuple = "Source: " + str(src_ip) + ":" + str(udp.sport) + \
                                " Destination: " + str(dst_ip) + ":" + str(udp.dport) + \
                                " Type: " + "UDP"
                # Sets an entry in the conns dict if it is a new connection, increments the counter otherwise
                if address_tuple not in conns:
                    conns[address_tuple] = 1
                else:
                    conns[address_tuple] += 1

                ##### LAYER 7 (DNS) ANALYSIS
                # Check if packet is DNS
                if (udp.dport == 53 or udp.sport == 53) and len(udp.data) > 0:

                    # These prints are for testing purposes only
                    print_packet_eth(counter, date, packet_length, src_mac, dst_mac)
                    print_packet_ip(src_ip, dst_ip)
                    print_packet_udp(udp.sport, udp.dport)

                    counter_dns += 1        # Increment DNS counter
                    parse_dns(udp.data, counter, dns_queries, dns_responses, ip6)

            # Check if packet is TCP
            elif ip.p == dpkt.ip.IP_PROTO_TCP:

                ##### LAYER 4 (TCP) STARTS HERE

                # Todo: implement some sort of connection number (assign packets to a connection)
                counter_tcp += 1        # Increment TCP counter
                tcp = ip.data           # Get the TCP data

                if isinstance(tcp, basestring):      # I have no idea why this happens, needs further investigation...
                    continue

                tcp_flags = parse_tcp_flags(tcp)     # Parse TCP flags

                # Todo: implement proper connection counter (handshakes)
                # Check for SYN/FIN flags in the same connection once properly implemented
                if tcp.flags & dpkt.tcp.TH_SYN:
                    counter_conn_est += 1
                elif tcp.flags & dpkt.tcp.TH_FIN:
                    counter_conn_fin += 1

                # Create a tuple to use in the conns dict
                address_tuple = "Source: " + str(src_ip) + ":" + str(tcp.sport) + \
                                " Destination: " + str(dst_ip) + ":" + str(tcp.dport) + \
                                " Type: " + "TCP"
                # Sets an entry in the conns dict if it is a new connection, increments otherwise
                if address_tuple not in conns:
                    conns[address_tuple] = 1
                else:
                    conns[address_tuple] += 1

                ##### LAYER 7 (DNS) ANALYSIS
                # Check if packet is DNS
                # Does TCP DNS really have to be implemented?
                if (tcp.dport == 53 or tcp.sport == 53) and len(tcp.data) > 0:

                    # These prints are for testing purposes only
                    print_packet_eth(counter, date, packet_length, src_mac, dst_mac)
                    print_packet_ip(src_ip, dst_ip)
                    print_packet_tcp(tcp.sport, tcp.dport, tcp_flags, tcp.seq, tcp.win)

                    counter_dns += 1                 # Increment DNS counter
                    parse_dns(tcp.data, counter, dns_queries, dns_responses, ip6)

                ##### LAYER 7 (HTTP) ANALYSIS
                # Check if packet is HTTP
                # Todo: problems with responses and TCP stream reassembly
                if (tcp.dport == 80 or tcp.sport == 80) and len(tcp.data) > 0:
                    try:
                        if tcp.dport == 80:
                            http = dpkt.http.Request(tcp.data)      # Get the packets HTTP data if it is a request

                            # These prints are for testing purposes only
                            print_packet_eth(counter, date, packet_length, src_mac, dst_mac)
                            print_packet_ip(src_ip, dst_ip)
                            print_packet_tcp(tcp.sport, tcp.dport, tcp_flags, tcp.seq, tcp.win)

                            parse_http_request(http)
                        elif tcp.sport == 80:
                            http = dpkt.http.Response(tcp.data)     # Get the packets HTTP data if it is a response

                            # These prints are for testing purposes only
                            print_packet_eth(counter, date, packet_length, src_mac, dst_mac)
                            print_packet_ip(src_ip, dst_ip)
                            print_packet_tcp(tcp.sport, tcp.dport, tcp_flags, tcp.seq, tcp.win)

                            parse_http_response(http)
                    except dpkt.UnpackError:        # Filter non-HTTP packets (see Todo)
                        continue
                    except OverflowError as e:      # This sometimes happens when larger files are used
                        counter_http += 1           # The cause is still unclear, needs further investigation
                        print "\nError in packet #" + str(counter)      # Simply increment and continue for now
                        print e
                        continue
                    counter_http += 1               # Increment HTTP counter

            else:           # If the packet is something else (does this ever happen?)
                continue    # Just continue

    except dpkt.Error as e:
        print "\nError in packet #" + str(counter)
        print e

    # This print is for testing purposes only
    print_sum(counter, counter_arp, counter_ip, counter_icmp, counter_udp, counter_tcp, counter_conn_est,
              counter_conn_fin, counter_dns, counter_http, conns, dns_queries, dns_responses, time_start)


#def parse_udp():
    """
    Parses the UDP portion of a packet
    """


#def parse_tcp():
    """
    Parses the TCP portion of a packet
    """


def parse_tcp_flags(data):
    """
    Parses the TCP portion of a packet for TCP flags
    """
    r = ""                               # Stores the TCP flags
    if data.flags & dpkt.tcp.TH_FIN:     # Check for FIN
        r += "FIN "
    if data.flags & dpkt.tcp.TH_SYN:     # Check for SYN
        r += "SYN "
    if data.flags & dpkt.tcp.TH_RST:     # Check for RST
        r += "RST "
    if data.flags & dpkt.tcp.TH_PUSH:    # Check for PSH
        r += "PSH "
    if data.flags & dpkt.tcp.TH_ACK:     # Check for ACK
        r += "ACK "
    if data.flags & dpkt.tcp.TH_URG:     # Check for URG
        r += "URG "
    if data.flags & dpkt.tcp.TH_ECE:     # Check for ECE
        r += "ECE "
    if data.flags & dpkt.tcp.TH_CWR:     # Check for CWR
        r += "CWR "
    return r


def format_mac_address(mac):
    """
    Formats 6 bytes of an ethernet packet into a readable MAC address
    """
    r = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(mac[0]), ord(mac[1]), ord(mac[2]), ord(mac[3]), ord(mac[4]), ord(mac[5]))
    return r


def parse_dns(data, counter, queries, responses, ip6):
    """
    Parses for DNS query or response, handles exceptions
    """
    try:
        dns = dpkt.dns.DNS(data)                    # Get the packets DNS data
    except IndexError as e:                         # This sometimes happens when very larger files are used
        print "Error in packet #" + str(counter)    # The cause is still unclear, needs further investigation
        print e                                     # See OverflowError from HTTP analysis
        return                                      # Simply returns for now

    if dns.qr == dpkt.dns.DNS_Q:    # Checks whether it is a query
        parse_dns_query(dns, queries)
    elif dns.qr == dpkt.dns.DNS_R:  # Checks whether it is a response
        parse_dns_response(dns, responses, ip6)


def parse_dns_query(data, queries):
    """
    Parses the DNS query portion of a packet
    """
    query_type = None       # The query type (e.g: A, AAAA, CNAME, ....)
    query_data = None       # The query data

    if data.qd[0].type == dpkt.dns.DNS_A:       # Check for type
        query_type = "A"                        # Set type
        query_data = data.qd[0].name            # Set data
    if data.qd[0].type == dpkt.dns.DNS_AAAA:
        query_type = "AAAA"
        query_data = data.qd[0].name
    elif data.qd[0].type == dpkt.dns.DNS_CNAME:
        query_type = "CNAME"
        query_data = data.qd[0].name
    elif data.qd[0].type == dpkt.dns.DNS_MX:
        query_type = "MX"
        query_data = data.qd[0].name
    elif data.qd[0].type == dpkt.dns.DNS_PTR:
        query_type = "PTR"
        query_data = data.qd[0].name
    elif data.qd[0].type == dpkt.dns.DNS_NS:
        query_type = "NS"
        query_data = data.qd[0].name
    elif data.qd[0].type == dpkt.dns.DNS_SOA:
        query_type = "SOA"
        query_data = data.qd[0].name
    elif data.qd[0].type == dpkt.dns.DNS_HINFO:
        query_type = "HINFO"
        query_data = data.qd[0].name
    elif data.qd[0].type == dpkt.dns.DNS_TXT:
        query_type = "TXT"
        query_data = data.qd[0].name
    elif data.qd[0].type == dpkt.dns.DNS_SRV:
        query_type = "SRV"
        query_data = data.qd[0].name

    transaction_id = data.id    # Get the packets transaction ID

    # Create a tuple to use in the queries dict
    dns_tuple = "Transaction ID: \"" + str(transaction_id) + "\" Type: \"" + str(query_type) + "\" Data: \"" +\
                str(query_data) + "\""
    # Sets an entry in the queries dict if it is a new query, increments otherwise
    if dns_tuple not in queries:
        queries[dns_tuple] = 1
    else:
        queries[dns_tuple] += 1

    # This print is for testing purposes only
    print_packet_dns_query(transaction_id, query_type, query_data)


def parse_dns_response(data, responses, ip6):
    """
    Parses the DNS response portion of a packet
    """
    response = dict()       # Dict containing all DNS responses (for multiple records)
    dns_tuple = None        # A tuple to use in the responses dict

    # Iterate through all answers
    for answer in data.an:
        if answer.type == dpkt.dns.DNS_A:   # If it is an A record
            # Add if such an entry already exists, append otherwise
            if "A" not in response:
                response["A"] = str(socket.inet_ntoa(answer.rdata))
            else:
                response["A"] += " " + str(socket.inet_ntoa(answer.rdata))
            # Set tuple
            dns_tuple = "Transaction ID: \"" + str(data.id) + "\" Type: \"A\" Data: \"" +\
                        str(response["A"]) + "\""
        elif answer.type == dpkt.dns.DNS_AAAA:  # If it is an AAAA record
            if not ip6:     # If packet is IPv4
                # Add if such an entry already exists, append otherwise
                if "AAAA" not in response:
                    response["AAAA"] = str(socket.inet_ntoa(answer.rdata))
                else:
                    response["AAAA"] += str(socket.inet_ntoa(answer.rdata))
            else:           # If packet is IPv6
                try:        # See comments on IPv6 above
                    # Add if such an entry already exists, append otherwise
                    if "AAAA" not in response:
                        response["AAAA"] = str(socket.inet_pton(answer.rdata))
                    else:
                        response["AAAA"] += str(socket.inet_pton(answer.rdata))
                except TypeError:               # If null bytes are present
                    response["AAAA"] = None     # This needs to be fixed
                except AttributeError as e:
                    if platform.platform().startswith('Windows'):   # If platform is Windows, inet_pton is unsupported
                        print "\nError - IPv6 is unsupported on Windows"
                    else:                                           # This shouldn't happen
                        print "\nUnspecified AttributeError while parsing the DNS response"
                        print e
                    response["AAAA"] = None
            # Set tuple
            dns_tuple = "Transaction ID: \"" + str(data.id) + "\" Type: \"AAAA\" Data: \"" +\
                        str(response["AAAA"]) + "\""
        elif answer.type == dpkt.dns.DNS_CNAME:     # If it is a CNAME record
            # Add if such an entry already exists, append otherwise
            if "CNAME" not in response:
                response["CNAME"] = answer.cname
            else:
                response["CNAME"] += answer.cname
            # Set tuple
            dns_tuple = "Transaction ID: \"" + str(data.id) + "\" Type: \"CNAME\" Data: \"" +\
                        str(response["CNAME"]) + "\""
        elif answer.type == dpkt.dns.DNS_MX:        # If it is a MX record
            # Add if such an entry already exists, append otherwise
            if "MX" not in response:
                response["MX"] = answer.mxname
            else:
                response["MX"] += answer.mxname
            # Set tuple
            dns_tuple = "Transaction ID: \"" + str(data.id) + "\" Type: \"MX\" Data: \"" +\
                        str(response["MX"]) + "\""
        elif answer.type == dpkt.dns.DNS_PTR:       # If it is a PTR record
            # Add if such an entry already exists, append otherwise
            if "PTR" not in response:
                response["PTR"] = answer.ptrname
            else:
                response["PTR"] += answer.ptrname
            # Set tuple
            dns_tuple = "Transaction ID: \"" + str(data.id) + "\" Type: \"PTR\" Data: \"" +\
                        str(response["PTR"]) + "\""
        elif answer.type == dpkt.dns.DNS_NS:        # If it is a NS record
            # Add if such an entry already exists, append otherwise
            if "NS" not in response:
                response["NS"] = answer.ptrname
            else:
                response["NS"] += answer.nsname
            # Set tuple
            dns_tuple = "Transaction ID: \"" + str(data.id) + "\" Type: \"NS\" Data: \"" +\
                        str(response["NS"]) + "\""
        elif answer.type == dpkt.dns.DNS_SOA:       # If it is a SOA record
            # Add if such an entry already exists, append otherwise
            if "SOA" not in response:
                response["SOA"] = ",".join([answer.mname, answer.rname, str(answer.serial),
                                            str(answer.refresh), str(answer.retry), str(answer.expire),
                                            str(answer.minimum)])
            else:
                response["SOA"] += ",".join([answer.mname, answer.rname, str(answer.serial),
                                            str(answer.refresh), str(answer.retry), str(answer.expire),
                                            str(answer.minimum)])
            # Set tuple
            dns_tuple = "Transaction ID: \"" + str(data.id) + "\" Type: \"SOA\" Data: \"" +\
                        str(response["SOA"]) + "\""
        elif answer.type == dpkt.dns.DNS_HINFO:     # If it is a HINFO record
            # Add if such an entry already exists, append otherwise
            if "HINFO" not in response:
                response["HINFO"] = " ".join(answer.text)
            else:
                response["HINFO"] += " ".join(answer.text)
            # Set tuple
            dns_tuple = "Transaction ID: \"" + str(data.id) + "\" Type: \"HINFO\" Data: \"" +\
                        str(response["HINFO"]) + "\""
        elif answer.type == dpkt.dns.DNS_TXT:       # If it is a TXT record
            # Add if such an entry already exists, append otherwise
            if "TXT" not in response:
                response["TXT"] = " ".join(answer.text)
            else:
                response["TXT"] += " ".join(answer.text)
            # Set tuple
            dns_tuple = "Transaction ID: \"" + str(data.id) + "\" Type: \"TXT\" Data: \"" +\
                        str(response["TXT"]) + "\""
        elif answer.type == dpkt.dns.DNS_SRV:       # If it is a SRV record
            # BROKEN!
            # Add if such an entry already exists, append otherwise
            if "SRV" not in response:
                response["SRV"] = " ".join(answer.text)
            else:
                response["SRV"] += " ".join(answer.text)
            # Set tuple
            dns_tuple = "Transaction ID: \"" + str(data.id) + "\" Type: \"SRV\" Data: \"" +\
                        str(response["SRV"]) + "\""

    transaction_id = data.id    # Get the packets transaction ID

    # Sets an entry in the responses dict if it is a new response, increments otherwise
    if dns_tuple is not None:               # Check if dns_tuple has been set (it should never be None)
        if dns_tuple not in responses:
            responses[dns_tuple] = 1
        else:
            responses[dns_tuple] += 1

    # This print is for testing purposes only
    print_packet_dns_response(transaction_id, response)


def parse_http_request(data):
    """
    Parses the HTTP request of a packet
    """
    host = ""               # The host entry
    user_agent = ""         # The user-agent entry
    if "host" in data.headers:          # Check for a host entry in the packets headers
        host = data.headers["host"]     # Set host entry
    if "user-agent" in data.headers:                # Check for a user-agent entry in the packets headers
        user_agent = data.headers["user-agent"]     # Set the user-agent entry

    http_version = data.version     # Get the HTTP version used
    http_uri = data.uri             # Get the HTTP uri used
    http_method = data.method       # Get the HTTP method used

    http_body = ""              # The HTTP body
    if http_method == "POST":   # Check if the method is POST
        http_body = data.body   # Get the HTTP body

    # Parse HTTP parameters
    temp = unquote(http_uri).replace("?", "&")      # Temporary list to split uri
    temp = temp.split("&")                          # Split uri
    resource = temp[0]                              # Get resource
    params = []                                     # List for HTTP parameters
    if len(temp) > 0:                               # If the length of temp is 0, there are no parameters to parse
        for s in temp:                              # Check all individual strings
            if "=" in s:                            # Filter resource
                params.append(s)                    # Append to parameters list

    # This print is for testing purposes only
    print_packet_http_request(http_version, host, http_uri, http_method, http_body, user_agent, resource, params)


def parse_http_response(data):
    """
    Parses the HTTP response of a packet
    """
    http_status = data.status   # The HTTP status (e.g: 200, 404, ...)
    http_reason = data.reason     # The HTTP reason (e.g: OK, Not Found, ...)
    http_body = data.body       # The HTTP body

    # This print is for testing purposes only
    print_packet_http_response(http_status, http_reason, http_body)


def parse_arp(data):
    """
    Parses the ARP portion of a packet
    """
    if data.data.op == dpkt.arp.ARP_OP_REQUEST:         # If it is a request
        arp_type = "Request"
    elif data.data.op == dpkt.arp.ARP_OP_REPLY:         # If it is a response
        arp_type = "Response"
    else:                                               # If it is something else (this is currently unsupported
        arp_type = "Unsupported"                        # because it isn't deemed necessary...)
    return arp_type                                     # Return the type of operation used


def parse_icmp(data):
    """
    Parses the ICMP portion of a packet
    """
    #Todo: differentiate between icmp and icmp6, maybe decode icmp types
    icmp_type = data.type           # The ICMP type
    icmp_code = data.code           # The ICMP code
    return icmp_type, icmp_code     # Return ICMP type and code


def print_sum(ctr, ctr_arp, ctr_ip, ctr_icmp, ctr_udp, ctr_tcp, ctr_conn_est, ctr_conn_fin, ctr_dns, ctr_http,
              conns, dns_queries, dns_responses, time_start):
    """
    Prints the summary of all parsed packets
    """
    print "\nSUMMARY\n"
    print "Total time elapsed: " + str(time.clock() - time_start) + " seconds (~" + \
          str(int(ctr/time.clock() - time_start)) + " packets per second)\n"
    print "Total number of packets: " + str(ctr)
    print "Total number of ARP packets: " + str(ctr_arp)
    print "Total number of IP packets: " + str(ctr_ip)
    print "Total number of ICMP packets: " + str(ctr_icmp)
    print "Total number of UDP packets: " + str(ctr_udp)
    print "Total number of TCP packets: " + str(ctr_tcp)
    print "Total number of established TCP connections: " + str(ctr_conn_est)
    print "Total number of finished TCP connections: " + str(ctr_conn_fin)
    print "Total number of DNS packets: " + str(ctr_dns)
    print "Total number of HTTP packets: " + str(ctr_http)
    print "\nConnections: "
    for k, v in conns.iteritems():
        print "%s :: number of packets: %s" % (str(k), str(v))
    print "\nDNS queries:"
    for k, v in dns_queries.iteritems():
        print str(k)                            # "%s :: number of queries: %s" % (str(k), str(v))
    print "\nDNS responses:"
    for k, v in dns_responses.iteritems():
        print str(k)                            # "%s :: number of responses: %s" % (str(k), str(v))


def print_packet_eth(ctr, date, packet_length, src_mac, dst_mac):
    """
    Prints the ethernet portion of a single packet
    """
    print "\nPACKET #" + str(ctr)
    print "Time stamp: " + str(date)
    print "Packet length: " + str(packet_length) + " bytes"
    print "Ethernet analysis:"
    print "MAC - Source: " + str(src_mac)
    print "MAC - Destination: " + str(dst_mac)


def print_packet_arp(type_arp):
    """
    Prints the ARP portion of a single packet
    """
    print "ARP analysis:"
    print "ARP type: " + str(type_arp)


def print_packet_ip(src_ip, dst_ip):
    """
    Prints the IP portion of a single packet
    """
    print "IP analysis:"
    print "IP - Source: " + str(src_ip)
    print "IP - Destination: " + str(dst_ip)


def print_packet_icmp(type_icmp, code_icmp):
    """
    Prints the ICMP portion of a single packet
    """
    print "ICMP analysis:"
    print "ICMP - Type: " + str(type_icmp)
    print "ICMP - Code: " + str(code_icmp)


def print_packet_udp(sport, dport):
    """
    Prints the UDP portion of a single packet
    """
    print "UDP analysis:"
    print "UDP - Source port: " + str(sport)
    print "UDP - Destination port: " + str(dport)


def print_packet_tcp(sport, dport, flags, seq, win):
    """
    Prints the TCP portion of a single packet
    """
    print "TCP analysis:"
    print "TCP - Source port: " + str(sport)
    print "TCP - Destination port: " + str(dport)
    print "TCP - Flag(s): " + flags
    print "TCP - Sequence number: " + str(seq)
    print "TCP - Sliding window size: " + str(win)


def print_packet_dns_query(transaction_id, query_type, query_data):
    """
    Prints the DNS query portion of a single packet
    """
    print "DNS analysis:"
    print "DNS type (query, response): " + "query"
    print "DNS transaction ID: " + str(transaction_id)
    print "DNS query type: " + str(query_type)
    print "DNS query data: " + str(query_data)


def print_packet_dns_response(transaction_id, response):
    """
    Prints the DNS response portion of a single packet
    """
    print "DNS analysis:"
    print "DNS type (query, response): " + "response"
    print "DNS transaction ID: " + str(transaction_id)
    for k, v in response.items():
        print "DNS response type: " + str(k)
        print "DNS response data: " + str(v)


def print_packet_http_request(version, host, uri, method, body, user_agent, resource, params):
    """
    Prints the HTTP request portion of a single packet
    """
    print "HTTP analysis:"
    print "HTTP type: " + "request"
    print "HTTP version: " + str(version)
    if host != "":
        print "HTTP host: " + str(host)
        print "HTTP uri: " + str(uri)
        print "HTTP url: " + "http://" + str(host) + str(uri)
    else:
        print "HTTP host: " + "no host record found"
        print "HTTP uri: " + str(uri)
    print "HTTP method: " + str(method)
    if params:
        print "HTTP resource: " + str(resource)
        print "HTTP parameters:\n---"
        for s in params:
            print s.split("=")
        print "---"
    if method == "POST":
        print "HTTP body: " + str(body)
    if user_agent != "":
        print "HTTP user-agent: " + str(user_agent)


def print_packet_http_response(status, reason, body):
    """
    Prints the HTTP response portion of a single packet
    """
    print "HTTP analysis:"
    print "HTTP type: " + "response"
    print "HTTP status: " + str(status) + " " + str(reason)
    print "HTTP body: " + str(body)


class NetworkStatistics:
    """
    This will be properly filled once the actual implementation starts
    """
    import sys
    log_file = open('test.log', 'w')
    sys.stdout = log_file

    f = open('traffic.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    parse_file(pcap)

    log_file.close()