import struct
import socket
import sys
import os
import operator
import binascii
import time

class iphdr(object):
    def __init__(self, id=os.getpid(), ttl = 64, proto=socket.IPPROTO_ICMP, src=socket.gethostbyname(socket.gethostname()), dst=None):
        self.version = 4
        self.hlen = 5
        self.tos = 0
        self.length = 20
        self.id = id
        self.frag = 0
        self.ttl = ttl
        self.proto = proto
        self.cksum = 0
        self.src = src
        self.saddr = socket.inet_aton(src)
        self.dst = dst or "0.0.0.0"
        self.daddr = socket.inet_aton(self.dst)
        self.data = ""

    def assemble(self):
		header_part1 = struct.pack('!BBHHHBB',
                             (self.version & 0x0f) << 4 | (self.hlen & 0x0f),
                             self.tos, self.length + len(self.data),
                             socket.htons(self.id), self.frag,
                             self.ttl, self.proto)
		#print binascii.hexlify(header_part1)
		header_part2 = struct.pack('!4s4s', self.saddr, self.daddr)
		cksum = self.checksum(header_part1 + "\x00\x00" + header_part2)
		cksum = struct.pack('H', cksum)
		#print binascii.hexlify(cksum)
		#print binascii.hexlify(self.saddr)
		self._raw = header_part1 + cksum + header_part2 + self.data
		
		#print binascii.hexlify(self._raw)
		return self._raw

    @classmethod
    def disassemble(self, data):
        self._raw = data
        ip = iphdr()
        pkt = struct.unpack('!BBHHHBBH', data[:12])
        ip.version = (pkt[0] >> 4 & 0x0f)
        ip.hlen = (pkt[0] & 0x0f)
        ip.tos, ip.length, ip.id, ip.frag, ip.ttl, ip.proto, ip.cksum = pkt[1:]
        ip.saddr = data[12:16]
        ip.daddr = data[16:20]
        ip.src = socket.inet_ntoa(ip.saddr)
        ip.dst = socket.inet_ntoa(ip.daddr)
        return ip
	
    @classmethod
    def checksum(self, data):
        cksum = reduce(operator.add,
                    struct.unpack('!%dH' % (len(data) >> 1), data))
        cksum = (cksum >> 16) + (cksum & 0xffff)
        cksum += (cksum >> 16)
        cksum = (cksum & 0xffff) ^ 0xffff
        #print cksum
        return cksum
	
    def __repr__(self):
        return "IP (tos %s, ttl %s, id %s, frag %s, proto %s, length %s) " \
               "%s -> %s" % \
               (self.tos, self.ttl, self.id, self.frag, self.proto,
                self.length, self.src, self.dst)

class icmphdr(object):
    def __init__(self, id=os.getpid(), data=""):
        self.type = 8
        self.code = 0
        self.cksum = 0
        self.id = id
        self.sequence = 0
        self.data = data

    def assemble(self):
        part1 = struct.pack("BB", self.type, self.code)
        part2 = struct.pack("!HH", self.id, self.sequence)
        cksum = self.checksum(part1 + "\x00\x00" + part2 + self.data)
        cksum = struct.pack("!H", cksum)
        self._raw = part1 + cksum + part2 + self.data
        return self._raw

    @classmethod
    def checksum(self, data):
        if len(data) & 1:
            data += "\x00"
        cksum = reduce(operator.add,
                       struct.unpack('!%dH' % (len(data) >> 1), data))
        cksum = (cksum >> 16) + (cksum & 0xffff)
        cksum += (cksum >> 16)
        cksum = (cksum & 0xffff) ^ 0xffff
        return cksum

    @classmethod
    def disassemble(self, data):
        self._raw = data
        icmp = icmphdr()
        pkt = struct.unpack("!BBHHH", data)
        icmp.type, icmp.code, icmp.cksum, icmp.id, icmp.seq = pkt
        return icmp

    def __repr__(self):
        return "ICMP (type %s, code %s, id %s, sequence %s)" % \
               (self.type, self.code, self.id, self.sequence)

def main(*sysdata):
	dst_name = sysdata[1]
	if len(sysdata) > 2:
		hop = int(sysdata[2])
	else:
		hop = 30
	print "Max %d hop..." % hop 
	dst_addr = socket.gethostbyname(dst_name)
	print "Traceroute to %s(%s)" % (dst_name, dst_addr)

	
	print "TTL\tRoute Addr"
	mylist = []
	
	for i in range (1, hop):
		send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
		send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)	#very important! tell kernel not to put in headers
		send_socket.settimeout(10)
		raw_ip = iphdr(ttl=i, dst=dst_addr)
		msg = 'Hello'
		icmp_id = os.getpid()+i
		raw_icmp = icmphdr(id=icmp_id, data=msg)	#incremental id
		packet = raw_ip.assemble() + raw_icmp.assemble()
		
		send_time = time.time() 
		
		length = send_socket.sendto(packet, (dst_addr, 0))
		
		while True:
			try:
				res_data, res_addr = send_socket.recvfrom(512)
			except socket.timeout:
				print '%d\t*' % i
				break
				
			if res_addr[0] in mylist:
				continue
			#recv_time = time.time()
			#print binascii.hexlify(res_data)
			res_data = res_data.rstrip(msg)	#strip message
			res_data = res_data[20:28]		#strip ip header
	
			icmp = raw_icmp.disassemble(res_data)
		
			#I find this process very time-comsuming, for efficiency reason I ignored it 
			try:
				res_name = socket.gethostbyaddr(res_addr[0])[0]
			except:
				res_name = res_addr[0]
			
			if (icmp.type == 11):
				mylist.append(res_addr[0])	#to eliminate numberous redundant packet, the reason of redundant packet is unknown
				print "%d\t%s(%s)" % (i, res_addr[0], res_name)
				break
			elif (icmp.type == 0):
				print "%d\t%s(%s)" % (i, res_addr[0], res_name)
				print "Traceroute complete."
				break
			else:
				print "Unknown Packet Recived, continue to receive"
				pass
		send_socket.close()
		if (icmp.type == 0):
			break
	else:
		print "Destination is unreachable within %d hops!" % hop
			#print icmp.type, icmp.code, icmp.cksum
			#print binascii.hexlify(res_data)

if __name__ == "__main__":
	#print "Traceroute to " , sys.argv[1]
	#print sys.argv
	main(*sys.argv)