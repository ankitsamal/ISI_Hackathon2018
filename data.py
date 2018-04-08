'''
Date
Time
Source MAC
Source IP
Source Port
Dest MAC
Dest IP
Dest Port
Protocol
Good packet = 1, Bad packet = 0
Allowed = 1, Blocked = 0
'''
from dateutil import parser
import numpy as np
import pandas as pd
import json
from IPy import IP
import requests
import re
import urllib.parse as urlparse

class MacParser:
	def __init__(self, filename):
		train_set = pd.read_csv(filename, sep=",", dtype="str")
		self.d = {}
		for line in train_set.values:
			self.d[line[1]] = line[2]
	def parse(self, mac):
		mac = "".join(mac.split(":")[0:3])
		return self.d.get(mac, "")

class RuleList:
	ports = []
	protocols = [] 
	def __init__(self):
		self.white_list = [] #[(ip, port, protocol), ...]
		self.black_list = []
	def getSingleScore(self, list_ip, list_port, list_protocol, ip, port, protocol):
		score = 0
		if list_ip != None and list_ip != ip:
			return 0
		if list_port != None and list_port != port and port not in RuleList.ports:
			return 0
		if list_protocol != None and list_protocol != protocol and protocol not in RuleList.protocols:
			return 0
		return int(list_ip == ip) + int(list_port == port) + int(list_protocol == protocol) + 1
	def getScore(self, l, ip, port, protocol):
		score = 0
		for rule in l:
			cur = self.getSingleScore(rule[0], rule[1], rule[2], ip, port, protocol)
			if cur > score:
				score = cur
		return score
	def query(self, ip, port, protocol):
		white_score = self.getScore(self.white_list, ip, port, protocol)
		black_score = self.getScore(self.black_list, ip, port, protocol)
		if white_score <= black_score:
			return 0
		else:
			return 1
	def isEmpty(self):
		return len(self.white_list) == 0 and len(self.black_list) == 0

class PacketData:
	macParser = MacParser("oui.csv")
	def __init__(self, date, time, source_mac, source_ip, source_port, dest_mac, dest_ip, dest_port, protocol, good_packet, allowed, content):	
		self.date = date
		self.time = time
		self.source_mac = source_mac
		self.source_ip = source_ip
		self.source_port = source_port
		self.dest_mac = dest_mac
		self.dest_ip = dest_ip
		self.dest_port = dest_port
		self.protocol = protocol
		self.good_packet = good_packet
		self.allowed = allowed
		self.source_org = PacketData.macParser.parse(self.source_mac)
		self.host = ""
		self.serialNumber = ""
		self.token = ""
		self.model = ""
		if protocol == 'DNS':
			rst = re.match(r'Standard query 0x\d\d\d\d A ([\w.]+)$', content)
			if rst != None:
				self.host = rst.groups()[0]
		elif protocol == 'HTTP':
			rst = re.match(r'^GET ([\w/?=%&]+) HTTP/\d.\d', content)
			if rst != None:
				d = urlparse.parse_qs(urlparse.urlparse(rst.groups()[0]).query)
				self.serialNumber = d.get("serialNumber", ("",))[0]
				self.token = d.get("token", ("",))[0]
				self.model = d.get("model", ("",))[0]


def CSV2ListAndDict(filename):
	'''
	Return things like:
	{'date': datetime.date(2018, 4, 7), 'time': datetime.time(8, 55, 43), 'source_mac': ['AA', 'BB', 'CC', 'DD', 'EE', 'FF'], 'source_ip': ['11', '22', '33', '44'], 'source_port': 1234, 'dest_mac': ['11', '22', '33', '44', '55', '66'], 'dest_ip': ['55', '66', '77', '88'], 'dest_port': 5678, 'protocol': 'HTTP', 'good_packet': 1, 'allowed': 1}
	'''
	train_set = np.loadtxt(filename, skiprows=1, delimiter=",", dtype="str")
	# train_set.reshape((-1, 11))
	datas = []
	for line in train_set:
		packetData = PacketData(parser.parse(line[0]).date(), parser.parse(line[1]).time(), \
			line[2], line[3], int(line[4]) if len(line[4]) != 0 else -1,\
			line[5], line[6], int(line[7]) if len(line[7]) != 0 else -1,\
			line[8], int(line[9]), int(line[10]), line[11]\
			)
		datas.append(packetData)
	d = {}
	for data in datas:
		d[data.source_mac] = d.get(data.source_mac, RuleList())
	return datas, d

def List2CSV(datas, filename):
	f = open(filename, "w")
	for data in datas:
		f.write("%s, %s, %s, %s, %s, %s, %s, %s, %d, %d\n" % (data.date.strftime("%Y/%m/%d"), data.time.strftime("%H:%M:%S"), \
			data.source_mac, data.source_ip, str(data.source_port) if data.source_port >= 0 else "", \
			data.dest_ip, str(data.dest_port) if data.dest_port >= 0 else "", data.protocol, \
			data.good_packet, data.allowed))

def List2JSON(datas):
	groups = {}
	for index in range(0, len(datas)):
		data = datas[index] 
		groups[data.source_mac] = groups.get(data.source_mac, {"org": data.source_org, "host":[], "packets": [], "token": [], "serialNumber": [], "model": []})
		added = False
		for keyword in ["token", "serialNumber", "model", "host"]:
			if len(data.__dict__[keyword]) != 0 and data.__dict__[keyword] not in groups[data.source_mac][keyword]:
				groups[data.source_mac][keyword].append(data.__dict__[keyword])
		for old_packet in groups[data.source_mac]["packets"]:
			if old_packet["source_ip"] == data.source_ip and old_packet["source_port"] == data.source_port and \
					old_packet["dest_mac"] == data.dest_mac and old_packet["dest_ip"] == data.dest_ip and \
					old_packet["dest_port"] == data.dest_port and old_packet["protocol"] == data.protocol:
				old_packet["id"].append(index)
				added = True
				break
		if not added:
			groups[data.source_mac]["packets"].append(\
				{\
					"id": [index], \
					"date": data.date.strftime("%Y/%m/%d"), \
					"time": data.time.strftime("%H:%M:%S"), \
					"source_ip": data.source_ip, \
					"source_port": str(data.source_port) if data.source_port >= 0 else "", \
					"dest_mac": data.dest_mac, \
					"dest_ip": data.dest_ip, \
					"dest_port": str(data.dest_port) if data.dest_port >= 0 else "", \
					"protocol": data.protocol, \
					"good_packet": data.good_packet,\
					"allowed": data.allowed\
				})
	return json.dumps(groups)

def tagList(datas, rules):
	for data in datas:
		if len(data.dest_ip) == 0:
			data.good_packet = 1
			data.allowed = 1
			continue
		if IP(data.dest_ip).iptype() == 'PUBLIC':
			rl = rules[data.source_mac]
			if rl.isEmpty():
				rl.white_list.append((data.dest_ip, None, None))
				data.good_packet = 1
				data.allowed = 1
			else:
				data.good_packet = rl.query(data.dest_ip, data.dest_port, data.protocol)
				data.allowed = data.good_packet
		else:
			data.good_packet = 1
			data.allowed = 1

# datas: [PacketData] rules: {"11:22:33:11:22:33": ruleList}
'''
from data import CSV2ListAndDict

datas, rules = CSV2ListAndDict("train.csv")
for data in datas:
	do something
	rl = ruleList[data.source_mac]
	rl.white_list.append()
	rl.black_list.append()
	rl.query()
'''
'''
http://localhost:8080/api/post
'''