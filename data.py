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
	def __init__(self):
		self.white_list = [] #[(ip, port, protocol), ...]
		self.black_list = []
	def query(self, ip, port, protocol):
		return True

class PacketData:
	macParser = MacParser("oui.csv")
	def __init__(self, date, time, source_mac, source_ip, source_port, dest_mac, dest_ip, dest_port, protocol, good_packet, allowed):	
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

def CSV2List(filename):
	'''
	Return things like:
	{'date': datetime.date(2018, 4, 7), 'time': datetime.time(8, 55, 43), 'source_mac': ['AA', 'BB', 'CC', 'DD', 'EE', 'FF'], 'source_ip': ['11', '22', '33', '44'], 'source_port': 1234, 'dest_mac': ['11', '22', '33', '44', '55', '66'], 'dest_ip': ['55', '66', '77', '88'], 'dest_port': 5678, 'protocol': 'HTTP', 'good_packet': 1, 'allowed': 1}
	'''
	train_set = np.loadtxt(filename, skiprows=1, delimiter=",", dtype="str")
	train_set.reshape((-1, 11))
	data = []
	for line in train_set:
		packetData = PacketData(parser.parse(line[0]).date(), parser.parse(line[1]).time(), \
			line[2], line[3], int(line[4]),\
			line[5], line[6], int(line[7]),\
			line[8], int(line[9]), int(line[10])\
			)
		data.append(packetData)
	return data

def List2JSON(datas):
	groups = {}
	for index in range(0, len(datas)):
		data = datas[index] 
		groups[data.source_mac] = groups.get(data.source_mac, {"org": data.source_org, "packets": []})
		added = False
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
					"time": data.time.strftime("%H/%M/%S"), \
					"source_ip": data.source_ip, \
					"source_port": data.source_port, \
					"dest_mac": data.dest_mac, \
					"dest_ip": data.dest_ip, \
					"dest_port": data.dest_port, \
					"protocol": data.protocol, \
					"good_packet": data.good_packet,
					"allowed": data.allowed
				})
	return json.dumps(groups)

# datas: [PacketData] rules: {"11:22:33:11:22:33": ruleList}
