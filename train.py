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

import numpy as np
from data import CSV2ListAndDict, RuleList, tagList, List2CSV, List2JSON, postJSON

# datas, rules = CSV2ListAndDict("train.csv")
# print(list(map(lambda x: x.__dict__, datas)))
# print(rules[datas[0].source_mac].__dict__)

# rules[datas[0].source_mac].white_list.append((ip, None, None))
# rules[datas[0].source_mac].query(ip, port, protocol)
# print(List2JSON(data))

# rl = RuleList()
# rl.white_list.append(('1.2.3.4', 100, 'HTTPS'))
# print(rl.query('1.2.3.4', 90, 'HTTPS'))
# print(rl.query('1.2.3.4', 80, 'HTTPS'))
# print(rl.query('1.2.3.4', 100, 'HTTP'))

datas, rules = CSV2ListAndDict("featureCapture.csv")
tagList(datas, rules)
jsonFile = List2JSON(datas)
postJSON(jsonFile)
List2CSV(datas, "featureCapture.csv", "output.csv")
# tagList(datas, rules)
# List2CSV(datas, "output.csv")
