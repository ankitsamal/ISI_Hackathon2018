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
from data import loadCSV, MacParser, toJSON

data = CSV2List("train.csv")
# print(list(map(lambda x: x.__dict__, data)))
print(List2JSON(data))
