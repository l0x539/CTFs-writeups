import time
import datetime
import requests

d = time.time()
r = requests.get('http://challenges.0x0539.net:3003/')

year = 2020
month = 7
day = 23
ad = r.headers['Date'].split(', ')[1].split(' ')[3].split(':')
hour = int(ad[0])
minutes = int(ad[1])
secondes = int(ad[2])

now = datetime.datetime(year, month, day, hour, minutes, secondes)

print(now.timestamp(), d)
print(now.timestamp()- d)
print(now)
