import sys
import time
import datetime

while True:
    line = sys.stdin.readline()
    sys.stdout.write(str(datetime.datetime.now().strftime("%H:%M:%S"))+'\t')
    sys.stdout.write(line)
    sys.stdout.flush()
