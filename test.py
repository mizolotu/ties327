import sys

k = 0
try:
    buff = ''
    while True:
        buff += sys.stdin.read(1)
        if buff.endswith('\n'):
            print(len(buff))
            buff = ''
            k = k + 1
except KeyboardInterrupt:
   sys.stdout.flush()
   pass