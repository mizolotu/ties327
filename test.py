import sys

k = 0
try:
    while True:
        print(sys.stdin.readline())
        k += 1
except KeyboardInterrupt:
    sys.stdout.flush()
    pass