import sys

from config import attacker_ip

if __name__ == '__main__':

    for line in iter(sys.stdin.readline, b''):
        try:
            spl = line.strip().split(',')
            features = ','.join(spl[4:])
            src_ip = spl[1]
            dst_ip = spl[3]
            if src_ip == attacker_ip or dst_ip == attacker_ip:
                label = 1
            else:
                label = 0
            line = f'{features},{label}'
            sys.stdout.write(line)
            sys.stdout.flush()
        except:
            pass