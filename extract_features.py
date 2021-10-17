import sys, os
import numpy as np

from queue import Queue
from threading import Thread
from time import time

class Flow():

    def __init__(self, ts, id, direction, size, blk_thr=1.0, idl_thr=5.0):

        # lists

        self.id = id
        self.pkts = [[ts, size]]

        # thresholds

        self.blk_thr = blk_thr
        self.idl_thr = idl_thr

        # zero features

        self.fl_dur = 0
        self.tot_bw_pk = 0
        self.fw_pkt_l_std = 0
        self.bw_pkt_l_max = 0
        self.bw_pkt_l_min = 0
        self.bw_pkt_l_avg = 0
        self.bw_pkt_l_std = 0
        self.fl_byt_s = 0
        self.fl_pkt_s = 0
        self.fl_iat_avg = 0
        self.fl_iat_std = 0
        self.fl_iat_max = 0
        self.fl_iat_min = 0
        self.fw_iat_tot = 0
        self.fw_iat_avg = 0
        self.fw_iat_std = 0
        self.fw_iat_max = 0
        self.fw_iat_min = 0
        self.bw_iat_tot = 0
        self.bw_iat_avg = 0
        self.bw_iat_std = 0
        self.bw_iat_max = 0
        self.bw_iat_min = 0
        self.fw_pkt_s = 0
        self.bw_pkt_s = 0
        self.pkt_len_std = 0
        self.down_up_ratio = 0
        self.fw_byt_blk_avg = 0
        self.fw_pkt_blk_avg = 0
        self.fw_blk_rate_avg = 0
        self.bw_byt_blk_avg = 0
        self.bw_pkt_blk_avg = 0
        self.bw_blk_rate_avg = 0
        self.fw_pkt_sub_avg = 0
        self.fw_byt_sub_avg = 0
        self.bw_pkt_sub_avg = 0
        self.bw_byt_sub_avg = 0
        self.atv_avg = 0
        self.atv_std = 0
        self.atv_max = 0
        self.atv_min = 0
        self.idl_avg = 0
        self.idl_std = 0
        self.idl_max = 0
        self.idl_min = 0

        self.last_ts = ts
        self.newpkts = True

        # features

        if direction == 1:
            self.directions = [1]
            self.tot_fw_pk = 1
            self.tot_l_fw_pkt = size
            self.fw_pkt_l_max = size
            self.fw_pkt_l_min = size
            self.fw_pkt_l_avg = size
            self.subfl_fw_pk = 1
            self.subfl_fw_byt = size
        else:
            self.directions = [-1]
            self.tot_bw_pk = 1
            self.tot_l_bw_pkt = size
            self.bw_pkt_l_max = size
            self.bw_pkt_l_min = size
            self.bw_pkt_l_avg = size
            self.subfl_bw_pk = 1
            self.subfl_bw_byt = size

        self.pkt_len_min = size
        self.pkt_len_max = size
        self.pkt_len_avg = size

    def append(self, ts, size, direction):
        self.pkts.append([ts, size])
        self.directions.append(direction)
        self.last_ts = ts
        self.newpkts = True

    def get_features(self):

        # recalculate features

        fw_pkts = np.array([pkt for pkt, d in zip(self.pkts, self.directions) if d > 0])
        bw_pkts = np.array([pkt for pkt, d in zip(self.pkts, self.directions) if d < 0])

        # forward and backward bulks

        if len(fw_pkts) > 1:
            fwt = np.zeros(len(fw_pkts))
            fwt[1:] = fw_pkts[1:, 0] - fw_pkts[:-1, 0]
            fw_blk_idx = np.where(fwt <= self.blk_thr)[0]
            fw_bulk = fw_pkts[fw_blk_idx, :]
            fw_blk_dur = np.sum(fwt[fw_blk_idx])
        elif len(fw_pkts) == 1:
            fw_bulk = [fw_pkts[0, :]]
            fw_blk_dur = 0
        else:
            fw_bulk = []
            fw_blk_dur = 0
        fw_bulk = np.array(fw_bulk)

        if len(bw_pkts) > 1:
            bwt = np.zeros(len(bw_pkts))
            bwt[1:] = bw_pkts[1:, 0] - bw_pkts[:-1, 0]
            bw_blk_idx = np.where(bwt <= self.blk_thr)[0]
            bw_bulk = bw_pkts[bw_blk_idx, :]
            bw_blk_dur = np.sum(bwt[bw_blk_idx])
        elif len(bw_pkts) == 1:
            bw_bulk = [bw_pkts[0, :]]
            bw_blk_dur = 0
        else:
            bw_bulk = []
            bw_blk_dur = 0
        bw_bulk = np.array(bw_bulk)

        pkts = np.array(self.pkts)

        iat = pkts[1:, 0] - pkts[:-1, 0]
        self.fl_dur = pkts[-1, 0] - pkts[0, 0]
        self.tot_fw_pk = len(fw_pkts)
        self.tot_bw_pk = len(bw_pkts)
        self.tot_l_fw_pkt = np.sum(fw_pkts[:, 1]) if len(fw_pkts) > 0 else 0
        self.fw_pkt_l_max = np.max(fw_pkts[:, 1]) if len(fw_pkts) > 0 else 0
        self.fw_pkt_l_min = np.min(fw_pkts[:, 1]) if len(fw_pkts) > 0 else 0
        self.fw_pkt_l_avg = np.mean(fw_pkts[:, 1]) if len(fw_pkts) > 0 else 0
        self.fw_pkt_l_std = np.std(fw_pkts[:, 1]) if len(fw_pkts) > 0 else 0
        self.bw_pkt_l_max = np.max(bw_pkts[:, 1]) if len(bw_pkts) > 0 else 0
        self.bw_pkt_l_min = np.min(bw_pkts[:, 1]) if len(bw_pkts) > 0 else 0
        self.bw_pkt_l_avg = np.mean(bw_pkts[:, 1]) if len(bw_pkts) > 0 else 0
        self.bw_pkt_l_std = np.std(bw_pkts[:, 1]) if len(bw_pkts) > 0 else 0
        self.fl_byt_s = np.sum(pkts[:, 1]) / self.fl_dur if self.fl_dur > 0 else 0
        self.fl_pkt_s = len(pkts) / self.fl_dur if self.fl_dur > 0 else 0
        self.fl_iat_avg = np.mean(iat) if len(pkts) > 1 else 0
        self.fl_iat_std = np.std(iat) if len(pkts) > 1 else 0
        self.fl_iat_max = np.max(iat) if len(pkts) > 1 else 0
        self.fl_iat_min = np.min(iat) if len(pkts) > 1 else 0
        self.fw_iat_tot = np.sum(fw_pkts[1:, 0] - fw_pkts[:-1, 0]) if len(fw_pkts) > 1 else 0
        self.fw_iat_avg = np.mean(fw_pkts[1:, 0] - fw_pkts[:-1, 0]) if len(fw_pkts) > 1 else 0
        self.fw_iat_std = np.std(fw_pkts[1:, 0] - fw_pkts[:-1, 0]) if len(fw_pkts) > 1 else 0
        self.fw_iat_max = np.max(fw_pkts[1:, 0] - fw_pkts[:-1, 0]) if len(fw_pkts) > 1 else 0
        self.fw_iat_min = np.min(fw_pkts[1:, 0] - fw_pkts[:-1, 0]) if len(fw_pkts) > 1 else 0
        self.bw_iat_tot = np.sum(bw_pkts[1:, 0] - bw_pkts[:-1, 0]) if len(bw_pkts) > 1 else 0
        self.bw_iat_avg = np.mean(bw_pkts[1:, 0] - bw_pkts[:-1, 0]) if len(bw_pkts) > 1 else 0
        self.bw_iat_std = np.std(bw_pkts[1:, 0] - bw_pkts[:-1, 0]) if len(bw_pkts) > 1 else 0
        self.bw_iat_max = np.max(bw_pkts[1:, 0] - bw_pkts[:-1, 0]) if len(bw_pkts) > 1 else 0
        self.bw_iat_min = np.min(bw_pkts[1:, 0] - bw_pkts[:-1, 0]) if len(bw_pkts) > 1 else 0

        if len(fw_pkts) > 0:
            fw_dur = fw_pkts[-1, 0] - fw_pkts[0, 0]
            self.fw_pkt_s = len(fw_pkts) / fw_dur if fw_dur > 0 else 0
        else:
            self.fw_pkt_s = 0
        if len(bw_pkts) > 0:
            bw_dur = bw_pkts[-1, 0] - bw_pkts[0, 0]
            self.bw_pkt_s = len(bw_pkts) / bw_dur if bw_dur > 0 else 0
        else:
            self.bw_pkt_s = 0

        self.pkt_len_min = np.min(pkts[:, 1])
        self.pkt_len_max = np.max(pkts[:, 1])
        self.pkt_len_avg = np.mean(pkts[:, 1])
        self.pkt_len_std = np.std(pkts[:, 1])

        self.down_up_ratio = len(bw_pkts) / len(fw_pkts) if len(fw_pkts) > 0 else 0

        self.fw_byt_blk_avg = np.mean(fw_bulk[:, 1]) if len(fw_bulk) > 0 else 0
        self.fw_pkt_blk_avg = len(fw_bulk)
        self.fw_blk_rate_avg = np.sum(fw_bulk[:, 1]) / fw_blk_dur if fw_blk_dur > 0 else 0
        self.bw_byt_blk_avg = np.mean(bw_bulk[:, 1]) if len(bw_bulk) > 0 else 0
        self.bw_pkt_blk_avg = len(bw_bulk)
        self.bw_blk_rate_avg = np.sum(bw_bulk[:, 1]) / bw_blk_dur if bw_blk_dur > 0 else 0

        self.subfl_fw_pk = len(fw_pkts) / (len(fw_pkts) - len(fw_bulk)) if len(fw_pkts) - len(fw_bulk) > 0 else 0
        self.subfl_fw_byt = np.sum(fw_pkts[:, 1]) / (len(fw_pkts) - len(fw_bulk)) if len(fw_pkts) - len(fw_bulk) > 0 else 0
        self.subfl_bw_pk = len(bw_pkts) / (len(bw_pkts) - len(bw_bulk)) if len(bw_pkts) - len(bw_bulk) > 0 else 0
        self.subfl_bw_byt = np.sum(bw_pkts[:, 1]) / (len(bw_pkts) - len(bw_bulk)) if len(bw_pkts) - len(bw_bulk) > 0 else 0

        self.newpkts = False

        return np.array([
            self.fl_dur,  # 0
            self.tot_fw_pk,  # 1
            self.tot_bw_pk,  # 2
            self.tot_l_fw_pkt,  # 3
            self.fw_pkt_l_max,  # 4
            self.fw_pkt_l_min,  # 5
            self.fw_pkt_l_avg,  # 6
            self.fw_pkt_l_std,  # 7
            self.bw_pkt_l_max,  # 8
            self.bw_pkt_l_min,  # 9
            self.bw_pkt_l_avg,  # 10
            self.bw_pkt_l_std,  # 11
            self.fl_byt_s,  # 12
            self.fl_pkt_s,  # 13
            self.fl_iat_avg,  # 14
            self.fl_iat_std,  # 15
            self.fl_iat_max,  # 16
            self.fl_iat_min,  # 17
            self.fw_iat_tot,  # 18
            self.fw_iat_avg,  # 19
            self.fw_iat_std,  # 20
            self.fw_iat_max,  # 21
            self.fw_iat_min,  # 22
            self.bw_iat_tot,  # 23
            self.bw_iat_avg,  # 24
            self.bw_iat_std,  # 25
            self.bw_iat_max,  # 26
            self.bw_iat_min,  # 27
            self.fw_pkt_s,  # 28
            self.bw_pkt_s,  # 29
            self.pkt_len_min,  # 30
            self.pkt_len_max,  # 31
            self.pkt_len_avg,  # 32
            self.pkt_len_std,  # 33
            self.down_up_ratio,  # 34
            self.fw_byt_blk_avg,  # 35
            self.fw_pkt_blk_avg,  # 36
            self.fw_blk_rate_avg,  # 37
            self.bw_byt_blk_avg,  # 38
            self.bw_pkt_blk_avg,  # 39
            self.bw_blk_rate_avg,  # 40
            self.fw_pkt_sub_avg,  # 41
            self.fw_byt_sub_avg,  # 42
            self.bw_pkt_sub_avg,  # 43
            self.bw_byt_sub_avg,  # 44
            self.atv_avg,  # 45
            self.atv_std,  # 46
            self.atv_max,  # 47
            self.atv_min,  # 48
            self.idl_avg,  # 49
            self.idl_std,  # 50
            self.idl_max,  # 51
            self.idl_min  # 52
        ])

def extract_features(pkt_q, subnet, ports, step, thr):
    flow_ids = []
    flow_objects = []
    tstart = time()
    while True:

        if not pkt_q.empty():
            timestamp, dst, dport, src, sport, size = pkt_q.get()
            if sport in ports and dst.startswith(subnet):
                id = [dst, dport, src, sport]
                direction = -1
            elif dport in ports and src.startswith(subnet):
                id = [src, sport, dst, dport]
                direction = 1
        else:
            id = None
            direction = 0

        tnow = time()
        if tnow > (tstart + step):

            # remove old flows

            tmp_ids = []
            tmp_objects = []
            for i, o in zip(flow_ids, flow_objects):
                if o.last_ts > tnow - thr:
                    tmp_ids.append(i)
                    tmp_objects.append(o)
            flow_ids = list(tmp_ids)
            flow_objects = list(tmp_objects)

            # calculate_features

            for i, o in zip(flow_ids, flow_objects):
                if o.newpkts:
                    o_features = o.get_features()
                    id_str = ','.join([str(item) for item in i])
                    features_str = ','.join([str(item) for item in o_features])
                    print(f'{id_str},{features_str}')

            # update time

            tstart = time()

        # add packet

        if id is not None:
            if id in flow_ids:
                idx = flow_ids.index(id)
                flow_objects[idx].append(timestamp, size, direction)
            else:
                flow_ids.append(id)
                flow_objects.append(Flow(timestamp, id, direction, size))


if __name__ == '__main__':

    step = 3
    subnet = '192.168.10.'
    ports = [80, 443]
    thr = 30

    pkt_q = Queue()

    ef_thread = Thread(target=extract_features, args=(pkt_q, subnet, ports, step, thr), daemon=True)
    ef_thread.start()

    for line in sys.stdin:
        try:
            spl = line.strip().split(',')
            timestamp = float(spl[0])
            src = spl[1]
            sport = int(spl[2])
            dst = spl[3]
            dport = int(spl[4])
            size = float(spl[5])
            pkt_q.put([timestamp, src, sport, dst, dport, size])

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(e, fname, exc_tb.tb_lineno)
