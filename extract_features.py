import sys, os

class Flow():

    def __init__(self, ts, id, features, flags, blk_thr=1.0, idl_thr=5.0):

        # lists

        self.id = id
        self.pkts = [[ts, *features]]
        self.flags = [flags]
        self.directions = [1]

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
        self.fw_psh_flag = 0
        self.bw_psh_flag = 0
        self.fw_urg_flag = 0
        self.bw_urg_flag = 0
        self.bw_hdr_len = 0
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
        self.bw_win_byt = 0
        self.atv_avg = 0
        self.atv_std = 0
        self.atv_max = 0
        self.atv_min = 0
        self.idl_avg = 0
        self.idl_std = 0
        self.idl_max = 0
        self.idl_min = 0
        self.flag_counts = [0 for _ in range(5)]

        # features

        self.is_tcp = 0
        self.is_udp = 0
        if id[4] == 6:
            self.is_tcp = 1
        elif id[4] == 17:
            self.is_udp = 1
        for i in range(len(self.flag_counts)):
            self.flag_counts[i] = 1 if flags[i] == 1 else 0
        self.tot_fw_pk = 1
        psize = features[0]
        self.tot_l_fw_pkt = psize
        self.fw_pkt_l_max = psize
        self.fw_pkt_l_min = psize
        self.fw_pkt_l_avg = psize
        self.fw_hdr_len = psize
        self.pkt_len_min = psize
        self.pkt_len_max = psize
        self.pkt_len_avg = psize
        self.subfl_fw_pk = 1
        self.subfl_fw_byt = psize
        self.fw_win_byt = psize
        self.fw_act_pkt = 1 if features[2] > 0 else 0

        # is active

        self.is_active = True

    def append(self, ts, features, flags, direction):
        self.pkts.append([ts, *features])
        self.flags.append(flags)
        self.directions.append(direction)
        if flags[0] == 1 or flags[2] == 1:
            self.is_active = False

    def get_features(self):

        # recalculate features

        npkts = len(self.pkts)
        fw_pkts = np.array([pkt for pkt, d in zip(self.pkts, self.directions) if d > 0])
        bw_pkts = np.array([pkt for pkt, d in zip(self.pkts, self.directions) if d < 0])
        fw_flags = np.array([f for f, d in zip(self.flags, self.directions) if d > 0])
        bw_flags = np.array([f for f, d in zip(self.flags, self.directions) if d < 0])

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
        flags = np.array(self.flags)
        if npkts > 1:
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
        self.fw_psh_flag = np.sum(fw_flags[:, 3]) if len(fw_flags) > 0 else 0
        self.bw_psh_flag = np.sum(bw_flags[:, 3]) if len(bw_flags) > 0 else 0

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

        self.fin_cnt = np.sum(flags[:, 0])
        self.syn_cnt = np.sum(flags[:, 1])
        self.rst_cnt = np.sum(flags[:, 2])
        self.psh_cnt = np.sum(flags[:, 3])
        self.ack_cnt = np.sum(flags[:, 4])

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

        self.fw_win_byt = fw_pkts[0, 3] if len(fw_pkts) > 0 else 0
        self.bw_win_byt = bw_pkts[0, 3] if len(bw_pkts) > 0 else 0

        self.fw_act_pkt = len([pkt for pkt in fw_pkts if self.is_tcp == 1 and pkt[1] > pkt[2]])
        self.fw_seg_min = np.min(fw_pkts[:, 2]) if len(fw_pkts) > 0 else 0

        return np.array([
            self.is_tcp,  # 0
            self.is_udp,  # 1
            self.fl_dur,  # 2
            self.tot_fw_pk,  # 3
            self.tot_bw_pk,  # 4
            self.tot_l_fw_pkt,  # 5
            self.fw_pkt_l_max,  # 6
            self.fw_pkt_l_min,  # 7
            self.fw_pkt_l_avg,  # 8
            self.fw_pkt_l_std,  # 9
            self.bw_pkt_l_max,  # 10
            self.bw_pkt_l_min,  # 11
            self.bw_pkt_l_avg,  # 12
            self.bw_pkt_l_std,  # 13
            self.fl_byt_s,  # 14
            self.fl_pkt_s,  # 15
            self.fl_iat_avg,  # 16
            self.fl_iat_std,  # 17
            self.fl_iat_max,  # 18
            self.fl_iat_min,  # 19
            self.fw_iat_tot,  # 20
            self.fw_iat_avg,  # 21
            self.fw_iat_std,  # 22
            self.fw_iat_max,  # 23
            self.fw_iat_min,  # 24
            self.bw_iat_tot,  # 25
            self.bw_iat_avg,  # 26
            self.bw_iat_std,  # 27
            self.bw_iat_max,  # 28
            self.bw_iat_min,  # 29
            self.fw_psh_flag,  # 30
            self.bw_psh_flag,  # 31
            self.fw_pkt_s,  # 32
            self.bw_pkt_s,  # 33
            self.pkt_len_min,  # 34
            self.pkt_len_max,  # 35
            self.pkt_len_avg,  # 36
            self.pkt_len_std,  # 37
            *self.flag_counts, # 38, 39, 40, 41, 42
            self.down_up_ratio,  # 43
            self.fw_byt_blk_avg,  # 44
            self.fw_pkt_blk_avg,  # 45
            self.fw_blk_rate_avg,  # 46
            self.bw_byt_blk_avg,  # 47
            self.bw_pkt_blk_avg,  # 48
            self.bw_blk_rate_avg,  # 49
            self.fw_pkt_sub_avg,  # 50
            self.fw_byt_sub_avg,  # 51
            self.bw_pkt_sub_avg,  # 52
            self.bw_byt_sub_avg,  # 53
            self.fw_win_byt,  # 54
            self.bw_win_byt,  # 55
            self.fw_act_pkt,  # 56
            self.atv_avg,  # 57
            self.atv_std,  # 58
            self.atv_max,  # 59
            self.atv_min,  # 60
            self.idl_avg,  # 61
            self.idl_std,  # 62
            self.idl_max,  # 63
            self.idl_min  # 64
        ])

if __name__ == '__main__':

    ports = [80, 443]

    flow_ids = []
    flow_objects = []
    flow_features = []

    for line in sys.stdin:
        try:
            spl = line.split(',')
            print(spl)


        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(e, fname, exc_tb.tb_lineno)
