import socket, sys
import numpy as np

from socket import AF_INET, AF_INET6, inet_ntop
from struct import unpack
from queue import Queue
from threading import Thread
from time import time


class sFlowRecordBase:
    def __init__(self, datagram):
        self.data = datagram

    def __repr__(self):
        return """
            sFlow Record Type Not Implimented:
                Incomplete
            """

    def __len__(self):
        return 1


class sFlowRawPacketHeader:
    "flowData: enterprise = 0, format = 1"

    def __init__(self, datagram):
        self.header_protocol = unpack(">i", datagram[0:4])[0]
        self.frame_length = unpack(">i", datagram[4:8])[0]
        self.payload_removed = unpack(">i", datagram[8:12])[0]
        self.header_size = unpack(">i", datagram[12:16])[0]
        self.header = datagram[(16) : (16 + self.header_size)]

        if self.header_protocol == 1:  # Ethernet
            self.destination_mac = self.header[0:6].hex("-")
            self.source_mac = self.header[6:12].hex("-")
            self.type = unpack(">H", self.header[12:14])[0]

            offset = 0
            if unpack(">H", self.header[12:14])[0] == 37120:  # 802.1ad
                offset = 8
                self.outer_vlan = divmod(unpack(">H", self.header[14:16])[0], 4096)[1]
                self.inner_vlan = divmod(unpack(">H", self.header[18:20])[0], 4096)[1]

            if unpack(">H", self.header[12:14])[0] == 33024:  # 802.1Q
                offset = 4
                self.vlan = divmod(unpack(">H", self.header[14:16])[0], 4096)[1]

            if unpack(">H", self.header[12 + offset : 14 + offset])[0] == 2048:
                self.ip_version, self.ip_header_legth = divmod(self.header[14 + offset], 16)
                self.ip_dscp, self.ip_ecn = divmod(self.header[15 + offset], 4)
                self.ip_total_length = unpack(">H", self.header[16 + offset : 18 + offset])[0]
                self.ip_identification = unpack(">H", self.header[18 + offset : 20 + offset])[0]
                self.ip_flags, self.ip_fragement_offset = divmod(unpack(">H", self.header[20 + offset : 22 + offset])[0], 8192)
                self.ip_ttl = self.header[22 + offset]
                self.ip_protocol = self.header[23 + offset]
                self.ip_checkum = unpack(">H", self.header[24 + offset : 26 + offset])[0]
                self.ip_source = inet_ntop(AF_INET, self.header[26 + offset : 30 + offset])
                self.ip_destination = inet_ntop(AF_INET, self.header[30 + offset : 34 + offset])
                self.source_port = unpack(">H", self.header[34 + offset : 36 + offset])[0]
                self.destination_port = unpack(">H", self.header[36 + offset : 38 + offset])[0]
                #self.tcp_flags = unpack(">i", self.header[42 + offset : 46 + offset])[0]

                if self.ip_header_legth > 5:
                    self.ip_options = self.header[34 + offset : (35 + offset) + ((self.ip_header_legth - 5) * 4)]
                self.ip_remaining_header = self.header[34 + offset + ((self.ip_header_legth - 5) * 4) :]

    def __repr__(self):
        return f"""
            Raw Packet Header:
                Protocol: {self.header_protocol}
                Frame Length: {self.frame_length}
                Header Size: {self.header_size}
                Payload Removed: {self.payload_removed}
                Source MAC: {self.source_mac}
                Destination MAC: {self.destination_mac}
        """

    def __len__(self):
        return 1


s_flow_record_format = {
    (1, 0, 1): sFlowRawPacketHeader
}


class sFlowRecord:

    def __init__(self, header, sample_type, datagram):
        self.header = header
        self.sample_type = sample_type
        self.enterprise, self.format = divmod(self.header, 4096)
        self.datagram = datagram
        self.record = s_flow_record_format.get((sample_type, self.enterprise, self.format), sFlowRecordBase)(datagram)


class sFlowSample:

    def __init__(self, header, sample_size, datagram):

        self.len = sample_size
        self.data = datagram

        sample_header = unpack(">i", header)[0]
        self.enterprise, self.sample_type = divmod(sample_header, 4096)
        # 0 sample_data / 1 flow_data (single) / 2 counter_data (single)
        #             / 3 flow_data (expanded) / 4 counter_data (expanded)

        self.sequence = unpack(">i", datagram[0:4])[0]

        if self.sample_type in [1, 2]:
            sample_source = unpack(">i", datagram[4:8])[0]
            self.source_type, self.source_index = divmod(sample_source, 16777216)
            data_position = 8
        elif self.sample_type in [3, 4]:
            self.source_type, self.source_index = unpack(">ii", datagram[4:12])
            data_position = 12
        else:
            pass  # sampleTypeError
        self.records = []

        if self.sample_type in [1, 3]:  # Flow
            self.sample_rate, self.sample_pool, self.dropped_packets = unpack(
                ">iii", datagram[data_position : (data_position + 12)]
            )
            data_position += 12
            if self.sample_type == 1:
                input_interface, output_interface = unpack(">ii", datagram[(data_position) : (data_position + 8)])
                data_position += 8
                self.input_if_format, self.input_if_value = divmod(input_interface, 1073741824)
                self.output_if_format, self.output_if_value = divmod(output_interface, 1073741824)
            elif self.sample_type == 3:
                self.input_if_format, self.input_if_value, self.output_if_format, self.output_if_value = unpack(
                    ">ii", datagram[data_position : (data_position + 16)]
                )
                data_position += 16
            self.record_count = unpack(">i", datagram[data_position : data_position + 4])[0]
            data_position += 4

        elif self.sample_type in [2, 4]:  # Counters
            self.record_count = unpack(">i", datagram[data_position : (data_position + 4)])[0]
            data_position += 4
            self.sample_rate = 0
            self.sample_pool = 0
            self.dropped_packets = 0
            self.input_if_format = 0
            self.input_if_value = 0
            self.output_if_format = 0
            self.output_if_value = 0
        else:  # sampleTypeError
            self.record_count = 0
        for _ in range(self.record_count):
            record_header = unpack(">i", datagram[(data_position) : (data_position + 4)])[0]
            record_size = unpack(">i", datagram[(data_position + 4) : (data_position + 8)])[0]
            record_data = datagram[(data_position + 8) : (data_position + record_size + 8)]
            self.records.append(sFlowRecord(record_header, self.sample_type, record_data))
            data_position += record_size + 8


class sFlow:

    def __init__(self, datagram):

        self.len = len(datagram)
        self.data = datagram
        self.datagram_version = unpack(">i", datagram[0:4])[0]
        self.address_type = unpack(">i", datagram[4:8])[0]
        if self.address_type == 1:
            self.agent_address = inet_ntop(AF_INET, datagram[8:12])
            self.sub_agent = unpack(">i", datagram[12:16])[0]
            self.sequence_number = unpack(">i", datagram[16:20])[0]
            self.system_uptime = unpack(">i", datagram[20:24])[0]
            self.number_sample = unpack(">i", datagram[24:28])[0]
            data_position = 28
        elif self.address_type == 2:
            self.agent_address = inet_ntop(AF_INET6, datagram[8:24])
            self.sub_agent = unpack(">i", datagram[24:28])[0]
            self.sequence_number = unpack(">i", datagram[28:32])[0]
            self.system_uptime = unpack(">i", datagram[32:36])[0]
            self.number_sample = unpack(">i", datagram[36:40])[0]
            data_position = 40
        else:
            self.agent_address = 0
            self.sub_agent = 0
            self.sequence_number = 0
            self.system_uptime = 0
            self.number_sample = 0
        self.samples = []
        if self.number_sample > 0:
            for _ in range(self.number_sample):
                sample_header = datagram[(data_position) : (data_position + 4)]
                sample_size = unpack(">i", datagram[(data_position + 4) : (data_position + 8)])[0]
                sample_datagram = datagram[(data_position + 8) : (data_position + sample_size + 8)]

                self.samples.append(sFlowSample(sample_header, sample_size, sample_datagram))
                data_position = data_position + 8 + sample_size


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

            if step <= thr:
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

    # params

    collector_ip = "127.0.0.1"
    collector_port = 6343
    subnet = '192.168.10.'
    ports = [80, 443]
    step = 3
    thr = 3

    # sflow socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((collector_ip, collector_port))

    # queue

    pkt_q = Queue()

    # feature extraction thread

    ef_thread = Thread(target=extract_features, args=(pkt_q, subnet, ports, step, thr), daemon=True)
    #ef_thread.start()

    while True:

        data, addr = sock.recvfrom(3000)
        try:
            sflow_data = sFlow(data)
            for i in range(sflow_data.number_sample):
                sflow_record = sflow_data.samples[i].records[1]
                if sflow_record.format == 1:
                    record = sflow_record.record
                    if record.header_protocol == 1:
                        line = f'{time()},{record.ip_source},{record.source_port},{record.ip_destination},{record.destination_port},{record.ip_total_length}\n'
                        sys.stdout.write(line)
                        sys.stdout.flush()
                        #print(f'{time()},{record.ip_source},{record.source_port},{record.ip_destination},{record.destination_port},{record.ip_total_length}')
                        #pkt_q.put([time(), record.ip_source, record.source_port, record.ip_destination, record.destination_port, record.ip_total_length])

        except:
            pass