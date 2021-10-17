import socket, sys

from socket import AF_INET, AF_INET6, inet_ntop
from struct import unpack
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


if __name__ == '__main__':

    # params

    collector_ip = "127.0.0.1"
    collector_port = 6343

    # sflow socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((collector_ip, collector_port))

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

        except:
            pass