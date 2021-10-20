# sflow collector parameters

collector_ip = "127.0.0.1"
collector_port = 6343

# feature extraction parameters

subnet = '192.168.'
ports = [80, 443]
step = 3
thr = 30

# dataset creation parameters

attacker_ip = '192.168.12.2'

# ml parameters

validation_split = 0.4  # float between 0 and 1
layers = [256, 256]  # list of integers
dropout = 0.5  # float between 0 and 1
learning_rate = 1e-4  # float
batch_size = 64  # integer

epochs = 1000
patience = 100