# sflow collector parameters

collector_ip = "127.0.0.1"
collector_port = 6343

# feature extraction parameters

ports = [80, 443]
step = 3
thr = 30

# dataset creation parameters

attacker_ip = '192.168.12.2'

# ml parameters

validation_split = 0.4
layers = [256, 256]
dropout = 0.5
learning_rate = 1e-4
batch_size = 64

epochs = 1000
patience = 250