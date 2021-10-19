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
layers = [64, 64]
dropout = 0.5
learning_rate = 0.5e-5
batch_size = 64

epochs = 1000
patience = 100