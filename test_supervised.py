import sys
import tensorflow as tf
import numpy as np

from queue import Queue
from threading import Thread
from time import time
from config import step

def classify(q, model, step):
    tstart = time()
    ids, batch = [], []
    while True:
        if not q.empty():
            id, features = q.get()
            ids.append(id)
            batch.append(features)

        tnow = time()
        if tnow > (tstart + step):
            if len(batch) > 0:
                batch = np.vstack(batch)
                predictions = model.predict(batch)
                sys.stdout.write('Probability of a reverse shell\n:')
                sys.stdout.flush()
                for id, pr in zip(ids, predictions):
                    line = f'{id} - {pr * 100}%\n'
                    sys.stdout.write(line)
                    sys.stdout.flush()
            ids, batch = [], []
            tstart = time()
            print('\n')

if __name__ == '__main__':

    # load model

    model = tf.keras.models.load_model('supervised_model')

    # queue

    q = Queue()

    # feature extraction thread

    ef_thread = Thread(target=classify, args=(q, model, step), daemon=True)
    ef_thread.start()

    for line in iter(sys.stdin.readline, b''):
        try:
            spl = line.strip().split(',')
            src_ip = spl[0]
            src_port = spl[1]
            dst_ip = spl[2]
            dst_port = spl[3]
            id = f'{src_ip}:{src_port} -> {dst_ip}:{dst_port}'
            features = np.array([float(item) for item in spl[4:]])
            q.put((id, features))
        except Exception as e:
            print(e)
            pass