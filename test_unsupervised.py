import sys, json
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
                batch = (batch - xmin[None, :]) / (xmax[None, :] - xmin[None, :] + 1e-10)
                R = model.predict(batch)
                probs = np.linalg.norm(R - batch, axis=-1)
                predictions = np.clip(probs / thr, 0, 1)
                sys.stdout.write('Probability of a reverse shell:\n')
                sys.stdout.flush()
                idx = np.argsort(predictions)[::-1]
                for i in idx:
                    line = f'{ids[i]} - {predictions[i] * 100} %\n'
                    sys.stdout.write(line)
                    sys.stdout.flush()
            ids, batch = [], []
            tstart = time()
            print('...')

if __name__ == '__main__':

    # load model

    model = tf.keras.models.load_model('unsupervised_model')

    # load params

    with open('params', 'r') as f:
        params = json.load(f)
    xmin = np.array(params['xmin'])
    xmax = np.array(params['xmax'])
    thr = params['thr']

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
            id = f'{src_ip}:{src_port}->{dst_ip}:{dst_port}'
            features = np.array([float(item) for item in spl[4:]])
            q.put((id, features))
        except Exception as e:
            print(e)
            pass