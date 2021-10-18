import pandas as pd
import tensorflow as tf
import numpy as np
import argparse as arp

from utils import *

if __name__ == '__main__':

    # parse args

    parser = arp.ArgumentParser(description='Train model')
    parser.add_argument('-d', '--data', help='Data files', nargs='+')
    args = parser.parse_args()

    # read data

    X, Y = [], []
    for f in args.data:
        try:
            p = pd.read_csv(f, header=None)
            v = p.values
            X.append(v[:, :-1])
            Y.append(v[:, -1])
        except Exception as e:
            print(e)
    X = np.vstack(X)
    Y = np.hstack(Y)
    assert X.shape[0] == len(Y), 'Something is wrong with the data!'
    assert 0 in np.unique(Y), 'No data with label 0 found, please add normal samples to the dataset!'
    assert 1 in np.unique(Y), 'No data with label 1 found, please add malicious samples to the dataset!'

    # increase the number of malicious samples
    print([len(np.where(Y == y)[0]) for y in np.unique(Y)])
    X, Y = add_more_samples(X, Y)
    print([len(np.where(Y == y)[0]) for y in np.unique(Y)])

