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
    print(X.shape, Y.shape)

