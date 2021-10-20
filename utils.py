import numpy as np
import pandas as pd

def read_data(data_files):
    X, Y = [], []
    for f in data_files:
        try:
            p = pd.read_csv(f, header=None)
            v = p.values
            X.append(v[:, :-1])
            Y.append(v[:, -1])
        except Exception as e:
            print(e)
    return np.vstack(X), np.hstack(Y)

def remove_bias(X, Y):
    Yu = np.unique(Y)
    nu = [len(np.where(Y == y)[0]) for y in Yu]
    n = np.max(nu)
    X_new, Y_new = [], []
    for y in Yu:
        i = np.where(Y == y)[0]
        idx = np.random.choice(i, n)
        X_new.append(X[idx, :])
        Y_new.append(Y[idx])
    return np.vstack(X_new), np.hstack(Y_new)