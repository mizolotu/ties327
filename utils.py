import numpy as np

def add_more_samples(X, Y):
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

