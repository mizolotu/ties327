import tensorflow as tf
import numpy as np
import argparse as arp

from utils import read_data, remove_bias
from config import layers, dropout, learning_rate, batch_size, epochs, patience, validation_split

if __name__ == '__main__':

    # parse args

    parser = arp.ArgumentParser(description='Train model')
    parser.add_argument('-t', '--traindata', help='Train data', nargs='+')
    parser.add_argument('-i', '--infdata', help='Inference data', nargs='+')
    args = parser.parse_args()

    # read data

    X, Y = read_data(args.traindata)
    assert X.shape[0] == len(Y), 'Something is wrong with the data!'
    assert 0 in np.unique(Y), 'No data with label 0 found, please add normal samples to the dataset!'
    assert 1 in np.unique(Y), 'No data with label 1 found, please add malicious samples to the dataset!'

    # increase the number of malicious samples

    X, Y = remove_bias(X, Y)

    # minmax std

    xmin = np.min(X, 0)
    xmax = np.max(X, 0)
    X = (X - xmin[None, :]) / (xmax[None, :] - xmin[None, :] + 1e-10)

    # split into normal and malicious data

    idx0 = np.where(Y == 0)[0]
    idx1 = np.where(Y == 1)[0]
    X0 = X[idx0, :]
    Y0 = Y[idx0]
    X1 = X[idx1, :]
    Y1 = Y[idx1]

    # compile model

    nfeatures = X.shape[1]
    inputs = tf.keras.layers.Input(shape=(nfeatures,))
    hidden = tf.keras.layers.BatchNormalization()(inputs)
    for layer in layers:
        hidden = tf.keras.layers.Dense(layer, activation='relu')(hidden)
        hidden = tf.keras.layers.Dropout(dropout)(hidden)
    outputs = tf.keras.layers.Dense(nfeatures, activation='linear')(hidden)
    model = tf.keras.models.Model(inputs=inputs, outputs=outputs)
    model.compile(loss=tf.keras.losses.MeanSquaredError(), optimizer=tf.keras.optimizers.Adam(lr=learning_rate))

    # fit the model

    model.fit(
        X0, X0,
        validation_split=validation_split,
        epochs=epochs,
        batch_size=batch_size,
        callbacks=[tf.keras.callbacks.EarlyStopping(
            monitor='val_loss',
            verbose=0,
            patience=patience,
            mode='min',
            restore_best_weights=True
        )]
    )

    R = model.predict(X)
    probs = np.linalg.norm(R - X, axis=-1)
    n = len(Y)
    p0 = probs[np.where(Y == 0)[0]]
    p1 = probs[np.where(Y == 1)[0]]
    p0si = np.argsort(p0)
    p1si = np.argsort(p1)
    p0s = p0[p0si]
    p1s = p1[p1si]
    n0 = len(p0s)
    n1 = len(p1s)
    if p1s[0] > p0s[-1]:
        print('here')
        acc = [1]
        thr = [(p1s[0] + p0s[-1]) / 2]
    else:
        idx = np.where(p0s > p1s[0])[0]
        acc = [float(len(p0s) - len(idx) + len(p1s)) / n, *np.zeros(len(idx))]
        h = n0 - len(idx)
        n10 = 0
        for i, j in enumerate(idx):
            thr = p0s[j]
            thridx = np.where(p1s[n10:] < thr)[0]
            n10 += len(thridx)
            h += 1
            acc[i + 1] = (h - n10 + n1) / n
    argmax = np.argmax(acc)
    thr_best = thr[argmax]
    print(thr_best, np.max(acc))

    # save model

    model.save('unsupervised_model')

    # save thr

    with open('thr', 'w') as f:
        f.write(str(thr_best))

    # test if there inference data

    if args.infdata is not None:
        Xi, labels = read_data(args.infdata)
        R = model.predict(X)
        probs = np.linalg.norm(R - X, axis=-1)
        binary_predictions = np.zeros_like(probs)
        binary_predictions[np.where(probs > thr_best)[0]] = 1
        idx_tp = np.where((labels == 1) & (binary_predictions == 1))[0]  # true positives
        idx_tn = np.where((labels == 0) & (binary_predictions == 0))[0]  # true negatives
        idx_fp = np.where((labels == 0) & (binary_predictions == 1))[0]  # false positives
        idx_fn = np.where((labels == 1) & (binary_predictions == 0))[0]  # false negatives
        acc = float(len(idx_tp) + len(idx_tn)) / len(labels) * 100
        tpr = float(len(idx_tp)) / (len(idx_tp) + len(idx_fn)) * 100
        fpr = float(len(idx_fp)) / (len(idx_tn) + len(idx_fp)) * 100
        print(f'Accuracy = {acc}%\nTrue positive rate = {tpr}%\nFalse positive rate = {fpr}%')