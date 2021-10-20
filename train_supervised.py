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

    # compile model

    nfeatures = X.shape[1]
    inputs = tf.keras.layers.Input(shape=(nfeatures,))
    hidden = tf.keras.layers.BatchNormalization()(inputs)
    for layer in layers:
        hidden = tf.keras.layers.Dense(layer, activation='relu')(hidden)
        hidden = tf.keras.layers.Dropout(dropout)(hidden)
    outputs = tf.keras.layers.Dense(1, activation='sigmoid')(hidden)
    model = tf.keras.models.Model(inputs=inputs, outputs=outputs)
    model.compile(loss=tf.keras.losses.BinaryCrossentropy(), optimizer=tf.keras.optimizers.Adam(lr=learning_rate), metrics=[tf.keras.metrics.BinaryAccuracy(name='accuracy'), tf.keras.metrics.Precision(name='precision')])

    # fit the model

    model.fit(
        X, Y,
        validation_split=validation_split,
        epochs=epochs,
        batch_size=batch_size,
        callbacks=[tf.keras.callbacks.EarlyStopping(
            monitor='val_accuracy',
            verbose=0,
            patience=patience,
            mode='max',
            restore_best_weights=True
        )]
    )

    # save model

    model.save('supervised_model')

    # test if there is inference data

    if args.infdata is not None:
        Xi, labels = read_data(args.infdata)
        predictions = model.predict(Xi).flatten()
        binary_predictions = np.zeros_like(predictions)
        binary_predictions[np.where(predictions > 0.5)[0]] = 1
        idx_tp = np.where((labels == 1) & (binary_predictions == 1))[0]  # true positives
        idx_tn = np.where((labels == 0) & (binary_predictions == 0))[0]  # true negatives
        idx_fp = np.where((labels == 0) & (binary_predictions == 1))[0]  # false positives
        idx_fn = np.where((labels == 1) & (binary_predictions == 0))[0]  # false negatives
        acc = float(len(idx_tp) + len(idx_tn)) / len(labels) * 100
        tpr = float(len(idx_tp)) / (len(idx_tp) + len(idx_fn)) * 100
        fpr = float(len(idx_fp)) / (len(idx_tn) + len(idx_fp)) * 100
        print(f'Accuracy = {acc}%\nTrue positive rate = {tpr}%\nFalse positive rate = {fpr}%')