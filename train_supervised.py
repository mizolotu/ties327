import tensorflow as tf
import numpy as np
import argparse as arp

from utils import read_data, remove_bias, accuracy
from config import layers, dropout, learning_rate, batch_size, epochs, patience

if __name__ == '__main__':

    # parse args

    parser = arp.ArgumentParser(description='Train model')
    parser.add_argument('-t', '--traindata', help='Train data', nargs='+')
    parser.add_argument('-i', '--infdata', help='Inference data', nargs='+')
    args = parser.parse_args()

    # read data
    print(args.traindata)
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
        validation_split=0.3,
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

    # test if there inference data

    if args.infdata is not None:
        Xi, Yi = read_data(args.infdata)
        P = model.predict(Xi).flatten()
        acc = accuracy(P, Yi)
        print(f'Accuracy = {acc}')

