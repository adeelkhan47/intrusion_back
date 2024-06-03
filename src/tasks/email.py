import logging
import math
from datetime import datetime, timedelta
from datetime import timezone

import numpy as np # linear algebra
import tensorflow
import pandas as pd # data processing, CSV file I/O (e.g. pd.read_csv)
import joblib
import keras
import time
from model.packet import Packet
from tasks.celery import DbTask, celery_app
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__file__)

mapping = {
    'dst_port': ' Destination Port',
    'flow_duration': ' Flow Duration',
    'flow_byts_s': 'Flow Bytes/s',
    'flow_pkts_s': ' Flow Packets/s',
    'fwd_pkts_s': 'Fwd Packets/s',
    'bwd_pkts_s': ' Bwd Packets/s',
    'tot_fwd_pkts': ' Total Fwd Packets',
    'tot_bwd_pkts': ' Total Backward Packets',
    'totlen_fwd_pkts': 'Total Length of Fwd Packets',
    'totlen_bwd_pkts': ' Total Length of Bwd Packets',
    'fwd_pkt_len_max': ' Fwd Packet Length Max',
    'fwd_pkt_len_min': ' Fwd Packet Length Min',
    'fwd_pkt_len_mean': ' Fwd Packet Length Mean',
    'fwd_pkt_len_std': ' Fwd Packet Length Std',
    'bwd_pkt_len_max': 'Bwd Packet Length Max',
    'bwd_pkt_len_min': ' Bwd Packet Length Min',
    'bwd_pkt_len_mean': ' Bwd Packet Length Mean',
    'bwd_pkt_len_std': ' Bwd Packet Length Std',
    'pkt_len_max': ' Max Packet Length',
    'pkt_len_min': ' Min Packet Length',
    'pkt_len_mean': ' Packet Length Mean',
    'pkt_len_std': ' Packet Length Std',
    'pkt_len_var': ' Packet Length Variance',
    'fwd_header_len': ' Fwd Header Length',
    'bwd_header_len': ' Bwd Header Length',
    'fwd_seg_size_min': ' min_seg_size_forward',
    'fwd_act_data_pkts': ' act_data_pkt_fwd',
    'flow_iat_mean': ' Flow IAT Mean',
    'flow_iat_max': ' Flow IAT Max',
    'flow_iat_min': ' Flow IAT Min',
    'flow_iat_std': ' Flow IAT Std',
    'fwd_iat_tot': 'Fwd IAT Total',
    'fwd_iat_max': ' Fwd IAT Max',
    'fwd_iat_min': ' Fwd IAT Min',
    'fwd_iat_mean': ' Fwd IAT Mean',
    'fwd_iat_std': ' Fwd IAT Std',
    'bwd_iat_tot': 'Bwd IAT Total',
    'bwd_iat_max': ' Bwd IAT Max',
    'bwd_iat_min': ' Bwd IAT Min',
    'bwd_iat_mean': ' Bwd IAT Mean',
    'bwd_iat_std': ' Bwd IAT Std',
    'fwd_psh_flags': 'Fwd PSH Flags',
    'bwd_psh_flags': ' Bwd PSH Flags',
    'fwd_urg_flags': ' Fwd URG Flags',
    'bwd_urg_flags': ' Bwd URG Flags',
    'fin_flag_cnt': 'FIN Flag Count',
    'syn_flag_cnt': ' SYN Flag Count',
    'rst_flag_cnt': ' RST Flag Count',
    'psh_flag_cnt': ' PSH Flag Count',
    'ack_flag_cnt': ' ACK Flag Count',
    'urg_flag_cnt': ' URG Flag Count',
    'ece_flag_cnt': ' ECE Flag Count',
    'down_up_ratio': ' Down/Up Ratio',
    'pkt_size_avg': ' Average Packet Size',
    'init_fwd_win_byts': 'Init_Win_bytes_forward',
    'init_bwd_win_byts': ' Init_Win_bytes_backward',
    'active_max': ' Active Max',
    'active_min': ' Active Min',
    'active_mean': 'Active Mean',
    'active_std': ' Active Std',
    'idle_max': ' Idle Max',
    'idle_min': ' Idle Min',
    'idle_mean': 'Idle Mean',
    'idle_std': ' Idle Std',
    'fwd_byts_b_avg': 'Fwd Avg Bytes/Bulk',
    'fwd_pkts_b_avg': ' Fwd Avg Packets/Bulk',
    'bwd_byts_b_avg': ' Bwd Avg Bytes/Bulk',
    'bwd_pkts_b_avg': ' Bwd Avg Packets/Bulk',
    'fwd_blk_rate_avg': ' Fwd Avg Bulk Rate',
    'bwd_blk_rate_avg': 'Bwd Avg Bulk Rate',
    'fwd_seg_size_avg': ' Avg Fwd Segment Size',
    'bwd_seg_size_avg': ' Avg Bwd Segment Size',
    'cwe_flag_count': ' CWE Flag Count',
    'subflow_fwd_pkts': 'Subflow Fwd Packets',
    'subflow_bwd_pkts': ' Subflow Bwd Packets',
    'subflow_fwd_byts': ' Subflow Fwd Bytes',
    'subflow_bwd_byts': ' Subflow Bwd Bytes'
}
remove_columns = ['src_ip', 'dst_ip', 'src_port', 'src_mac', 'dst_mac', 'protocol', 'timestamp']

def load_objects():
    scaler_filename = "tasks/scaler.save"
    scaler = joblib.load(scaler_filename)

    cnn_name = "cnn_trained.keras"
    cnn = keras.saving.load_model("tasks/cnn_trained.keras")

    pca_name = "tasks/pca.joblib"
    pca = joblib.load(pca_name)

    onehotencoder_name = "tasks/label_encoder.joblib"
    onehotencoder = joblib.load(onehotencoder_name)

    return onehotencoder, scaler, cnn, pca
onehotencoder, scaler, cnn, pca = load_objects()
# cnn.summary()


## packet



@celery_app.task(bind=True, base=DbTask)
def process_packets(self, *args, **kwargs):
    import os
    import subprocess
    import time
    # Define the command with sudo
    command = "echo 'Khanadeel47' | sudo -S cicflowmeter -i en0 --csv flows.csv"

    # Run the command as a subprocess with sudo
    process = subprocess.Popen(command, shell=True)

    # Wait for 60 seconds
    time.sleep(25)

    # Terminate the process after 60 seconds
    process.terminate()

@celery_app.task(bind=True, base=DbTask)
def load_packets(self, *args, **kwargs):
    session = self.session
    try:
        df = pd.read_csv("flows.csv")
        df.rename(columns=mapping, inplace=True)
        df.drop(remove_columns, axis=1, inplace=True)
        df[' Fwd Header Length.1'] = df[' Fwd Header Length']
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)

        # #Remove the following two rows when dealing your own data
        # y_labels = onehotencoder.transform(df[' Label'].values.reshape(-1,1)).toarray()
        # df.drop([' Label'],axis=1,inplace=True)

        features = scaler.get_feature_names_out()
        df = df[features]
        scaled = scaler.transform(df)
        test_X = pca.transform(scaled)  # Dimensionality Reduction using PCA

        # Reshaping data for CNN input
        test_X = test_X.reshape(test_X.shape[0], pca.n_components, 1)
        predictions = cnn.predict(test_X)

        final_predictions = []
        intrusion_predictions = []
        non_intrusion_predictions = []
        accuracies = []

        i = 0
        print(len(predictions))
        for prediction in predictions:
            prediction_accuracy = max(x for x in prediction)
            if prediction_accuracy > 0.5:
                intrusion_predictions.append(prediction)
            else:
                # if none of the classes have 0.5 threshold
                # store the index of these predictions
                # later we add them back
                non_intrusion_predictions.append(i)
            accuracies.append(prediction_accuracy)
            i += 1

        # Get the labels of predictions which are intrusions
        final_predictions = onehotencoder.inverse_transform(intrusion_predictions)

        # Add a 'Non-Intrusion label for the rows which did nto have 0.5 threshold.
        for index in non_intrusion_predictions:
            final_predictions = np.insert(final_predictions, index, "Non Intrusion")

        for i, each in enumerate(final_predictions):
            packet = Packet(label=each[0])
            session.add(packet)
            session.commit()

    except Exception as e:
        print(e.__str__())

# logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__file__)

@celery_app.task(bind=True, base=DbTask)
def delete_packets(self, *args, **kwargs):
    session = self.session
    current_time = datetime.now()

    # Subtract 5 min from the current time
    five_min_ago = current_time - timedelta(hours=2)

    # Query to get emails older than 5 min directly
    emails_to_delete = session.query(Packet).filter(Packet.created_at < five_min_ago).all()

    # Deleting the fetched emails
    for email in emails_to_delete:
        session.delete(email)
    session.commit()
