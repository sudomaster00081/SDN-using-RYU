from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet

import switch
from datetime import datetime
import pandas as pd
import pickle
import logging
import os
import subprocess
import csv
from collections import Counter
import math




FLOW_STATS_FILE = "PredictFlowStatsfile.csv"
TRAFFIC_DATA_FILE = "traffic_data.txt"
MODEL_PATH = 'flow_model.pkl'

##################SOM######################

import numpy as np
import pickle
import pandas as pd

# Load your SOM model and define other necessary variables
with open('som.p', 'rb') as infile:
    som = pickle.load(infile)

# Calculate the reference point G
g = np.median(som.get_weights(), axis=(0, 1))

# Function to calculate distance between input sample V and reference point G
def calculate_distance(v, g):
    return np.linalg.norm(v - g)

# Function to classify input sample as attack or normal and return the prediction
def predict_ddos(input_sample, d_threshold, sigma):
    distance_to_g = calculate_distance(input_sample, g)
    p_d_greater_than_x = 1 - np.exp(- (distance_to_g / sigma)**2)  # Cumulative distribution function
    is_attack = distance_to_g > d_threshold or p_d_greater_than_x > 0.6  # You can adjust the threshold as needed
    return 1 if is_attack else 0

# Function to encapsulate prediction process
def make_prediction(input_value):
    preprocessed_input = preprocess_input(input_value)
    d_threshold = 0.1  # Predefined distance threshold
    sigma = 0.2  # Probability threshold
    prediction = predict_ddos(preprocessed_input, d_threshold, sigma)
    return prediction

def normalize_with_tanh_estimator_single(data_row, mean_std_dict):
    normalized_row = []
    # print("data_row", data_row )
    for i, val in enumerate(data_row):
        mu, sigma = mean_std_dict[i]
        normalized_val = 0.5 * (np.tanh(0.1 * ((val - mu) / sigma)) + 1)
        normalized_row.append(normalized_val)
# Keep excluded columns as they are
    return normalized_row

def preprocess_input(input_value):
    # Implement any necessary preprocessing steps here
    mean_std_dict = [(8.263881658687838, 4.671149926162893), (0.9246188369475715, 0.5443941383426818), (0.7003273029028211, 0.7272171514281917), (0.3280379809243417, 0.18777105312169787), (455704.77437325905, 391359.48898741446)]
    normalized = normalize_with_tanh_estimator_single(input_value, mean_std_dict)
    return normalized








class DataPathManager:
    def __init__(self):
        self.datapaths = {}

    def register_datapath(self, datapath):
        self.datapaths[datapath.id] = datapath

    def unregister_datapath(self, datapath):
        del self.datapaths[datapath.id]

    def get_datapaths(self):
        return self.datapaths.values()


class TrafficMonitor:
    def __init__(self, logger):
        self.logger = logger
        self.traffic_data = {}

    def monitor_traffic(self, msg):
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        src = eth.src
        dst = eth.dst
        self.logger.info(f"Real-time traffic: {src} -> {dst}")

    def log_traffic(self, ip_src, ip_dst):
        self.traffic_data[(ip_src, ip_dst)] = self.traffic_data.get((ip_src, ip_dst), 0) + 1

    def display_traffic(self):
        hub.sleep(2)
        self._clear_screen()
        print("Current Traffic Flow:")
        for (ip_src, ip_dst), count in self.traffic_data.items():
            print(f"{ip_src} -> {ip_dst}: {count} packets")
        self.traffic_data.clear()

    def _clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')


class ModelLoader:
    def __init__(self, model_path, logger):
        self.logger = logger
        self.model = self._load_model(model_path)

    def _load_model(self, model_path):
        try:
            return pickle.load(open(model_path, 'rb'))
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            return None

    def predict(self, data):
        if self.model:
            return self.model.predict(data)
        return []


class FlowStatsManager:
    def __init__(self, file_path):
        self.file_path = file_path
        self._init_flow_stats_file()

    def _init_flow_stats_file(self):
        with open(self.file_path, "w") as file:
            file.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,'
                       'flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,'
                       'packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')

    def write_flow_stat(self, stat, datapath_id, timestamp):
        ip_src, ip_dst, ip_proto = stat.match['ipv4_src'], stat.match['ipv4_dst'], stat.match['ip_proto']
        icmp_code, icmp_type, tp_src, tp_dst = -1, -1, 0, 0

        if ip_proto == 1:
            icmp_code = stat.match['icmpv4_code']
            icmp_type = stat.match['icmpv4_type']
        elif ip_proto == 6:
            tp_src = stat.match['tcp_src']
            tp_dst = stat.match['tcp_dst']
        elif ip_proto == 17:
            tp_src = stat.match['udp_src']
            tp_dst = stat.match['udp_dst']

        flow_id = f"{ip_src}{tp_src}{ip_dst}{tp_dst}{ip_proto}"
        packet_count_per_second = self._calculate_rate(stat.packet_count, stat.duration_sec)
        packet_count_per_nsecond = self._calculate_rate(stat.packet_count, stat.duration_nsec)
        byte_count_per_second = self._calculate_rate(stat.byte_count, stat.duration_sec)
        byte_count_per_nsecond = self._calculate_rate(stat.byte_count, stat.duration_nsec)

        with open(self.file_path, "a") as file:
            file.write(f"{timestamp},{datapath_id},{flow_id},{ip_src},{tp_src},{ip_dst},{tp_dst},{ip_proto},{icmp_code},{icmp_type},"
                       f"{stat.duration_sec},{stat.duration_nsec},{stat.idle_timeout},{stat.hard_timeout},{stat.flags},"
                       f"{stat.packet_count},{stat.byte_count},{packet_count_per_second},{packet_count_per_nsecond},"
                       f"{byte_count_per_second},{byte_count_per_nsecond}\n")

    def _calculate_rate(self, count, duration):
        try:
            return count / duration
        except ZeroDivisionError:
            return 0


class TrafficPrediction:
    def __init__(self, model_loader, logger):
        self.model_loader = model_loader
        self.logger = logger

    def predict_and_log(self, file_path):
        try:
            dataset = pd.read_csv(file_path)
            dataset = self._sanitize_dataset(dataset)
            X_predict_flow = dataset.values.astype('float64')
            y_flow_pred = self.model_loader.predict(X_predict_flow)
            legitimate_traffic, ddos_traffic, victim = self._analyze_predictions(y_flow_pred, dataset)
            self._log_prediction_results(legitimate_traffic, ddos_traffic, victim, len(y_flow_pred))
        except Exception as e:
            self.logger.error(f"Error in flow prediction: {e}")

    def _sanitize_dataset(self, dataset):
        dataset.iloc[:, 2] = dataset.iloc[:, 2].str.replace('.', '')
        dataset.iloc[:, 3] = dataset.iloc[:, 3].str.replace('.', '')
        dataset.iloc[:, 5] = dataset.iloc[:, 5].str.replace('.', '')
        return dataset

    def _analyze_predictions(self, predictions, dataset):
        legitimate_traffic = 0
        ddos_traffic = 0
        victim = None

        for i, prediction in enumerate(predictions):
            if prediction == 0:
                legitimate_traffic += 1
            else:
                ddos_traffic += 1
                victim = int(dataset.iloc[i, 5]) % 20

        return legitimate_traffic, ddos_traffic, victim

    def _log_prediction_results(self, legitimate_traffic, ddos_traffic, victim, total_traffic):
        date_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.logger.info(f"------------------------------------------------------------------------------")
        self.logger.info(f"{date_time_str}")
        if (legitimate_traffic / total_traffic * 100) > 80:
            self.logger.info("Good traffic...")
            self.logger.info("------------------------------------------------------------------------------")

            
        else:
            self.logger.info("DDoS traffic ...")
            # self.logger.info(f"Victim is host: h{victim}")
            self.logger.info(f"*************************************************************************")


class SimpleMonitor13(switch.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.flow_model = self._load_model('flow_model.pkl')
        self.logger = logging.getLogger('SimpleMonitor13')
        self.flow_stats_file = "PredictFlowStatsfile.csv"
        self.traffic_data_file = "traffic_data.txt"
        self._init_flow_stats_file()
        self.traffic_data = {}
        self.som_data_file = 'som_data.csv'
        # self._start_display_process()
        
    def calculate_entropy(self, data_list):
        count = Counter(data_list)
        probabilities = [count[key] / len(data_list) for key in count.keys()]
        entropy = -sum([p * math.log2(p) for p in probabilities])
        return entropy

    def calculate_and_print_statistics(self, dataset):
        try:
            dataset = dataset
            
            src_ip_entropy = self.calculate_entropy(dataset['ip_src'])
            src_port_entropy = self.calculate_entropy(dataset['tp_src'])
            dst_port_entropy = self.calculate_entropy(dataset['tp_dst'])
            protocol_entropy = self.calculate_entropy(dataset['ip_proto'])
            total_packets = dataset['packet_count'].sum()
            
            # print(f"Entropy of source IP address (etpSrcIP): {src_ip_entropy}")
            # print(f"Entropy of source port (etpSrcP): {src_port_entropy}")
            # print(f"Entropy of destination port (etpDstP): {dst_port_entropy}")
            # print(f"Entropy of packet protocol (etpProtocol): {protocol_entropy}")
            # print(f"Total number of packets (totalPacket): {total_packets}")
            return (src_ip_entropy, src_port_entropy, dst_port_entropy, protocol_entropy, total_packets)
        except Exception as e:
            self.logger.error(f"Error calculating statistics: {e}")

    def _start_display_process(self):
        import subprocess
        subprocess.Popen(["python3", "traffic_display.py"])

    def _display_traffic(self):
        while True:
            hub.sleep(2)
            self._clear_screen()
            print("Current Traffic Flow:")
            for (ip_src, ip_dst), count in self.traffic_data.items():
                print(f"{ip_src} -> {ip_dst}: {count} packets")
            self.traffic_data.clear()  # Clear data after displaying

    def _clear_screen(self):
        import os
        os.system('cls' if os.name == 'nt' else 'clear')


    def _realtime_traffic_monitor(self, msg):
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        src = eth.src
        dst = eth.dst
        self.logger.info(f"Real-time traffic: {src} -> {dst}")

    
    def _load_model(self, model_path):
        try:
            return pickle.load(open(model_path, 'rb'))
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            return None

    def _init_flow_stats_file(self):
        with open(self.flow_stats_file, "w") as file:
            file.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,'
                       'flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,'
                       'packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('Register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('Unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(2)
            self.flow_predict()
            # Add invocation of real-time traffic monitor here
            # self._realtime_traffic_monitor()

    def _request_stats(self, datapath):
        self.logger.debug('Send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        timestamp = datetime.now().timestamp()
        body = ev.msg.body
        with open(self.flow_stats_file, "a") as file:
            for stat in sorted([flow for flow in body if flow.priority == 1], 
                               key=lambda flow: (flow.match['eth_type'], flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.match['ip_proto'])):
                ip_src = stat.match['ipv4_src']
                ip_dst = stat.match['ipv4_dst']
                self.traffic_data[(ip_src, ip_dst)] = self.traffic_data.get((ip_src, ip_dst), 0) + 1
                self._write_flow_stat(file, stat, ev.msg.datapath.id, timestamp)
        self._write_traffic_data()

    
    def _write_traffic_data(self):
        with open(self.traffic_data_file, "w") as file:
            for (ip_src, ip_dst), count in self.traffic_data.items():
                file.write(f"{ip_src} -> {ip_dst}: {count} packets\n")
        self.traffic_data.clear()

    def _write_flow_stat(self, file, stat, datapath_id, timestamp):
        ip_src, ip_dst, ip_proto = stat.match['ipv4_src'], stat.match['ipv4_dst'], stat.match['ip_proto']
        icmp_code, icmp_type, tp_src, tp_dst = -1, -1, 0, 0

        if ip_proto == 1:
            icmp_code = stat.match['icmpv4_code']
            icmp_type = stat.match['icmpv4_type']
        elif ip_proto == 6:
            tp_src = stat.match['tcp_src']
            tp_dst = stat.match['tcp_dst']
        elif ip_proto == 17:
            tp_src = stat.match['udp_src']
            tp_dst = stat.match['udp_dst']

        flow_id = f"{ip_src}{tp_src}{ip_dst}{tp_dst}{ip_proto}"
        packet_count_per_second = self._calculate_rate(stat.packet_count, stat.duration_sec)
        packet_count_per_nsecond = self._calculate_rate(stat.packet_count, stat.duration_nsec)
        byte_count_per_second = self._calculate_rate(stat.byte_count, stat.duration_sec)
        byte_count_per_nsecond = self._calculate_rate(stat.byte_count, stat.duration_nsec)

        file.write(f"{timestamp},{datapath_id},{flow_id},{ip_src},{tp_src},{ip_dst},{tp_dst},{ip_proto},{icmp_code},{icmp_type},"
                   f"{stat.duration_sec},{stat.duration_nsec},{stat.idle_timeout},{stat.hard_timeout},{stat.flags},"
                   f"{stat.packet_count},{stat.byte_count},{packet_count_per_second},{packet_count_per_nsecond},"
                   f"{byte_count_per_second},{byte_count_per_nsecond}\n")

    def _calculate_rate(self, count, duration):
        try:
            return count / duration
        except ZeroDivisionError:
            return 0

    def flow_predict(self):
        try:
            predict_flow_dataset = pd.read_csv(self.flow_stats_file)
            predict_flow_dataset = self._sanitize_dataset(predict_flow_dataset)
            X_predict_flow = predict_flow_dataset.values.astype('float64')
            # Call the new method to calculate and print statistics
            
            y_flow_pred = self.flow_model.predict(X_predict_flow)
            legitimate_traffic, ddos_traffic, victim = self._analyze_predictions(y_flow_pred, predict_flow_dataset)
            label = self._log_prediction_results(legitimate_traffic, ddos_traffic, victim, len(y_flow_pred))
            self._init_flow_stats_file()
            # print(predict_flow_dataset)
            #Entropy values
            src_ip_entropy, src_port_entropy, dst_port_entropy, protocol_entropy, total_packets = self.calculate_and_print_statistics(predict_flow_dataset)
            input_value_for_som = [src_ip_entropy, src_port_entropy, dst_port_entropy, protocol_entropy, total_packets]
            self.write_to_som_data(input_value_for_som, label)
            made_som_prediction = make_prediction(input_value_for_som)
            # if made_som_prediction == 0:
            #     print("SOM predicted as Benign")
            # else:
            #     print("SOM predicted as ATTACK!!!")
            
        except Exception as e:
            print("No Traffic detected!!!")
            # self.logger.error(f"Error in flow prediction: {e}")

    def write_to_som_data(self, input_value, label):
        input_value.append(label)
        with open(self.som_data_file, 'a') as file:
            file.write(f"\n{input_value[0]},{input_value[1]},{input_value[2]},{input_value[3]},{input_value[4]},{input_value[5]}")
            print(f"Saved as {label}")
            
    
    
    def _sanitize_dataset(self, dataset):
        dataset.iloc[:, 2] = dataset.iloc[:, 2].str.replace('.', '')
        dataset.iloc[:, 3] = dataset.iloc[:, 3].str.replace('.', '')
        dataset.iloc[:, 5] = dataset.iloc[:, 5].str.replace('.', '')
        return dataset

    def _analyze_predictions(self, predictions, dataset):
        legitimate_traffic = 0
        ddos_traffic = 0
        victim = None

        for i, prediction in enumerate(predictions):
            if prediction == 0:
                legitimate_traffic += 1
            else:
                ddos_traffic += 1
                victim = int(dataset.iloc[i, 5]) % 20

        return legitimate_traffic, ddos_traffic, victim

    # def _log_prediction_results(self, legitimate_traffic, ddos_traffic, victim, total_traffic):
    #     date_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    #     # self.logger.info(f"------------------------------------------------------------------------------")
    #     self.logger.info(f"{date_time_str}")
    #     if (legitimate_traffic / total_traffic * 100) > 80:
    #         self.logger.info("Legitimate traffic...")
    #     else:
    #         self.logger.info("DDoS traffic detected...")
    #         self.logger.info(f"Victim is host: h{victim}")
    #     # self.logger.info("------------------------------------------------------------------------------")
    
    
    def _log_prediction_results(self, legitimate_traffic, ddos_traffic, victim, total_traffic):
        date_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.logger.info(f"------------------------------------------------------------------------------")
        self.logger.info(f"{date_time_str}")
        if (legitimate_traffic / total_traffic * 100) > 80:
            self.logger.info("Good traffic...(RF)")
            self.logger.info("------------------------------------------------------------------------------")
            return 0
            
        else:
            self.logger.info("DDoS traffic ...(RF)")
            # self.logger.info(f"Victim is host: h{victim}")
            self.logger.info(f"*************************************************************************")
            return 1




if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    SimpleMonitor13()

