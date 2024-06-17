from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp
import logging
from datetime import datetime
import pandas as pd
import pickle
import os
import switch

FLOW_STATS_FILE = "PredictFlowStatsfile.csv"
TRAFFIC_DATA_FILE = "traffic_data.txt"
MODEL_PATH = 'flow_model.pkl'

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
        self.interval = 2  # Interval for displaying traffic info
        self.packet_interval = 1  # Interval for capturing packets

    def monitor_traffic(self, msg):
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        src = eth.src
        dst = eth.dst
        self.logger.info(f"Real-time traffic: {src} -> {dst}")

    def log_traffic(self, ip_src, ip_dst):
        self.traffic_data[(ip_src, ip_dst)] = self.traffic_data.get((ip_src, ip_dst), 0) + 1

    def display_traffic(self):
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
            self.logger.info("Legitimate traffic...")
        else:
            self.logger.info("DDoS traffic detected...")
            self.logger.info(f"Victim is host: h{victim}")
        self.logger.info("------------------------------------------------------------------------------")

class SimpleMonitor13(switch.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.logger = logging.getLogger('SimpleMonitor13')

        self.datapath_manager = DataPathManager()
        self.traffic_monitor = TrafficMonitor(self.logger)
        self.model_loader = ModelLoader(MODEL_PATH, self.logger)
        self.flow_stats_manager = FlowStatsManager(FLOW_STATS_FILE)
        self.traffic_prediction = TrafficPrediction(self.model_loader, self.logger)

        self.monitor_thread = hub.spawn(self._monitor)
        self.stats_print_thread = hub.spawn(self._print_stats)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapath_manager.register_datapath(datapath)
        elif ev.state == DEAD_DISPATCHER:
            self.datapath_manager.unregister_datapath(datapath)

    def _monitor(self):
        while True:
            for dp in self.datapath_manager.get_datapaths():
                self._request_stats(dp)
            hub.sleep(2)
            self.traffic_prediction.predict_and_log(FLOW_STATS_FILE)
            self.traffic_monitor.display_traffic()

    def _request_stats(self, datapath):
        self.logger.debug('Send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        timestamp = datetime.now().timestamp()
        body = ev.msg.body
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['eth_type'], flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.match['ip_proto'])):
            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            self.traffic_monitor.log_traffic(ip_src, ip_dst)
            self.flow_stats_manager.write_flow_stat(stat, ev.msg.datapath.id, timestamp)

    def _print_stats(self):
        while True:
            hub.sleep(2)
            self._calculate_entropy()
            self._print_entropy_stats()

    def _calculate_entropy(self):
        # Implement entropy calculation here
        pass

    def _print_entropy_stats(self):
        self.logger.info("Printing entropy statistics...")

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    SimpleMonitor13()
