from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

import switch
from datetime import datetime
import pandas as pd
import pickle
import logging

class SimpleMonitor13(switch.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.display_thread = hub.spawn(self._display_traffic)
        self.flow_model = self._load_model('flow_model.pkl')
        self.logger = logging.getLogger('SimpleMonitor13')
        self.flow_stats_file = "PredictFlowStatsfile.csv"
        self._init_flow_stats_file()
        self.traffic_data = {}  # To store traffic data for display


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
            hub.sleep(1)
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

            y_flow_pred = self.flow_model.predict(X_predict_flow)
            legitimate_traffic, ddos_traffic, victim = self._analyze_predictions(y_flow_pred, predict_flow_dataset)
            self._log_prediction_results(legitimate_traffic, ddos_traffic, victim, len(y_flow_pred))
            self._init_flow_stats_file()

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
