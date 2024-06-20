from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet
import switch
import logging
import os
from datetime import datetime

FLOW_STATS_FILE = "PredictFlowStatsfile.csv"
MODEL_PATH = 'flow_model.pkl'

class SimpleMonitor13(switch.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.logger = logging.getLogger('SimpleMonitor13')
        self.flow_stats_file = FLOW_STATS_FILE
        self.model_path = MODEL_PATH
        self.traffic_data = {}

        self.monitor_thread = hub.spawn(self._monitor)

    def _monitor(self):
        while True:
            for dp in self.datapath:
                self._request_stats(dp)
            hub.sleep(2)
            self.predict_and_log(self.flow_stats_file)
            self.realtime_traffic_monitor()  # Implement your real-time monitoring logic here

    def realtime_traffic_monitor(self):
        # Implement real-time traffic monitoring logic here
        pass

    def _request_stats(self, datapath):
        self.logger.debug('Send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        if ev.state == MAIN_DISPATCHER:
            self.datapath = ev.datapath
        elif ev.state == DEAD_DISPATCHER:
            self.datapath = None

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        timestamp = datetime.now().timestamp()
        body = ev.msg.body
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['eth_type'], flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.match['ip_proto'])):
            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            self.traffic_data[(ip_src, ip_dst)] = self.traffic_data.get((ip_src, ip_dst), 0) + 1
            self.write_flow_stat(stat, ev.msg.datapath.id, timestamp)

    def write_flow_stat(self, stat, datapath_id, timestamp):
        with open(self.flow_stats_file, "a") as file:
            file.write(f"{timestamp},{datapath_id},{stat.match['ipv4_src']},{stat.match['tcp_src']},{stat.match['ipv4_dst']},"
                       f"{stat.match['tcp_dst']},{stat.match['ip_proto']},{stat.packet_count},{stat.byte_count}\n")

    def predict_and_log(self, file_path):
        try:
            with open(file_path, "r") as file:
                data = file.read()
                # Implement your prediction logic here
                self.logger.info("Predictions logged.")
        except FileNotFoundError:
            self.logger.error(f"File {file_path} not found.")

    def display_traffic(self):
        hub.sleep(2)
        os.system('cls' if os.name == 'nt' else 'clear')
        self.logger.info("Current Traffic Flow:")
        for (ip_src, ip_dst), count in self.traffic_data.items():
            self.logger.info(f"{ip_src} -> {ip_dst}: {count} packets")
        self.traffic_data.clear()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    SimpleMonitor13()
