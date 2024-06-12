from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

import switch
from datetime import datetime

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, accuracy_score
import joblib

class SimpleMonitor13(switch.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.flow_model = self.load_model()

    def load_model(self):
        try:
            # Load the trained model
            return joblib.load('flow_model.pkl')
        except Exception as e:
            print("Error loading model:", e)
            return None

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)
            self.flow_predict()

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        timestamp = datetime.now().timestamp()
        body = ev.msg.body
        icmp_code = -1
        icmp_type = -1
        tp_src = 0
        tp_dst = 0

        for stat in sorted([flow for flow in body if (flow.priority == 1)], key=lambda flow:
                (flow.match['eth_type'], flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.match['ip_proto'])):
            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            ip_proto = stat.match['ip_proto']

            if stat.match['ip_proto'] == 1:
                icmp_code = stat.match['icmpv4_code']
                icmp_type = stat.match['icmpv4_type']
            elif stat.match['ip_proto'] == 6:
                tp_src = stat.match['tcp_src']
                tp_dst = stat.match['tcp_dst']
            elif stat.match['ip_proto'] == 17:
                tp_src = stat.match['udp_src']
                tp_dst = stat.match['udp_dst']

            flow_id = str(ip_src) + str(tp_src) + str(ip_dst) + str(tp_dst) + str(ip_proto)

            try:
                packet_count_per_second = stat.packet_count / stat.duration_sec
                packet_count_per_nsecond = stat.packet_count / stat.duration_nsec
            except:
                packet_count_per_second = 0
                packet_count_per_nsecond = 0

            try:
                byte_count_per_second = stat.byte_count / stat.duration_sec
                byte_count_per_nsecond = stat.byte_count / stat.duration_nsec
            except:
                byte_count_per_second = 0
                byte_count_per_nsecond = 0

            # Write to CSV file
            with open("PredictFlowStatsfile.csv", "w") as file0:
                file0.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                            .format(timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src, ip_dst, tp_dst,
                                    stat.match['ip_proto'], icmp_code, icmp_type,
                                    stat.duration_sec, stat.duration_nsec,
                                    stat.idle_timeout, stat.hard_timeout,
                                    stat.flags, stat.packet_count, stat.byte_count,
                                    packet_count_per_second, packet_count_per_nsecond,
                                    byte_count_per_second, byte_count_per_nsecond))

    # def flow_predict(self):
    #     if self.flow_model:
    #         try:
    #             predict_flow_dataset = pd.read_csv('PredictFlowStatsfile.csv')
    #             predict_flow_dataset.iloc[:, 2] = predict_flow_dataset.iloc[:, 2].str.replace('.', '')
    #             predict_flow_dataset.iloc[:, 3] = predict_flow_dataset.iloc[:, 3].str.replace('.', '')
    #             predict_flow_dataset.iloc[:, 5] = predict_flow_dataset.iloc[:, 5].str.replace('.', '')

    #             X_predict_flow = predict_flow_dataset.iloc[:, :].values
    #             X_predict_flow = X_predict_flow.astype('float64')

    #             y_flow_pred = self.flow_model.predict(X_predict_flow)

    #             legitimate_traffic = sum(1 for i in y_flow_pred if i == 0)
    #             ddos_traffic = len(y_flow_pred) - legitimate_traffic
    #             victim = None

    #             if ddos_traffic > 0:
    #                 victim = int(predict_flow_dataset.iloc[y_flow_pred.argmax(), 5]) % 20

    #             self.logger.info("------------------------------------------------------------------------------")
    #             if (legitimate_traffic / len(y_flow_pred) * 100) > 80:
    #                 self.logger.info("legitimate traffic ...")
    #             else:
    #                 self.logger.info("ddos traffic ...")
    #                 self.logger.info("victim is host: h{}".format(victim))

    #             self.logger.info("------------------------------------------------------------------------------")

    #             # Clear the content of the file after prediction
    #             open("PredictFlowStatsfile.csv", "w").close()

    #         except Exception as e:
    #             self.logger.error("Error during prediction: %s", e)
    #     else:
    #         self.logger.error("Model is not loaded, prediction cannot be performed")

    # def flow_training(self):
    #     self.logger.info("Flow Training ...")

    #     flow_dataset = pd.read_csv('FlowStatsfile.csv')

    #     flow_dataset.iloc[:, 2] = flow_dataset.iloc[:, 2].str.replace('.', '')
    #     flow_dataset.iloc[:, 3] = flow_dataset.iloc[:, 3].str.replace('.', '')
    #     flow_dataset.iloc[:, 5] = flow_dataset.iloc[:, 5].str.replace('.', '')

    #     X_flow = flow_dataset.iloc[:, :-1].values
    #     X_flow = X_flow.astype('float64')

    #     y_flow = flow_dataset.iloc[:, -1].values

    #     X_flow_train, X_flow_test, y_flow_train, y_flow_test = train_test_split(X_flow, y_flow, test_size=0.25,
    #                                                                             random_state=0)

    #     classifier = RandomForestClassifier(n_estimators=10, criterion="entropy", random_state=0)
    #     self.flow_model = classifier.fit(X_flow_train, y_flow_train)

    #     y_flow_pred = self.flow_model.predict(X_flow_test)

    #     self.logger.info("------------------------------------------------------------------------------")
    #     self.logger.info("confusion matrix")
    #     cm = confusion_matrix(y_flow_test, y_flow_pred)
    #     self.logger.info(cm)

    #     acc = accuracy_score(y_flow_test, y_flow_pred)

    #     self.logger.info("success accuracy = {0:.2f} %".format(acc * 100))
    #     fail = 1.0 - acc
    #     self.logger.info("fail accuracy = {0:.2f} %".format(fail * 100))
    #     self.logger.info("------------------------------------------------------------------------------")

    # def flow_predict(self):
    #     if self.flow_model:
    #         try:
    #             predict_flow_dataset = pd.read_csv('PredictFlowStatsfile.csv')
    #             if not predict_flow_dataset.empty:
    #                 predict_flow_dataset.iloc[:, 2] = predict_flow_dataset.iloc[:, 2].str.replace('.', '')
    #                 predict_flow_dataset.iloc[:, 3] = predict_flow_dataset.iloc[:, 3].str.replace('.', '')
    #                 predict_flow_dataset.iloc[:, 5] = predict_flow_dataset.iloc[:, 5].str.replace('.', '')

    #                 X_predict_flow = predict_flow_dataset.iloc[:, :].values
    #                 X_predict_flow = X_predict_flow.astype('float64')

    #                 y_flow_pred = self.flow_model.predict(X_predict_flow)

    #                 legitimate_traffic = sum(1 for i in y_flow_pred if i == 0)
    #                 ddos_traffic = len(y_flow_pred) - legitimate_traffic
    #                 victim = None

    #                 if ddos_traffic > 0:
    #                     victim = int(predict_flow_dataset.iloc[y_flow_pred.argmax(), 5]) % 20

    #                 self.logger.info("------------------------------------------------------------------------------")
    #                 if (legitimate_traffic / len(y_flow_pred) * 100) > 80:
    #                     self.logger.info("legitimate traffic ...")
    #                 else:
    #                     self.logger.info("ddos traffic ...")
    #                     self.logger.info("victim is host: h{}".format(victim))

    #                 self.logger.info("------------------------------------------------------------------------------")

    #                 # Clear the content of the file after prediction
    #                 open("PredictFlowStatsfile.csv", "w").close()
    #             else:
    #                 self.logger.info("Prediction dataset is empty. No predictions made.")
    #         except Exception as e:
    #             self.logger.error("Error during prediction: %s", e)
    #     else:
    #         self.logger.error("Model is not loaded, prediction cannot be performed")

    def flow_predict(self):
        if self.flow_model:
            try:
                # Read the CSV file
                predict_flow_dataset = pd.read_csv('PredictFlowStatsfile.csv')

                # Check if the dataset is not empty
                if not predict_flow_dataset.empty:
                    # Preprocess the data if necessary
                    predict_flow_dataset.iloc[:, 2] = predict_flow_dataset.iloc[:, 2].str.replace('.', '')
                    predict_flow_dataset.iloc[:, 3] = predict_flow_dataset.iloc[:, 3].str.replace('.', '')
                    predict_flow_dataset.iloc[:, 5] = predict_flow_dataset.iloc[:, 5].str.replace('.', '')

                    # Convert data to numpy array
                    X_predict_flow = predict_flow_dataset.iloc[:, :].values
                    X_predict_flow = X_predict_flow.astype('float64')

                    # Make predictions using the loaded model
                    y_flow_pred = self.flow_model.predict(X_predict_flow)

                    # Process the predictions
                    legitimate_traffic = sum(1 for i in y_flow_pred if i == 0)
                    ddos_traffic = len(y_flow_pred) - legitimate_traffic
                    victim = None

                    if ddos_traffic > 0:
                        victim = int(predict_flow_dataset.iloc[y_flow_pred.argmax(), 5]) % 20

                    # Log the predictions
                    self.logger.info("------------------------------------------------------------------------------")
                    if (legitimate_traffic / len(y_flow_pred) * 100) > 80:
                        self.logger.info("Legitimate traffic ...")
                    else:
                        self.logger.info("DDoS traffic ...")
                        self.logger.info("Victim is host: h{}".format(victim))
                    self.logger.info("------------------------------------------------------------------------------")

                    # Clear the content of the file after prediction
                    open("PredictFlowStatsfile.csv", "w").close()
                else:
                    self.logger.info("Prediction dataset is empty. No predictions made.")
            except Exception as e:
                # Log any errors that occur during prediction
                self.logger.error("Error during prediction: %s", e)
        else:
            # Log an error if the model is not loaded
            self.logger.error("Model is not loaded, prediction cannot be performed")



if __name__ == "__main__":
    monitor = SimpleMonitor13()
    monitor.flow_training()
