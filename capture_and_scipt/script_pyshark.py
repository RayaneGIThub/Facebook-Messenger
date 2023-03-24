import pyshark
import collections
import matplotlib.pyplot as plt
import numpy as np


def Protocol_grpah(Analyses):
    for Analyse in Analyses:
        cap = pyshark.FileCapture(Analyse, only_summaries=True)
        cap.load_packets()

        protocolList = []

        print(len(cap))

        for packet in cap:
            print(packet)
            line = str(packet)
            lineSep = line.split(" ")
            protocolList.append(lineSep[4])

        counter = collections.Counter(protocolList)
        plt.style.use('ggplot')
        ypos = np.arange(len(list(counter.keys())))
        plt.bar(ypos, list(counter.values()), align='center', alpha=0.5,
                color=['b', 'r', 'g', 'c', 'm', 'pink', 'purple', 'darkorange', 'violet'])
        plt.xticks(ypos, list(counter.keys()))
        plt.ylabel("frequency")
        plt.xlabel("protcol")
        plt.show()


def Analyse_DNS(Analyses):
    for Analyse in Analyses:
        cap = pyshark.FileCapture(Analyse, only_summaries=True)
        cap.load_packets()

        for pkt in cap:
            try:
                if pkt.dns.qry_name:
                    print('DNS Request from %s: %s' % (pkt.ip.src, pkt.dns.qry_name))
            except AttributeError as e:
                # ignore packets that aren't DNS Request
                pass
            try:
                if pkt.dns.resp_name:
                    print('DNS Response from %s: %s' % (pkt.ip.src, pkt.dns.resp_name))
            except AttributeError as e:
                # ignore packets that aren't DNS Response
                pass


Analyses = ["Send_message.pcap", "Open_app.pcap", "No_pick_up.pcap", "Call_pick_up.pcap"]

Analyse_DNS(Analyses)
