import pyshark
import collections
import matplotlib.pyplot as plt
import numpy as np


def Protocol_graph(Analyses):
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

def Info_DNS(Analyses):
    for Analyse in Analyses:
        cap = pyshark.FileCapture(Analyse, only_summaries=True)
        cap2 = pyshark.FileCapture(Analyse, only_summaries=False)
        cap.load_packets()
        cap2.load_packets()
        
        print(Analyse)
        print("\n")
        for i in range(len(cap)):
            line = str(cap[i])
            lineSep = line.split(" ")
            protocol = lineSep[4]
            if (protocol == "DNS"):
                print(cap[i])                 #change cap2 to cap if want to have summaries info
                print("\n ............................... \n")

def Get_Destination_List(Analyse):
    for Analyse in Analyses:
        cap = pyshark.FileCapture(Analyse, only_summaries=True)
        cap.load_packets()

        destList = []
        print("\n")
        print(Analyse)
        print("\n")

        for packet in cap:
            line = str(packet)
            lineSep = line.split(" ")
            if lineSep[3] not in destList:
                destList.append(lineSep[3])

        for i in destList:
            print(i)


Analyses = [ "Open_app.pcap","Send_messages.pcap", "No_pick_up.pcap", "Call_pick_up.pcap"]


#Get_Destination_List(Analyses)
#Protocol_graph(Analyses)
#Info_DNS(Analyses)
