import pyshark
import collections
import matplotlib.pyplot as plt
import numpy as np

Analyses=["Send_message.pcap", "Open_app.pcap", "No_pick_up.pcap"]

for Analyse in Analyses:
    cap = pyshark.FileCapture( Analyse, only_summaries=True)
    cap.load_packets()
    protocolList=[]
    print(len(cap))
    for packet in cap:
        line = str(packet)
        lineSep = line.split(" ")
        protocolList.append(lineSep[4])
    print(protocolList)
