import matplotlib.pyplot as plt
import pandas as pd
from pandas.plotting import table
import json
import glob
import os


class Scatter():
    COMMON_CSV_DIRECTORY = '../pcap_csv'
    TARGET_CSV_DIRECTORY = '../pcap_csv/target'

    TARGET_IP_SETTING_FILE = "./target_ip.json"
    TARGET_IP_SETTING = "target_ip"

    def __init__(self, path, xlabel, ylabel):
        self.signature = path
        self.xlabel = xlabel
        self.ylabel = ylabel


    def day_encoder(self,date):
        date,time = map(str,date.split(' '))
        year,month,day = map(int,date.split('-'))
        hr,mit,sec = map(float,time.split(':'))
        return (day+(hr*3600+mit*60+sec)/86400)

    def ip_encoder(self,ip): # ex) ip : 192.168.0.1
        ip = ip.split(':')[1]
        ip_class = ip.split('.')
        encoded_ip = 0
        for digit in ip_class:
            encoded_ip += int(digit) * (256 ** (3 - ip_class.index(digit)))
        return encoded_ip # ex) encoded_ip : 3232235521


    def ip_decoder(self,encoded_ip): # ex) encoded_ip : 3232235521
        ip_class = []
        for i in range(4):
            ip_class.append(encoded_ip % 256)
            encoded_ip = encoded_ip // 256
        ip_class.reverse()
        ip_class = map(str,ip_class)
        decoded_ip = '.'.join(ip_class)
        return decoded_ip # decoded_ip : 192.168.0.1


    def singleFlatScatter(self):
        mapping = pd.read_csv(self.signature)
        mapping = pd.concat([mapping.loc[:,:'tcp_options'],mapping['raw']],axis = 1)
        print('plotting...')
        print()
        if 'date' in self.xlabel:
            mapping[self.xlabel] = mapping[self.xlabel].map(self.day_encoder)
            
        if 'ip_src' == self.ylabel:
            mapping[self.ylabel] = mapping[self.ylabel].map(self.ip_encoder)
            self.plot_freqency(mapping)
        
        if 'ip_ttl' == self.ylabel:
            mapping['ip_src'] = mapping['ip_src'].map(self.ip_encoder)

            mapping.plot(kind='scatter',x = 'date',y = 'ip_src',c='ip_ttl',s=2.0)
        plt.subplots_adjust(wspace=0.4)
        plt.show()


    def plot_freqency(self,mapping):
        honeypot = [self.ip_encoder('sip: 160.26.57.181'), self.ip_encoder('sip: 160.26.57.192'), self.ip_encoder('sip:160.26.57.203')]
        plt.figure(figsize=(12, 10))
        ax1 = plt.subplot(121, title=self.signature.split('/')[-1])
        
        fre_base = mapping.query(f'ip_src not in {honeypot}')
        fre_base = fre_base[fre_base['ip_id'].duplicated()]
        
        fre_base.plot(kind='scatter', x=self.xlabel, y='ip_src', s=0.5, ax=ax1)
        
        frequent = fre_base['ip_src'].map(self.ip_decoder).value_counts()[:30]
        
        fre_base['ip_src'] = fre_base['ip_src'].map(self.ip_decoder)
        ftmp = fre_base.set_index('ip_src')
        ftmp = ftmp.join(frequent).sort_values('ip_src',ascending=False)
        
        ip_info = pd.concat([ftmp['ip_src'],ftmp['country'],ftmp['ASN']],axis=1)
        ip_info = ip_info[~ip_info.duplicated()]
        ip_info = ip_info.iloc[:30,:]
        
        ax2 = plt.subplot(122, title='freqency')
        plt.axis('off')
        tb = table(ax2,ip_info,cellLoc='center',loc='center',rowLoc='center',colWidths=[0.2,0.3,0.3],fontsize=13)
        
