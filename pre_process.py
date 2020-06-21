import os
import csv
import pandas as pd


class Honeypots:
    def __init__(self):
        self.l_ip = '160.26.57.181'
        self.d_ip = '160.26.57.192'
        self.u_ip = '160.26.57.203'
        self.w_ip = '160.26.57.214'

        self.pot_path = self.load_CommonCsv()

    @classmethod
    def load_CommonCsv(cls):
        csv_path, csv_name = [], []
        csv_name = os.listdir('../csv/common')
        for name in csv_name:
            csv_path.append(rf'../csv/common/{name}')
        return csv_path

    def load_honeypot(self):
        honeypots = ['lurker', 'dionaea', 'ubuntu', 'windows']
        honeypots_csv_path = []
        for pot in honeypots:
            tmp = []
            pot_name = os.listdir(f'../csv/{pot}')
            for name in pot_name:
                tmp.append(rf'../csv/{pot}/{name}')
            honeypots_csv_path.append(tmp)
        return honeypots_csv_path

    def extract_Honeypot(self, path):
        if path.split('.')[1] == '.csv':
            df = pd.read_csv(path)
            file_date = path.split('/')[2].split('.')[0]

            lurker = df[(df['src'] == self.l_ip) | (df['dst'] == self.l_ip)]
            dionaea = df[(df['src'] == self.d_ip) | (df['dst'] == self.d_ip)]
            ubuntu = df[(df['src'] == self.u_ip) | (df['dst'] == self.u_ip)]
            windows = df[(df['src'] == self.w_ip) | (df['dst'] == self.w_ip)]
            try:
                lurker.to_csv(rf'../csv/Lurker/l_{file_date}.csv')
                dionaea.to_csv(rf'../csv/Dionaea/d_{file_date}.csv')
                ubuntu.to_csv(rf'../csv/Ubuntu/u_{file_date}.csv')
                windows.to_csv(rf'../csv/Windows/w_{file_date}.csv')
            except KeyboardInterrupt:
                os.remove(rf'../csv/Lurker/l_{file_date}.csv')
                os.remove(rf'../csv/Dionaea/d_{file_date}.csv')
                os.remove(rf'../csv/Ubuntu/u_{file_date}.csv')
                os.remove(rf'../csv/Windows/w_{file_date}.csv')

    def extract_signature(self,*column):
        honeypots = ['lurker', 'dionaea', 'ubuntu', 'windows']

        for col in column:
            path_dataframe = self.load_honeypot()
            for i, path in enumerate(path_dataframe):
                sig = pd.DataFrame()
                for p in path:
                    df = pd.read_csv(p,engine="python")
                    tmp = p.split('/')[3].split('.')[0].split('_')[1:]
                    date = tmp[0]+tmp[1]
                    sig[date] = df[col]

                print(sig)
                sig_path = rf'../csv/{honeypots[i]}/signature'

                try:
                    if not os.path.exists(sig_path):
                        os.makedirs(sig_path)
                except OSError:
                    print("Error: Could not make directory.")

                sig.to_csv(rf'../csv/{honeypots[i]}/signature/{col}.csv')
