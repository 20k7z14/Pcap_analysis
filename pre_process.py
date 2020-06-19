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
        csv_name = os.listdir('./csv/common')
        for name in csv_name:
            csv_path.append(rf'./csv/common/{name}')
        return csv_path

    def extract_Honeypot(self, path):
        if path[-4:] == '.csv':
            df = pd.read_csv(path)
            file_date = path.split('/')[2].split('.')[0]

            lurker = df[(df['src'] == self.l_ip) | (df['dst'] == self.l_ip)]
            dionaea = df[(df['src'] == self.d_ip) | (df['dst'] == self.d_ip)]
            ubuntu = df[(df['src'] == self.u_ip) | (df['dst'] == self.u_ip)]
            windows = df[(df['src'] == self.w_ip) | (df['dst'] == self.w_ip)]
            try:
                lurker.to_csv(rf'./csv/Lurker/l_{file_date}.csv')
                dionaea.to_csv(rf'./csv/Dionaea/d_{file_date}.csv')
                ubuntu.to_csv(rf'./csv/Ubuntu/u_{file_date}.csv')
                windows.to_csv(rf'./csv/Windows/w_{file_date}.csv')
            except KeyboardInterrupt:
                os.remove(rf'./csv/Lurker/l_{file_date}.csv')
                os.remove(rf'./csv/Dionaea/d_{file_date}.csv')
                os.remove(rf'./csv/Ubuntu/u_{file_date}.csv')
                os.remove(rf'./csv/Windows/w_{file_date}.csv')

    @staticmethod
    def load_potCsv(honeypot):
        pot_path, pot_name = [], []

        pot_name = os.listdir(rf'./csv/{honeypot}/')
        period = pot_name[0][2:11] + ' ~ ' + pot_name[-1][2:11]
        for name in pot_name:
            pot_path.append(rf'./csv/{honeypot}/{name}')
        return pot_path, period
