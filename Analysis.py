import os
import sys
import datetime
import pandas as pd
import matplotlib.pyplot as plt
from tqdm import tqdm
import pre_process as pre

global data_range

honey_pots = ['Lurker', 'Dionaea', 'Ubuntu', 'Windows']


def ip_convert(ip_src):
    ip_class = ip_src.split('.')
    cvt_ip = 0
    for digit in ip_class:
        cvt_ip += int(digit) * (256 ** (3 - ip_class.index(digit)))
    return cvt_ip


if __name__ == '__main__':
    args = sys.argv
    hp = pre.Honeypots()

    if args[1] == '-g':  # csv generate
        for path in tqdm(hp.pot_path):
            hp.extract_Honeypot(path)

    elif args[1] == '-d':
        path, data_range = hp.load_potCsv(args[2].lower())  # data_range's type is str
        pivot = pd.DataFrame()
        for p in tqdm(path):
            signature = pd.read_csv(p)
            x = pd.Series(signature.src.map(ip_convert).values)
            y = pd.Series(signature.seq.values)
            tmp = pd.DataFrame([x, y], index=['src', 'seq'])
            pivot = pd.concat([pivot, tmp], axis=1)
        print('plotting...')

        x, y = list(pivot.loc['seq']), list(pivot.loc['src'])
        plt.scatter(x, y, s=0.5, alpha=0.5)
        plt.title(args[2])
        plt.xlabel('seq')
        plt.ylabel('source ip')
        plt.grid(True)
        plt.show()

    elif args[1] == '-a':
        fig, axes = plt.subplots(2, 2, figsize=(10.0, 8.0), sharey=True)
        for cnt, pot in enumerate(honey_pots, 0):
            path, data_range = hp.load_potCsv(pot.lower())

            pivot = pd.DataFrame()
            for p in tqdm(path):
                signature = pd.read_csv(p)
                x = pd.Series(signature.src.map(ip_convert).values)
                y = pd.Series(signature.date.values)
                z = pd.Series(signature.seq.values)
                tmp = pd.DataFrame([x, y, z], index=['src', 'date', 'seq'])
                pivot = pd.concat([pivot, tmp], axis=1)

            print(pot + ' plotting...')

            x, z, y = list(pivot.loc['seq']), list(pivot.loc['src']), list(pivot.loc['date'])
            axes[cnt // 2, cnt % 2].scatter(x, y, s=0.5, alpha=0.5, c=z)
            axes[cnt // 2, cnt % 2].set(title=honey_pots[cnt], xlabel='seq', ylabel='source ip')
            axes[cnt // 2, cnt % 2].grid(True)

        fig.suptitle(rf'seq-src_{data_range}')
        fig.tight_layout()
        fig.subplots_adjust(top=0.9)
        plt.show()
        fig.savefig(rf'seq-src_{data_range}.png')
