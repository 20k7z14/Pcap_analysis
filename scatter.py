import matplotlib.pyplot as plt
import pandas as pd
import os

honey_pots = ['Lurker', 'Dionaea', 'Ubuntu', 'Windows']

class Scatter:
    def __init__(self, xlabel, ylabel):
        self.xlabel = xlabel
        self.ylabel = ylabel

    def ip_convert(ip_src):
        ip_class = ip_src.split('.')
        cvt_ip = 0
        for digit in ip_class:
            cvt_ip += int(digit) * (256 ** (3 - ip_class.index(digit)))
        return cvt_ip
    
    def load_potCsv(honeypot):
        pot_path, pot_name = [], []

        pot_name = os.listdir(rf'../csv/{honeypot}/')
        period = pot_name[0][2:11] + ' ~ ' + pot_name[-1][2:11]
        for name in pot_name:
            pot_path.append(rf'../csv/{honeypot}/{name}')
        return pot_path, period


    def mergeColumn(self, path):
        pivot = pd.DataFrame()
        for i, p in enumerate(path, 1):
            original_data = pd.read_csv(p)
            x = pd.Series(original_data[self.xlabel])
            y = pd.Series(original_data[self.ylabel])
            tmp = pd.DataFrame([x, y], index=[f'{self.xlabel}', f'{self.ylabel}'])
            pivot = pd.concat([pivot, tmp], axis=1)

            print(f'{i}/{len(path)} : ', p)
        return pivot


    def singleFlatScatter(self, pot):
        path, period = self.load_potCsv(pot.lower())  # period's type is str
        mapping = self.mergeColumn(path)

        print('plotting...')

        x, y = list(mapping.loc[f'{self.xlabel}']), list(mapping.loc[f'{self.ylabel}'])
        plt.scatter(x, y, s=0.5, alpha=0.5)
        plt.title(pot + period)
        plt.xlabel(f'{self.xlabel}')
        plt.ylabel(f'{self.ylabel}')
        plt.grid(True)
        plt.show()

    def quadFlatScatter(self):
        fig, axes = plt.subplots(2, 2, figsize=(10.0, 8.0), sharey=True)
        for cnt,pot in enumerate(honey_pots, 0):
            path, period = self.load_potCsv(pot)  # data_range's type is str
            mapping = self.mergeColumn(path)

            print(pot + ' plotting...')

            x, y = list(mapping.loc[f'{self.xlabel}']), list(mapping.loc[f'{self.ylabel}'])
            axes[cnt // 2, cnt % 2].scatter(x, y, s=0.5, alpha=0.5)
            axes[cnt // 2, cnt % 2].set(title=honey_pots[cnt], xlabel=f'{self.ylabel}', ylabel=f'{self.ylabel}')
            axes[cnt // 2, cnt % 2].grid(True)

        fig.suptitle(rf's{self.xlabel}-{self.ylabel}_{period}')
        fig.tight_layout()
        fig.subplots_adjust(top=0.9)
        plt.show()
        fig.savefig(rf'{self.xlabel}-{self.ylabel}_{period}.png')

