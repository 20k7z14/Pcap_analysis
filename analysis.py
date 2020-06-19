import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
from tqdm import tqdm
import pre_process as pre
import scatter as sc

global period

honey_pots = ['Lurker', 'Dionaea', 'Ubuntu', 'Windows']

if __name__ == '__main__':
    args = sys.argv
    hp = pre.Honeypots()

    if args[1] == '-g':  # csv generate
        for path in tqdm(hp.pot_path):
            hp.extract_Honeypot(path)

    elif args[1] == '-i': # individual
        chart = sc.Scatter(args[3], args[4])
        chart.singleFlatScatter(args[2])

    elif args[1] == '-a':
        chart = sc.Scatter(args[2],args[3])
        chart.quadFlatScatter()