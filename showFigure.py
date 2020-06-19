import matplotlib as plt
import pandas as pd
import tqdm


class Showfigure:
    def __init__(self, x, y, xlabel, ylabel):
        self.x = x
        self.y = y
        self.xlabel = xlabel
        self.ylabel = ylabel

    def SingleFlatFigure(self, path, period):
        pivot = pd.DataFrame()

        for p in tqdm(path):
            original_data = pd.read_csv(p)
            x = pd.Series(original_data, self.x)
            y = pd.Series(original_data, self.y)
            tmp = pd.DataFrame([x, y], index=[f'{self.xlabel}', f'{self.ylabel}'])
            pivot = pd.concat([pivot, tmp], axis=1)

        print('plotting...')

        x, y = list(pivot.loc[f'{self.xlabel}']), list(pivot.loc[f'{self.ylabel}'])
        plt.scatter(x, y, s=0.5, alpha=0.5)
        plt.title(period)
        plt.xlabel(f'{self.xlabel}')
        plt.ylabel(f'{self.ylabel}')
        plt.grid(True)
        plt.show()

