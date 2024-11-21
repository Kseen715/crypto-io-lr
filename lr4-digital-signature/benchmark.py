from sign import *
import csv
import argparse
import os
import timeit
from hashlib import sha256
import time
import multiprocessing
import random

import matplotlib.pyplot as plt
import pandas as pd
import numpy as np

CYN = ksilorama.Fore.CYAN
CLR = ksilorama.Fore.HEX('#FF6677') \
    + ksilorama.Style.BRIGHT \

RST = ksilorama.Style.RESET_ALL

wo_keygen = ['GOST 34.10-2018']
times = 1000


algs = [
    # 'RSA-SHA256',
    # 'RSA-SHA512',
    # 'DSA',
    # 'ECDSA',
    # 'GOST 34.10-2012 (SHA256)',
    # 'GOST 34.10-2012 (SHA512)',
    'GOST 34.10-2012 (STREEBOG256)',
    'GOST 34.10-2012 (STREEBOG512)',
    # 'GOST 34.10-2018 (SHA256)',
]


def test_case(alg, in_sizes):
    try:
        for i in range(times):
            sizes = list(in_sizes)
            # grab PID
            pid = os.getpid()
            # get time in ns
            time_ns = time.time_ns()
            # get hash of PID and time
            hash = sha256(f'{pid}{time_ns}'.encode()).hexdigest()
            while sizes:
                size = random.choice(sizes)
                sizes.remove(size)
                try:
                    folder_txt = Path('temp/txt')
                    folder_sig = Path('temp/sig')
                    folder_key = Path('temp/key')
                    file = Path(f'{folder_txt}/file_{size}_{hash}.txt')
                    signature_file = Path(
                        f'{folder_sig}/signature_{size}_{hash}.sig')
                    key_file = Path(f'{folder_key}/key_{size}_{hash}.key')

                    if not os.path.exists(folder_txt):
                        os.makedirs(folder_txt)
                    if not os.path.exists(folder_sig):
                        os.makedirs(folder_sig)
                    if not os.path.exists(folder_key):
                        os.makedirs(folder_key)

                    with file.open('wb') as f:
                        f.write(os.urandom(int(size * 1024 * 1024)))
                    if alg not in wo_keygen:
                        keygen_time = timeit.timeit(
                            lambda: generate_key(key_file, alg), number=1)
                    else:
                        keygen_time = 'inf'
                    sign_time = timeit.timeit(
                        lambda: sign_file(file, signature_file, key_file, alg),
                        number=1)
                    verify_time = timeit.timeit(
                        lambda: verify_file(file, signature_file, alg),
                        number=1)
                    with open('temp/benchmark.csv', 'a') as res_file:
                        res_file.write(f'"{alg}",{size},{keygen_time},{
                            sign_time},{verify_time}\n')
                    print(f'[{CYN}BENCH{RST}] '
                          + f'{CLR}Alg{RST}: {alg}, '
                          + f'{size} MB, '
                          + f'{CLR}Key{RST}: {float(keygen_time):.6f}s, '
                          + f'{CLR}Sign{RST}: {sign_time:.6f}s, '
                          + f'{CLR}Verify{RST}: {verify_time:.6f}s', end='\n')
                finally:
                    if os.path.exists(file):
                        os.remove(file)
                    if os.path.exists(signature_file):
                        os.remove(signature_file)
                    if os.path.exists(key_file) and alg not in wo_keygen:
                        os.remove(key_file)
    except KeyboardInterrupt:
        print(f'\n{CYN}Benchmarking interrupted{RST}')
        exit(1)
    except Exception as e:
        print(f'[{CYN}BENCH{RST}] {CLR}Error{RST}: {e}', end='\n')


def benchmark():
    sizes = np.arange(0.5, 8 + 0.1, 0.5)

    # csv format:
    # alg, size, keygen_time, sign_time, verify_time
    if not os.path.exists('temp/benchmark.csv'):
        with open('temp/benchmark.csv', 'w') as f:
            f.write('alg,size,keygen_time,sign_time,verify_time\n')

    try:
        # use multiprocessing to run tests in parallel
        with multiprocessing.Pool(processes=24) as pool:
            pool.starmap(test_case, [(alg, sizes)
                         for alg in algs])
    except KeyboardInterrupt:
        print(f'\n{CYN}Benchmarking interrupted{RST}')
        exit(1)


class StatPlotter():
    color = [
        '#e41a1c',
        '#377eb8',
        '#f781bf',
        '#dede00',
        '#4daf4a',
        '#ff7f00',
        '#a65628',
        '#984ea3',
        '#999999',
    ]

    @staticmethod
    def _remove_outliers(data: pd.DataFrame, m=2):
        """
        Remove outliers from data

        :param data: data to remove outliers from
        :param m: number of standard deviations to consider as outlier
        :return: data without outliers
        """
        return data[abs(data - data.mean()) < m * data.std()]

    @staticmethod
    def _dot(v, w):
        """
        Скалярное произведение векторов

        Parameters
        ----------
            v (list): Вектор
            w (list): Вектор

        Returns
        -------
            float: Скалярное произведение векторов
        """
        if type(v) != list:
            raise TypeError("v should be a list, not " + str(type(v)) + ".")
        if type(w) != list:
            raise TypeError("w should be a list, not " + str(type(w)) + ".")
        if len(v) != len(w):
            raise ValueError("vectors should be the same length "
                             "(v: " + str(len(v)) + ", w: " + str(len(w)) + ").")
        if len(v) == 0 or len(w) == 0:
            raise ValueError("vectors should be non-empty.")
        if type(v[0]) != int and type(v[0]) != float:
            raise TypeError("v should contain numbers, "
                            "not " + str(type(v[0])) + ".")
        if type(w[0]) != int and type(w[0]) != float:
            raise TypeError("w should contain numbers, "
                            "not " + str(type(w[0])) + ".")
        return sum(v_i * w_i for v_i, w_i in zip(v, w))

    @staticmethod
    def _gauss_slae(A, b):
        """
        Метод Гаусса решения СЛАУ

        Parameters
        ----------
            A (list of list): Матрица коэффициентов
            b (list): Свободные члены

        Returns
        -------
            list: Решение
        """

        n = len(b)  # вычисляем порядок системы
        # строим расширенную матрицу системы
        G = [ai+[bi] for ai, bi in zip(A, b)]
        # Прямой проход
        for i in range(n):
            for j in range(i, n):
                G[j] = list(map(lambda x: x/G[j][i], G[j]))
                if j > i:
                    G[j] = [g - u for g, u in zip(G[j], G[i])]
        # Обратный проход
        x = [0]*n      # инициируем список, который потом станет решением
        for i in range(n-1, -1, -1):
            x[i] = G[i][-1]-StatPlotter._dot(x, G[i][:-1])
        return x

    @staticmethod
    def _approx_poly(x, t, r):
        """
        Аппроксимация полиномом

        Parameters
        ----------
            x (list): Список чисел
            t (list): Список чисел, range(1, len(x)+1)
            r (int): Степень полинома

        Returns
        -------
            list: Параметры полинома
        """
        M = [[] for _ in range(r+1)]
        b = []
        for l in range(r+1):
            for q in range(r+1):
                M[l].append(sum(list(map(lambda z: z**(l+q), t))))
            b.append(sum(xi*ti**l for xi, ti in zip(x, t)))
        a = StatPlotter._gauss_slae(M, b)
        return a

    @staticmethod
    def plot_lines(
            df: pd.DataFrame,
            xcolumn: str,
            ycolumn: str,
            column_with_line_name: str,
            groupby: list,
            title: str = 'Title',
            xlabel: str = 'X axis',
            ylabel: str = 'Y asix',
            exclude_line_name: list = [],
            m: float = 1e9999,
            output_folder: str = 'temp',
            file_postfix: str = '',
    ):
        """
        Plot line plot with error bars

        :param df: data to plot 
        :param xcolumn: x axis column
        :param ycolumn: y axis column
        :param column_with_line_name: column with line name (e.g. 'alg')
        :param groupby: columns to group by (e.g. ['alg', 'size'])
        :param title: plot title
        :param xlabel: x axis label
        :param ylabel: y axis label
        :param m: number of standard deviations to consider as outlier 
        (default: 1e9999)
        :param output_folder: output folder for plot (default: 'temp')
        """
        # exclude alg from exclude_line_name
        df = df[~df[column_with_line_name].isin(exclude_line_name)]

        # remove outliers
        df = df.groupby(groupby).apply(StatPlotter._remove_outliers, m)

        # calculate average time for every alg for every size by iteration
        means = df.groupby(groupby).mean()

        # calculate yerr for every alg
        mins = df.groupby(groupby).min()
        maxs = df.groupby(groupby).max()

        # combine data
        means = means.reset_index()
        mins = mins.reset_index()
        maxs = maxs.reset_index()

        column_max = ycolumn + '_max'
        column_min = ycolumn + '_min'
        column_mean = ycolumn + '_mean'

        data = pd.merge(means, mins, on=groupby, suffixes=('_mean', '_min'))

        data = pd.merge(data, maxs, on=groupby)
        data = data.rename(columns={ycolumn: column_max})

        # calculate linear regression for every alg
        def gen_poly_data(x, P):
            return [sum([P[i] * x ** i for i in range(len(P))]) for x in x]

        def gen_poly_str(P):
            terms = []
            for i in range(len(P)-1, 0, -1):
                if i == len(P)-1:
                    if i == 1:
                        terms.append(f'{P[i]:.1f}x' if P[i] != 0 else '')
                    else:
                        terms.append(f'{P[i]:.1f}x^{i}' if P[i] != 0 else '')
                else:
                    if i == 1:
                        terms.append(f'{P[i]:+.1f}x' if P[i] != 0 else '')
                    else:
                        terms.append(f'{P[i]:+.1f}x^{i}' if P[i] != 0 else '')
            return ''.join(filter(None, terms)) \
                + (f'{P[0]:+.1f}' if P[0] != 0 else '')

        for alg in data[column_with_line_name].unique():
            alg_data = data[data[column_with_line_name] == alg]
            x = alg_data['size']
            y = alg_data[column_mean]

            m = StatPlotter._approx_poly(y.tolist(), x.tolist(), 1)
            data.loc[data[column_with_line_name] == alg, 'poly'] \
                = gen_poly_str(m)
            data.loc[data[column_with_line_name] == alg, 'poly_data'] \
                = gen_poly_data(x, m)

        print(data)

        percent_to_plot = 100
        plot_lim = int(100 / percent_to_plot)
        fig, ax = plt.subplots(figsize=(10, 6))
        for alg in data[column_with_line_name].unique():
            alg_data = data[data[column_with_line_name] == alg]
            ax.errorbar(
                alg_data[xcolumn][::plot_lim],
                alg_data[column_mean][::plot_lim],
                yerr=[(alg_data[column_mean]
                       - alg_data[column_min])[::plot_lim],
                      (alg_data[column_max]
                       - alg_data[column_mean])[::plot_lim]],
                label=alg,
                fmt='-o',
                color=StatPlotter.color[data[column_with_line_name].unique(
                ).tolist().index(alg)],
                capsize=4,
                capthick=1.5,
            )
            alg_data = data[data[column_with_line_name] == alg]
            ax.plot(
                alg_data[xcolumn][::plot_lim],
                alg_data['poly_data'][::plot_lim],
                label=f'{alg} poly {alg_data["poly"].iloc[0]}',
                linestyle='--',
                color=StatPlotter.color[data[column_with_line_name].unique(
                ).tolist().index(alg)],
            )
        ax.set_xlabel(xlabel)
        ax.set_ylabel(ylabel)
        ax.legend()
        plt.title(title)
        plt.tight_layout()
        plt.savefig(f'{output_folder}/plt_{ycolumn}{file_postfix}.png')

    @staticmethod
    def plot_bars(
            df: pd.DataFrame,
            xcolumn: str,
            ycolumn: str,
            column_with_line_name: str,
            groupby: list,
            title: str = 'Title',
            xlabel: str = 'X axis',
            ylabel: str = 'Y asix',
            m: float = 1e9999,
            exclude_bar_name: list = [],
            xlabel_rotation: int = 0,
            output_folder: str = 'temp',
            file_postfix: str = '',
    ):
        """
        Plot bar plot with error bars

        :param df: data to plot
        :param xcolumn: x axis column
        :param ycolumn: y axis column
        :param column_with_line_name: column with line name (e.g. 'alg')
        :param groupby: columns to group by (e.g. ['alg', 'size'])
        :param title: plot title
        :param xlabel: x axis label
        :param ylabel: y axis label
        :param m: number of standard deviations to consider as outlier
        (default: 1e9999)
        :param output_folder: output folder for plot (default: 'temp')
        """
        # exclude alg from exclude_line_name
        df = df[~df[column_with_line_name].isin(exclude_bar_name)]

        # remove outliers
        df = df.groupby(groupby).apply(StatPlotter._remove_outliers, m)

        # calculate average time for every alg for every size by iteration
        means = df.groupby(groupby).mean()

        # calculate yerr for every alg
        mins = df.groupby(groupby).min()
        maxs = df.groupby(groupby).max()

        # combine data
        means = means.reset_index()
        mins = mins.reset_index()
        maxs = maxs.reset_index()

        time_name_max = ycolumn + '_max'
        time_name_min = ycolumn + '_min'
        time_name_mean = ycolumn + '_mean'

        data = pd.merge(means, mins, on=groupby, suffixes=('_mean', '_min'))

        data = pd.merge(data, maxs, on=groupby)
        data = data.rename(columns={ycolumn: time_name_max})

        print(data)

        # plot bar plot with error bars
        fig, ax = plt.subplots(figsize=(10, 6))
        alg_data = data

        ax.bar(
            alg_data[xcolumn],
            alg_data[time_name_mean],
            yerr=[(alg_data[time_name_mean]
                   - alg_data[time_name_min]),
                  (alg_data[time_name_max]
                   - alg_data[time_name_mean])],
            color=StatPlotter.color,
            error_kw=dict(lw=1, capsize=5, capthick=2),
        )
        # add number on bottom of bars
        for i, v in enumerate(alg_data[time_name_mean]):
            ax.text(i, v, f'{v:.2f}', ha='center', va='bottom')
        ax.set_xlabel(xlabel)
        ax.set_ylabel(ylabel)
        # add title
        plt.title(title)
        plt.xticks(rotation=xlabel_rotation)
        # expand fig to fit labels
        plt.tight_layout()
        plt.savefig(f'{output_folder}/plt_{ycolumn}{file_postfix}.png')


def plot():
    #     alg, size, keygen_time, sign_time, verify_time
    time_names_line_plot = ['sign_time', 'verify_time']
    time_names_bar_plot = ['keygen_time']

    for time_name in time_names_line_plot:
        df = pd.read_csv('temp/benchmark.csv')
        other_time = (time_names_line_plot.copy() + time_names_bar_plot.copy())
        other_time.remove(time_name)

        # Drop other time columns
        df = df.drop(columns=other_time)

        # convert time from s to ms
        df[time_name] = df[time_name] * 1000

        StatPlotter.plot_lines(
            df,
            'size',
            time_name,
            'alg',
            ['alg', 'size'],
            f'{str(time_name).capitalize().replace(
                '_', ' ')} with different algorithms',
            'File size (MB)', 'Time (ms)',
            output_folder='temp',
            m=0.5,
            exclude_line_name=[
                # 'GOST 34.10-2012 (SHA512)',
                'GOST 34.10-2012 (STREEBOG256)',
                'GOST 34.10-2012 (STREEBOG512)',
            ],
            file_postfix='_smaller',
        )

    for time_name in time_names_line_plot:
        df = pd.read_csv('temp/benchmark.csv')
        other_time = (time_names_line_plot.copy() + time_names_bar_plot.copy())
        other_time.remove(time_name)

        # Drop other time columns
        df = df.drop(columns=other_time)

        # convert time from s to ms
        df[time_name] = df[time_name] * 1000

        StatPlotter.plot_lines(
            df,
            'size',
            time_name,
            'alg',
            ['alg', 'size'],
            f'{str(time_name).capitalize().replace(
                '_', ' ')} with different algorithms',
            'File size (MB)', 'Time (ms)',
            output_folder='temp',
            m=1e9999,
            file_postfix='_full',
        )

    for time_name in time_names_bar_plot:
        df = pd.read_csv('temp/benchmark.csv')
        # Drop size column
        df = df.drop(columns=['size'])

        other_time = (time_names_line_plot.copy() + time_names_bar_plot.copy())
        other_time.remove(time_name)

        # Drop other time columns
        df = df.drop(columns=other_time)

        # convert time from s to ms
        df[time_name] = df[time_name] * 1000

        StatPlotter.plot_bars(
            df,
            'alg',
            time_name,
            'alg',
            ['alg'],
            f'{str(time_name).capitalize().replace(
                '_', ' ')} with different algorithms',
            'Algorithm', 'Time (ms)',
            output_folder='temp',
            m=0.5,
            xlabel_rotation=55,
            file_postfix='',
            exclude_bar_name=[
                'GOST 34.10-2018 (SHA256)',
            ],
        )


if __name__ == '__main__':
    description = \
        ksilorama.Fore.HEX('#EE9944') \
        + ksilorama.Style.ITALIC \
        + 'Benchmark and plot the results' \
        + ksilorama.Style.RESET_ALL
    parser = argparse.ArgumentParser(
        description=description)

    parser.add_argument('command', choices=['bench', 'plot'])

    args = parser.parse_args()

    if args.command == 'bench':
        try:
            benchmark()
        except KeyboardInterrupt:
            print(f'\n{CYN}Benchmarking interrupted{RST}')
            exit(1)
    elif args.command == 'plot':
        try:
            plot()
        except KeyboardInterrupt:
            print(f'\n{CYN}Plotting interrupted{RST}')
            exit(1)
    else:
        print('Invalid command')
        exit(1)
