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
import dsmltf

CYN = ksilorama.Fore.CYAN
CLR = ksilorama.Fore.HEX('#FF6677') \
    + ksilorama.Style.BRIGHT \

RST = ksilorama.Style.RESET_ALL

wo_keygen = ['GOST 34.10-2018']
times = 1000


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


algs = [
    # 'RSA-SHA256',
    'RSA-SHA512',
    # 'DSA',
    # 'ECDSA',
    # 'GOST 34.10-2018',
]


def benchmark():
    sizes = np.arange(0.5, 8 + 0.1, 0.5)

    # csv format:
    # alg, size, keygen_time, sign_time, verify_time
    if not os.path.exists('temp/benchmark.csv'):
        with open('temp/benchmark.csv', 'w') as f:
            f.write('alg,size,keygen_time,sign_time,verify_time\n')

    try:
        # use multiprocessing to run tests in parallel
        with multiprocessing.Pool(processes=12) as pool:
            pool.starmap(test_case, [(alg, sizes)
                         for alg in algs])
    except KeyboardInterrupt:
        print(f'\n{CYN}Benchmarking interrupted{RST}')
        exit(1)


def remove_outliers(data: pd.DataFrame, m=2):
    """
    Remove outliers from data

    :param data: data to remove outliers from
    :param m: number of standard deviations to consider as outlier
    :return: data without outliers
    """
    return data[abs(data - data.mean()) < m * data.std()]


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

        # remove outliers
        df = df.groupby(['alg', 'size']).apply(remove_outliers, m=0.5)

        # calculate average time for every alg for every size by iteration
        means = df.groupby(['alg', 'size']).mean()

        # calculate yerr for every alg
        mins = df.groupby(['alg', 'size']).min()
        maxs = df.groupby(['alg', 'size']).max()

        # combine data
        means = means.reset_index()
        mins = mins.reset_index()
        maxs = maxs.reset_index()

        time_name_max = time_name + '_max'
        time_name_min = time_name + '_min'
        time_name_mean = time_name + '_mean'

        data = pd.merge(means, mins, on=[
                        'alg', 'size'], suffixes=('_mean', '_min'))

        data = pd.merge(data, maxs, on=['alg', 'size'])
        data = data.rename(columns={time_name: time_name_max})

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

        for alg in data['alg'].unique():
            alg_data = data[data['alg'] == alg]
            x = alg_data['size']
            y = alg_data[time_name_mean]

            m = dsmltf.approx_poly(y.tolist(), x.tolist(), 1)
            data.loc[data['alg'] == alg, 'poly'] \
                = gen_poly_str(m)
            data.loc[data['alg'] == alg, 'time_poly'] \
                = gen_poly_data(x, m)

        print(data)

        percent_to_plot = 100
        plot_lim = int(100 / percent_to_plot)
        fig, ax = plt.subplots(figsize=(10, 6))
        for alg in data['alg'].unique():
            alg_data = data[data['alg'] == alg]
            ax.errorbar(
                alg_data['size'][::plot_lim],
                alg_data[time_name_mean][::plot_lim],
                yerr=[(alg_data[time_name_mean]
                       - alg_data[time_name_min])[::plot_lim],
                      (alg_data[time_name_max]
                       - alg_data[time_name_mean])[::plot_lim]],
                label=alg,
                fmt='-o',
                color=color[data['alg'].unique().tolist().index(alg)]
            )
            alg_data = data[data['alg'] == alg]
            ax.plot(
                alg_data['size'][::plot_lim],
                alg_data['time_poly'][::plot_lim],
                label=f'{alg} poly {alg_data["poly"].iloc[0]}',
                linestyle='--',
                color=color[data['alg'].unique().tolist().index(alg)]
            )
        ax.set_xlabel('File size (MB)')
        ax.set_ylabel('Time (ms)')
        ax.legend()
        # add title
        plt.title('Time of signing and verifying with different algorithms')
        plt.tight_layout()
        # plt.show()
        plt.savefig(f'temp/plt_{time_name}.png')

    for time_name in time_names_bar_plot:
        df = pd.read_csv('temp/benchmark.csv')
        # Drop size column
        df = df.drop(columns=['size'])

        other_time = (time_names_line_plot.copy() + time_names_bar_plot.copy())
        other_time.remove(time_name)

        # Drop other time columns
        df = df.drop(columns=other_time)

        # Drop lines, where wo_keygen alg is present
        df = df[~df['alg'].isin(wo_keygen)]

        # convert time from s to ms
        df[time_name] = df[time_name] * 1000

        # remove outliers
        df = df.groupby('alg').apply(remove_outliers, m=0.5)

        # calculate average time for every alg for every size by iteration
        means = df.groupby(['alg']).mean()

        # calculate yerr for every alg
        mins = df.groupby(['alg']).min()
        maxs = df.groupby(['alg']).max()

        # combine data
        means = means.reset_index()
        mins = mins.reset_index()
        maxs = maxs.reset_index()

        time_name_max = time_name + '_max'
        time_name_min = time_name + '_min'
        time_name_mean = time_name + '_mean'

        data = pd.merge(means, mins, on=['alg'], suffixes=('_mean', '_min'))

        data = pd.merge(data, maxs, on=['alg'])
        data = data.rename(columns={time_name: time_name_max})

        print(data)

        # plot bar plot with error bars
        fig, ax = plt.subplots(figsize=(10, 6))
        alg_data = data
        ax.bar(
            alg_data['alg'],
            alg_data[time_name_mean],
            yerr=[(alg_data[time_name_mean]
                   - alg_data[time_name_min]),
                  (alg_data[time_name_max]
                   - alg_data[time_name_mean])],
            color=color
        )
        ax.set_xlabel('Algorithm')
        ax.set_ylabel('Time (ms)')
        ax.legend()
        # add title
        plt.title('Time of generating keys with different algorithms')
        plt.tight_layout()
        # plt.show()
        plt.savefig(f'temp/plt_{time_name}.png')


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
