import matplotlib.pyplot as plt
import pandas as pd
import dsmltf

if __name__ == '__main__':
    # read data from csv
    # method,iteration,file_size,time
    df = pd.read_csv('temp/test.csv')

    # convert time from s to ms
    df['time'] = df['time'] * 1000
    
    # calculate average time for every method for every size by iteration
    means = df.groupby(['method', 'file_size']).mean()
    means = means.drop(columns='iteration')
    
    # calculate yerr for every method
    mins = df.groupby(['method', 'file_size']).min()
    mins = mins.drop(columns='iteration')
    maxs = df.groupby(['method', 'file_size']).max()
    maxs = maxs.drop(columns='iteration')
    
    # combine data
    means = means.reset_index()
    mins = mins.reset_index()
    maxs = maxs.reset_index()
    
    # print(means)
    # print(mins)
    # print(maxs)

    data = pd.merge(means, mins, on=['method', 'file_size'], suffixes=('_mean', '_min'))

    data = pd.merge(data, maxs, on=['method', 'file_size'])
    data = data.rename(columns={'time': 'time_max'})

    # calculate linear regression
    # for every method

    def gen_poly_data(x, P):
        return [sum([P[i] * x ** i for i in range(len(P))]) for x in x]
    
    def gen_poly_str(P):
        return '+'.join([f'{P[i]:.1f}*x^{i}' for i in range(len(P)-1, 0, -1)]) + (f'+{P[0]:.1f}' if P[0] != 0 else '')

    for method in data['method'].unique():
        method_data = data[data['method'] == method]
        x = method_data['file_size']
        y = method_data['time_mean']
        m = dsmltf.approx_poly(y.tolist(), range(1, len(y.tolist()) + 1), 1)
        data.loc[data['method'] == method, 'poly'] = gen_poly_str(m)
        data.loc[data['method'] == method, 'time_poly'] = gen_poly_data(x, m)

    color = ['#e41a1c', '#377eb8', '#f781bf', '#dede00']
    CB_color_cycle = ['#377eb8', '#ff7f00', '#4daf4a',
                  '#f781bf', '#a65628', '#984ea3',
                  '#999999', '#e41a1c', '#dede00']

    print(data)

    fig, ax = plt.subplots(figsize=(10, 6))
    for method in data['method'].unique():
        method_data = data[data['method'] == method]
        ax.errorbar(method_data['file_size'], method_data['time_mean'], yerr=[method_data['time_mean'] - method_data['time_min'], method_data['time_max'] - method_data['time_mean']], label=method, fmt='-o', color=color[data['method'].unique().tolist().index(method)])
        # print(method_data.columns) 
        ax.plot(method_data['file_size'], method_data['time_poly'], label=f'{method} poly {method_data["poly"].iloc[0]}', linestyle='--',
                color=color[data['method'].unique().tolist().index(method)])
    ax.set_xlabel('File size (MB)')
    ax.set_ylabel('Time (ms)')
    ax.legend()
    # add title
    plt.title('Time of processing for different 3DES methods')
    plt.tight_layout()
    # plt.show()
    plt.savefig('temp/plot.png')

