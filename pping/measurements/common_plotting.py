import numpy as np
import matplotlib.pyplot as plt

def get_n_groups(group_dfs):
    return len([group for group in group_dfs if group != "all"])

def auto_alpha(n):
    if n < 2:
        return 1.0
    return max(1/100, 1/1.03**n)


def plot_pergroup_timeseries(group_dfs, col, axes=None, max_groups=10,
                             normalize_all=True, print_stats=True,
                             stats_only_all="auto", grid=True, alpha="auto",
                             legend="auto", stat_kwargs=None, **kwargs):
    if axes is None:
        axes = plt.gca()

    norm = max(1, get_n_groups(group_dfs)) if normalize_all else 1

    many_groups = get_n_groups(group_dfs) > max_groups
    if stats_only_all == "auto":
        stats_only_all = many_groups
    if legend == "auto":
        legend = not many_groups
    if alpha == "auto":
        alpha = auto_alpha(get_n_groups(group_dfs))
        
    for group, data in group_dfs.items():
        if group == "all":
            axes.plot(data["timestamp"], data[col]/norm, label="average", 
                      color="k", linewidth=2, zorder=2.5)
        else:
            if many_groups:
                axes.plot(data["timestamp"], data[col], label=group, color="C0",
                          alpha=alpha, **kwargs)
            else:
                axes.plot(data["timestamp"], data[col], label=group, alpha=alpha,
                          **kwargs)
                
    axes.grid(grid)
    axes.set_xlabel("Time")
    if legend:
        axes.legend()
        
    if print_stats:
        stat_kws = {"loc":"top", "only_all":stats_only_all}
        if stat_kwargs is not None:
            stat_kws.update(stat_kwargs)

        plot_stats_table(group_dfs, col, axes=axes, **stat_kws)
        
    return axes

def plot_stats_table(group_dfs, col, axes=None, fmt="{:.3f}", only_all=False, **kwargs):
    if axes is None:
        axes = plt.gca()
        
    cols = ["min", "median", "mean", "max"]
    rows = []
    cells = []
    
    for group, df in group_dfs.items():
        if not only_all or group == "all":
            rows.append(group)
            cells.append([fmt.format(func(df[col].values))
                          for func in (np.amin, np.median, np.mean, np.max)])
            
    axes.table(cells, rowLabels=rows, colLabels=cols, **kwargs)
    return axes

def plot_cdf(x, axes=None, **kwargs):
    if axes is None:
        axes = plt.gca()
        
    x = np.sort(x)
    y = np.linspace(1/len(x), 1, len(x))
    axes.plot(x, y, **kwargs)
    
    axes.set_ylabel("CDF")
    axes.set_ylim(0, 1)
    return axes

def plot_pergroup_cdf(group_dfs, col, axes=None, normalize_all=True,
                      print_stats=False, stats_only_all=False, grid=True, 
                      legend=True, stat_kwargs=None, **kwargs):
    if axes is None:
        axes = plt.gca()

    norm = max(1, get_n_groups(group_dfs)) if normalize_all else 1
    
    for group, df in group_dfs.items():
        if group == "all":
            plot_cdf(df[col]/norm, axes=axes, label="average",
                     color="k", linewidth=2, zorder=2.5)
        else:
            plot_cdf(df[col], axes=axes, label=group, **kwargs)
            
    axes.grid(grid)
    if legend:
        axes.legend()
        
    if print_stats:
        default_kwargs = {"loc":"top"}
        if stat_kwargs is not None:
            default_kwargs.update(stat_kwargs)
            plot_stats_table(group_dfs, col, axes=axes, **stat_kwargs)
            
    return axes
