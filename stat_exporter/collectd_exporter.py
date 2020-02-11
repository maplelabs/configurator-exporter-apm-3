"""
*******************
*Copyright 2017, MapleLabs, All Rights Reserved.
*
********************
"""

# from config_handler.collectd_manager import *
from common.util import *
# STATS_ROOTDIR = "/opt/collectd/var/lib/"
STATS_INDEX_FILE = "index.txt"

logger = expoter_logging(COLLECTD_MGR)


def get_file_list(num_samples, last_index, max_entries):
    file_list = []
    if num_samples > max_entries:
        count = max_entries
    else:
        count = num_samples
    while count > 0:
        if last_index < 0:
            last_index = max_entries - 1
        file_list.append(str(last_index % max_entries) + ".txt")
        last_index -= 1
        count -= 1
    return file_list


def get_list(num_samples, path):
    file_list = []
    value_list = []
    index_path = os.path.join(path, STATS_INDEX_FILE)
    # print index_path
    try:
        with open(index_path, "r") as fh:
            last_index = int(fh.readline())
            max_entries = int(fh.readline())
    except:
        return value_list
    file_list = get_file_list(num_samples, last_index, max_entries)
    # print file_list
    for file_name in file_list:
        fpath = os.path.join(path, file_name)
        if not os.path.exists(fpath):
            continue
        try:
            with open(fpath, "r") as fh:
                value_list.append(json.loads(fh.readline()))
        except:
            pass

    return value_list


def get_elem(index, list_elem):
    if index >= len(list_elem):
        return None
    else:
        return list_elem[index]


def get_val_list(data, index):
    # print data, index
    val_list = []
    for key, value in data.items():
        elem = get_elem(index, value)
        if elem is not None:
            val_list.append(elem)
    return val_list


def merge_data(data, index):
    value_dict = {}
    value_list = []
    for key, value in data.items():
        # print key, value
        # print "*" * 20
        if isinstance(value, dict):
            value_dict[key] = merge_data(value, index)
            # print value_dict
            # print "*" * 20
        else:
            value_list = get_val_list(data, index)
            # print value_list
            return value_list
    return value_dict


def get_merged_data(data_dict, num_samples):
    data_list = []
    for index in range(0, num_samples):
        data = merge_data(data_dict, index)
        data_list.append(data)
    return data_list


def traverse(num_samples, root, match, depth):
    values_dict = {}
    for entry in os.listdir(root):
        path = os.path.join(root, entry)
        if os.path.isdir(path):
            if ALL in match[depth] or entry.replace("_", '').lower() in match[depth]:
                depth += 1
                values_dict[entry] = traverse(num_samples, path, match, depth)
                depth -= 1
        else:
            value_list = get_list(num_samples, root)
            return value_list
    return values_dict


def get_plugin_data(rootdir, num_samples, plugins, plugin_instances):
    match = [plugins, plugin_instances]
    data = traverse(num_samples, rootdir, match, depth=0)
    return data


def get_stats_dir():
    # return STATS_ROOTDIR
    return STATS_DATADIR


# def get_data(num_samples=1, plugins=None, plugin_instances=None):
#     if plugin_instances is None:
#         plugin_instances = [ALL]
#     if plugins is None:
#         plugins = [ALL]
#     hostname = platform.node()
#     rootdir = os.path.join(get_root_dir(), hostname)
#     try:
#         data = get_plugin_data(rootdir, num_samples, plugins, plugin_instances)
#         # print data
#         data = get_merged_data(data, num_samples)
#     except:
#         data = {}
#     # data = {hostname:data}
#     return data

def get_data(num_samples=1, plugins=None, plugin_instances=None):
    multi_plugins = ["linux", "redisdb", "mysql", "jvm", "tpcc", "tomcat", "haproxy", "elasticsearchagent", "postgres", "oozie","yarn","namenode","kafkatopic", "kafkajmx", "zookeeperjmx", "apache", "topstats", "nginx", "nginxplus", "cassandra", "hxconnect", "esalogstore", "spark","mongod", "nodejs", "nodejsapi"]
    if plugin_instances is None:
        plugin_instances = [ALL]
    if plugins is None:
        plugins = [ALL]
    # rootdir = os.path.join(get_root_dir(), STATSDIR)
    try:
        data = get_plugin_data(get_stats_dir(), num_samples, plugins, plugin_instances)
        if any(x in multi_plugins for x in plugins):
            data = get_merged_data(data, num_samples)
        else:
            data = [data]
    except:
        data = {}
    # data = {hostname:data}
    return data


def delete_all_stats():
    # hostname = platform.node()
    # rootdir = os.path.join(get_root_dir(), STATSDIR)
    command = "rm -rf " + get_stats_dir()
    run_command(command.split())

# get_data(num_samples=10, plugins=["nic_stats"], plugin_instances=["eth0"])
