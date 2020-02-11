"""
*******************
*Copyright 2017, MapleLabs, All Rights Reserved.
*
********************
"""

import time

import requests

from stat_exporter.collectd_exporter import *


def push_collectd_configaration(success_config):
    error_msg = ''
    try:
        if success_config:
            conf_files = []
            for cfg in success_config:
                file_writer(cfg[0], cfg[1] + "\n")
                conf_files.append(cfg[0])

            insert_collectd_conf('python', conf_files)
            return True, error_msg

    except Exception as e:
        error_msg += "push configaration: "
        error_msg += str(e)
        logger.error(error_msg)
    return False, error_msg


def delete_collectd_config():
    error_msg = ''
    try:
        command = "ls " + CollectdPluginConfDir
        ret = run_command(command.split())
        for value in ret:
            filepath = CollectdPluginConfDir + os.path.sep + value
            file_delete(filepath)

        delete_collectd_conf()
        file_writer(CollectdData, json.dumps({}))
        delete_all_stats()
        return True, error_msg
    except Exception as e:
        error_msg += "delete config: "
        error_msg += str(e)
        logger.error(error_msg)
    return False, error_msg


def get_collectd_plugins_mapping():
    dirname, filename = os.path.split(os.path.abspath(__file__))
    file_name = os.path.join(dirname, CollectdPluginMappingFilePath)
    return read_yaml_file(file_name)


def get_supported_targets_mapping():
    dirname, filename = os.path.split(os.path.abspath(__file__))
    file_name = os.path.join(dirname, TargetMappingFilePath)
    return read_yaml_file(file_name)


def get_collectd_plugin_names(mapped_plugin=None):
    result = []
    mapping_list = get_collectd_plugins_mapping()
    if mapping_list:
        # mapping_list = json.loads(mapping_list)
        # plugin_mapping = mapping_list.get(PLUGINS, {})
        # print plugin_mapping
        if mapped_plugin is None:
            for i, v in mapping_list.items():
                # print i, v
                result.append(i)
                for p in v:
                    # print p
                    result.append(p["name"])
        else:
            for p in mapping_list.get(mapped_plugin, []):
                result.append(p["name"])
    return list(set(result))


def get_dest_filename(plugin):
    return os.path.join(CollectdPluginConfDir, plugin + EXTSN)


def change_fluentd_status(oper):
    logger.info("Change td-agent status, operation %s", oper)
    service = "td-agent"
    status = get_service_status(service)
    if status == -1:
        logger.warning("td-agent service not found, fluentd not installed")
    elif oper == "start":
        pid = get_process_id(service)
        if pid > 0:
            restart_service(service)
        else:
            start_service(service)
        time.sleep(1)
        pid = get_process_id(service)
        if pid <= 0:
            logger.error("Failed to start service %s", service)
    elif oper == "stop":
        stop_service(service)
        time.sleep(1)
        pid = get_process_id(service)
        if pid > 0:
            logger.error("Failed to stop service %s", service)
    elif oper == "restart":
        restart_service(service)
        time.sleep(1)
        pid = get_process_id(service)
        if pid <= 0:
            logger.error("Failed to restart service %s", service)
    else:
        logger.error("Undefined operation %s, start|stop|restart", oper)


def get_fluentd_status():
    service = "td-agent"
    status = get_service_status(service)
    if status == -1:
        return "NOT INSTALLED"
    if status == 1:
        return "RUNNING"
    elif status == 0:
        return "STOPPED"
    else:
        return "NOT RUNNING"


def get_fluentd_version():
    """
    Get collectd version
    :return:
    """
    # try:
    service = "td-agent"
    status = get_service_status(service)
    if status == -1:
        return "NOT INSTALLED"
    command = "td-agent --version | awk {'print $2'}"
    out, err = run_shell_command(command)
    if err:
        logger.warning("Failed to get output")
        return "UNKNOWN"
    if out.splitlines():
        for line in out.splitlines():
            line = str(line)
            if line and line[0].isdigit():
                return line
    return "UNKNOWN"


def start_collectd():
    truncate_collectd_logfile()
    service = "collectd"
    status = get_service_status(service)
    # pid = get_process_id(service)
    # if pid != -1:
    #     kill_process(pid)
    # command = COLLECTDBIN + " -C " + CollectdConfDir + "/collectd.conf"
    # out, err = run_shell_command(command)
    if status == 0:
        out, err = start_service(service)
    else:
        out, err = restart_service(service)

    #Attempting to get pid of collectd process for 3 times of every one second
    for i in range(0, 3):
        time.sleep(1)
        pid = get_process_id(service)
        if pid != -1:
            break
    pid = get_process_id(service)

    #If collectd process not get started, restart collectd service
    if pid == -1:
        # command = COLLECTDBIN + " -C " + CollectdConfDir + "/collectd.conf"
        out, err = restart_service(service)
    if err:
        logger.warning("Failed to start collectd" + str(err))


def stop_collectd():
    # command = "service collectd stop".split()
    # for line in run_command(command):
    #     print (line)
    logger.info("Stop collectd")
    service = "collectd"
    # status = get_service_status(service)
    # if status == 1:
    stop_service(service)
    time.sleep(1)
    pid = get_process_id(service)
    if pid != -1:
        logger.info("Failed to stop collectd")
        # kill_process(pid)


def get_collectd_status():
    service = "collectd"
    # status = get_service_status(service)
    pid = get_process_id(service)
    status = -1
    if pid != -1:
        status = 1
    if status == 1:
        return "RUNNING"
    elif status == 0:
        return "STOPPED"
    else:
        return "NOT RUNNING"


def get_collectd_version():
    """
    Get collectd version
    :return:
    """
    # try:
    command = COLLECTDBIN + " -help | grep ^collectd | awk {'print $2'}"
    out, err = run_shell_command(command)
    if err:
        logger.warning("Failed to get output")
        return "UNKNOWN"
    if out.splitlines():
        for line in out.splitlines():
            line = str(line)
            if line and line[0].isdigit():
                return line[0:5]
    return "UNKNOWN"


def insert_collectd_conf(loadplugin, conf_file=None):
    if conf_file is None:
        conf_file = []
    collectd_conf = CollectdConfDir + os.path.sep + 'collectd.conf'
    data = None
    try:
        f = open(collectd_conf, "r")
        data = f.readlines()
        f.close()
    except:
        logger.error("Error in %s File Reading ", collectd_conf)
    loadplugin = "LoadPlugin " + loadplugin + "\n"
    if data:
        new_data = [loadplugin]
        for f in conf_file:
            addconf = "Include \"" + f + "\"\n"
            new_data.append(addconf)
        for line in data:
            if line.startswith(loadplugin) or line.startswith("Include "):
                continue
            else:
                new_data.append(line)

        # Write configuration to file
        f = open(collectd_conf, 'w')
        f.write(''.join(new_data))
        f.close()


def delete_collectd_conf():
    collectd_conf = CollectdConfDir + os.path.sep + 'collectd.conf'
    data = None
    try:
        f = open(collectd_conf, "r")
        data = f.readlines()
        f.close()
    except:
        logger.error("Error in %s File Reading ", collectd_conf)

    # addconf = "Include \"" + filepath + "\"\n"

    if data:
        new_data = []
        for line in data:
            if line.startswith("Include "):
                continue
            else:
                new_data.append(line)

        # Write configuration to file
        f = open(collectd_conf, 'w')
        f.write(''.join(new_data))
        f.close()


def get_fluentd_plugins_mapping():
    dirname, filename = os.path.split(os.path.abspath(__file__))
    file_name = os.path.join(dirname, FluentdPluginMappingFilePath)
    return read_yaml_file(file_name)
    # return read_yaml_file(FluentdPluginMappingFilePath)


def get_fluentd_plugins_components_mapping():
    plugin_mapping = get_fluentd_plugins_mapping()
    n_plugins = dict()
    for plugin_name, plugin_comps in plugin_mapping.items():
        if isinstance(plugin_comps, dict):
            for comp_name, comp_config in plugin_comps.items():
                n_plugins[plugin_name + '-' + comp_name] = comp_config
    logger.info("Converted plugin mapping %s" % json.dumps(n_plugins))
    return n_plugins


def delete_fluentd_config():
    logger.info("Delete existing fluentd config")
    error_msg = ''
    fluentd_conf_dir = FluentdPluginConfDir + os.path.sep
    try:
        exsting_data = file_reader(FluentdData)
        if exsting_data:
            exsting_data = json.loads(exsting_data)
        else:
            exsting_data = {}
        if PLUGINS in exsting_data:
            for x_plugin in exsting_data[PLUGINS]:
                if NAME in x_plugin:
                    fluentd_conf_filepath = fluentd_conf_dir + x_plugin[NAME]
                    command = "rm -rf " + fluentd_conf_filepath
                    out, err = run_shell_command(command)
                    if err:
                        msg = "Failed to Delete Fluentd conf file " + fluentd_conf_filepath
                        logger.warning(msg)

            fluentd_conf_filepath = fluentd_conf_dir + "td-agent.conf"
            command = "rm -rf " + fluentd_conf_filepath
            out, err = run_shell_command(command)
            if err:
                msg = "Failed to Delete Fluentd conf file " + fluentd_conf_filepath
                logger.warning(msg)
        logger.info("Successfully deleted old fluentd config")
        return True, error_msg

    except Exception as e:
        error_msg += "delete fluentd config: "
        error_msg += str(e)
        logger.error(error_msg)
    return False, error_msg


def write_to_elasticsearch(host, port, index, type, data):
    '''
    Post the Data to Elastic_search
    '''
    url = "http://{0}:{1}/{2}/{3}".format(host, port, index, type)
    headers = {'content-type': 'application/json'}
    hostname = get_hostname()
    data['hostName'] = hostname
    # print json.dumps(data)
    try:
        r = requests.post(url, data=json.dumps(data),
                          headers=headers, timeout=30)
    except Exception as e:
        logger.error("write_to_elastic() error: %s" % str(e))


# def write_in_elasticsearch(host, port, index, type, data):
#     try:
#         es = Elasticsearch([{'host': host, 'port': port}])
#         r = requests.get('http://{0}:{1}'.format(host, port), timeout=10)
#         hostname = get_hostname()
#         data['hostName'] = hostname
#         if r.status_code == 200:
#             es.index(index=index, doc_type=type, body=data)
#     except Exception as e:
#         logger.error("write_in_elasticsearch error: %s" % str(e))

def truncate_collectd_logfile():
    log_path = "/opt/sfapm/collectd.log"
    print "truncate the file {0}".format(log_path)
    try:
        with open(log_path, "r+") as f:
            # line = f.read()
            f.seek(0)
            f.truncate()
    except:
        print "failed to truncate the file {0}".format(log_path)


def set_log_file_permission(filepath, permission):
    dirs = list_dirs(filepath.strip())
    for dir in reversed(dirs):
        cmd = 'chmod {0} {1}'.format(permission, dir)
        run_shell_command(cmd)


def list_dirs(path):
    dirs = [path]
    if not os.path.isfile(path):
        return []
    while True:
        path, tail = os.path.split(path)
        if path == '/' or path == '/var/log':
            break
        dirs.append(path)

    return dirs
