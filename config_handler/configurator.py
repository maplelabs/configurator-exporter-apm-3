"""
*******************
*Copyright 2017, MapleLabs, All Rights Reserved.
*
********************
"""

from threading import Timer

from config_handler import collectd_manager
from config_handler import fluentd_manager
from config_util import *
from elasticsearch import Elasticsearch, RequestsHttpConnection
import base64

CONFIG_WRITE_INTERVAL = 300
timer = None


def set_collectd_config(metrics):
    """
    API endpoint for configuring metrics config
    :param metrics:
    :return:
    """
    create_plugin_env()
    return_dict = {}
    stop_collectd()
    if metrics:
        collector_obj = collectd_manager.CollectdManager(metrics)
        success, return_dict = collector_obj.set_config()
    else:
        delete_collectd_config()
    if ERROR not in return_dict:
        return_dict[COLLECTD_STATUS] = get_collectd_process()
    return return_dict


def get_collectd_config():
    """
    API endpoint for get config from collectd
    :return:
    """
    exsting_data = file_reader(CollectdData)
    if exsting_data:
        exsting_data = json.loads(exsting_data)
        exsting_data[COLLECTD_STATUS] = get_collectd_process()
    else:
        exsting_data = {}
    return exsting_data


def enabled_collectd(data):
    """
    API endpoint for enable or disable collectd process
    :param data:
    :return:
    """
    if data[ENABLED]:
        start_collectd()
        result = get_collectd_status()

    else:
        stop_collectd()
        result = get_collectd_status()

    return result


def get_collectd_process():
    """
    API endpoint for get collectd status
    :return:
    """
    #return {COLLECTD_SERVICE: get_collectd_status(), VERSION: get_collectd_version()}
    return {COLLECTD_SERVICE: get_collectd_status()}


def enabled_fluentd(data):
    """
    API endpoint for enable or disable fluentd process
    :param data:
    :return:
    """
    if data[ENABLED]:
        change_fluentd_status("start")
        result = get_fluentd_status()

    else:
        change_fluentd_status("stop")
        result = get_fluentd_status()

    return result


def get_fluentd_process():
    """
    API endpoint for get fluentd status
    :return:
    """
    #return {FLUENTD_SERVICE: get_fluentd_status(), VERSION: get_fluentd_version()}
    return {FLUENTD_SERVICE: get_fluentd_status()}


def set_fluentd_config(logging):
    """
    API endpoint for configuring logging config
    :param logging:
    :return:
    """
    return_dict = {}
    change_fluentd_status(STOP)
    if logging:
        obj = fluentd_manager.FluentdPluginManager(logging)
        return_dict = obj.set_config()
    else:
        delete_fluentd_config()
    if ERROR not in return_dict:
        return_dict[FLUENTD_STATUS] = get_fluentd_process()
    # collector_obj = collectd_manager.CollectdManager(logging)
    # success, return_dict = collector_obj.set_config()
    return return_dict


def get_fluentd_config():
    exsting_data = file_reader(FluentdData)
    if exsting_data:
        exsting_data = json.loads(exsting_data)
        exsting_data[FLUENTD_STATUS] = get_fluentd_process()
    else:
        exsting_data = {}
    return exsting_data


def get_supported_metrics_plugins():
    mapping_list = get_collectd_plugins_mapping()
    result = []
    for key in mapping_list:
        result.append(key)
    return result


def get_supported_logging_plugins():
    mapping_list = get_fluentd_plugins_mapping()
    result = []
    for key in mapping_list:
        if key == 'default_flush_interval':
            continue
        result.append(key)
    return result


def get_supported_targets():
    mapping_list = get_supported_targets_mapping()
    result = []
    for key in mapping_list:
        result.append(key)
    return result


def get_targets_params(targets=None):
    if targets is None:
        targets = []
    mapping_list = get_supported_targets_mapping()
    result = []
    for key, value in mapping_list.items():
        if targets and key not in targets:
            continue
        result.append(value)
    return result


def get_metrics_plugins_params(plugins=None):
    """
    Get the names of plugin and configurable parameters
    :param plugins:
    :return:
    """
    if plugins is None:
        plugins = []
    result = {PLUGINS: []}
    mapping_list = get_collectd_plugins_mapping()
    for name, value in mapping_list.items():
        if plugins and name not in plugins:
            continue
        data = {NAME: name}
        config_data = []
        for v in value:
            try:
                for item in v.get(CONFIG_DATA):
                    config_data.append(item)
            except:
                logger.info("No config data is present for %s" %(v.get("name")))
        if config_data:
            data[CONFIG_DATA] = config_data
        result[PLUGINS].append(data)
    return result


def get_logging_plugins_params(plugins=None):
    if plugins is None:
        plugins = []
    result = {PLUGINS: []}
    for i in get_supported_logging_plugins():
        if plugins and i not in plugins:
            continue
        result[PLUGINS].append({NAME: i, "config": {"components": [{"name": "Name of the component", "filter": {}}]}})

    return result


def map_local_targets(targets, data):
    n_targets = list()
    if TARGETS in data:
        for l_targets in data[TARGETS]:
            for g_targets in targets:
                if l_targets == g_targets.get(NAME):
                    if CONFIG in g_targets:
                        g_targets.update(g_targets[CONFIG])
                        g_targets.pop(CONFIG)
                    g_targets = dict((str(k), str(v)) for k, v in g_targets.items())
                    n_targets.append(g_targets)
    if not n_targets:
        logger.info("local targets list is not matching with Global Targets")
    data[TARGETS] = n_targets
    return data


def write_config_to_target(es_config, interval=CONFIG_WRITE_INTERVAL):
    # print json.dumps(es_config), interval
    truncate_collectd_logfile()
    global timer
    # es_config = dict()
    data = dict()
    # for target in targets:
    #     if target[TYPE] == ELASTICSEARCH:
    #         es_config = target[CONFIG]
    host = es_config.get(HOST)
    port = es_config.get(PORT)
    index = es_config.get(INDEX)
    if host and port and index:
        type = DOCUMENT
        data[METRICS] = get_collectd_config()
        data[LOGGING] = get_fluentd_config()
        data[PLUGIN] = HEARTBEAT
        try:
            if timer:
                timer.cancel()
                timer = None
                write_to_elasticsearch(host=host, port=port, index=index, type=type, data=data)

            timer = Timer(interval, write_config_to_target, [es_config, interval])
            timer.start()
        except Exception as e:
            logger.error("Write Config to Target failed, Error: {0}\n".format(str(e)))


def get_target_status():
    target_status = []
    target_details = {}
    try:
        exsting_data = file_reader(CollectdData)
        collectd_exsting_data = json.loads(exsting_data)
        if collectd_exsting_data:
            for target in collectd_exsting_data['targets']:
                target_details["name"] = target["name"]
                target_details["index"] = target["index"]
                es_username = ''
                es_password = ''
                if "password" in target and target["password"]:
                    es_password = target["password"]
                if "username" in target and target["username"]:
                    es_username = target["username"]
                if "protocol" in target and target["protocol"]:
                    es_protocol = target["protocol"]
                else:
                    es_protocol = 'http'
                target_details["status"] = get_elasticsearch_status(target["host"], target["index"], target["port"], es_protocol, es_username, es_password)
                target_details["type"] = "collectd"
                target_status.append(target_details)
        else:
            logger.error("No workload data found in collectd_data.json")
        target_details = {}
        exsting_data = file_reader(FluentdData)
        fluent_exsting_data = json.loads(exsting_data)
        if fluent_exsting_data:
            for target in fluent_exsting_data['targets']:
                target_details = {}
                target_details["name"] = target["name"]
                target_details["index"] = target["index"]
                es_username = ''
                es_password = ''
                if "password" in target and target["password"]:
                    es_password = target["password"]
                if "username" in target and target["username"]:
                    es_username = target["username"]
                if "protocol" in target and target["protocol"]:
                    es_protocol = target["protocol"]
                else:
                    es_protocol = 'http'
                target_details["status"] = get_elasticsearch_status(target["host"], target["index"], target["port"], es_protocol, es_username, es_password)
                target_details["type"] = "fluentd"
                if 'store_type' in target and target['store_type'] == 'metric':
                    target_details["store_type"] = "metric"
                else:
                    target_details["store_type"] = "logger"
                target_status.append(target_details)
        else:
            logger.error("No workload data found in fluentd_data.json")

    except Exception as e:
        logger.error("Exception in getting target status due to %s" % str(e))
    return target_status

def get_elasticsearch_status(host, index, port, protocol='http', username='', password=''):
    logger.info("Collecting elasticsearch status for the host %s for index %s" % (host, index))
    connections = "{}://{}:{}".format(protocol, str(host), str(port))
    if password:
        password = base64.b64decode(password)
    elastic_search = Elasticsearch([connections], verify_certs=False, connection_class=RequestsHttpConnection, http_auth=(username, password))
    try:
        index_alias = elastic_search.indices.get_alias(index + "_write")
    except Exception as err:
        #logger.error("Restarting configurator service due to error in getting alias of index %s" % (index))
        #service = 'configurator'
        #restart_service(service)
        #try:
        #    index_alias = elastic_search.indices.get_alias(index + "_write")
        #except Exception as e:
        logger.error("Elasticsearch error in getting alias of the index %s due to  %s" % (index, str(err)))
        return "STOPPED"

    current_index = index_alias.keys()[0]
    try:
        resp = elastic_search.indices.get_settings(current_index)
    except Exception as e:
        logger.error("Elasticsearch error in getting settings of the index %s due to  %s" % (current_index, str(e)))
        return "STOPPED"

    if resp:
        try:
            settings_details = resp[current_index]['settings']['index'].get('blocks')
        except Exception as e:
            logger.error("Elasticsearch error of host %s in index %s due to %s" % (host, current_index, str(e)))
            return "STOPPED"
        
        if settings_details:
            read_only_allow_delete = settings_details.get('read_only_allow_delete', 'false')
            if read_only_allow_delete == 'false':
                return "RUNNING"
            else:
                logger.error("Elasticsearch error. Read_only_allow_delete flag set to %s" % read_only_allow_delete)
                return "STOPPED"
        else:
            return "RUNNING"
    else:
        return "STOPPED"
