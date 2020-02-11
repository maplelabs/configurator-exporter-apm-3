"""
*******************
*Copyright 2017, MapleLabs, All Rights Reserved.
*
********************
"""
import os
import subprocess
import re
import psutil
from config_handler import configurator
import json
import socket
import yaml
from common.util import *

logger = expoter_logging(COLLECTD_MGR)
JCMD_PID_DICT = dict()

USER_SERVICES = list()

# with open("/opt/configurator-exporter/service_discovery/service_port_mapping.json", "r") as disc_file:
#    DISCOVERY_RULES = json.loads(disc_file.read())
#for service in DISCOVERY_RULES['services']:
#    USER_SERVICES.append(service['name'])

DISCOVERY_RULES = {}
SERVICE_PORT_MAPPING = {}
PROMETHEUS_SERVICES = {
    'node-exporter': 9100,
    'mysql-exporter': 9104,
    'redis-exporter': 9121,
    'jmx-exporter': 9404,
    'elasticsearch-exporter': 9206,
    'apache-exporter': 9117,
    'postgres-exporter': 9187,
    'nginx-exporter': 9113,
    'jmeter-exporter': 9270
}
# for service in DISCOVERY_RULES['services']:
#    if re.search('exporter', service['name']):
#        PROMETHEUS_SERVICES[service['name']] = service['port']
#    else:
#        SERVICE_PORT_MAPPING[service['name']] = service['port']

SERVICE_NAME = {
    "topstats": "linux",
    "elasticsearch": "ES",
    "apache": "apache",
    "tomcat": "tomcat",
    "haproxy": "haproxy",
    "mysql": "mysql",
    "mongod" : "mongod",
    "mssql": "mssql",
    "postgres": "postgres",
    "nginx": "nginx",
    "tpcc": "tpcc",
    "kafka.Kafka": "kafka",
    "kafkajmx": "kafka",
    "zookeeper": "zookeeper",
    "hxconnect": "hxconnect",
    "cassandra": "cassandra",
    "esalogstore": "ESAlogstore",
    "redis": "redis",
    "oozie": "oozie",
    "yarn": "yarn",
    "hdfs": "hdfs",
    "spark2": "spark2",
    "jvm": "JMX",
    "jmeter": "jmeter",
    "node-exporter": "linux",
    "mysql-exporter": "mysql",
    "jmx-exporter": "JMX",
    "redis-exporter": "redis",
    "apache-exporter": "apache",
    "elasticsearch-exporter": "elasticsearch",
    "nginx-exporter": "nginx",
    "jmeter-exporter": "jmeter",
    "nodejs" : "node",
    "nodejsapi": "node"
}
SERVICES = [
    "elasticsearch",
    "apache",
    "tomcat",
    "haproxy",
    "redis",
    "mysql",
    "mongod",
    "mssql",
    "postgres",
    "nginx",
    "tpcc",
    "kafka.Kafka",
    "zookeeper",
    "hxconnect",
    "cassandra",
    "esalogstore",
    "jvm",
    "jmeter",
    "node"
]
'''
Mapping for services and the plugin to be configured for them.
'''
SERVICE_PLUGIN_MAPPING = {
    "topstats": "topstats",
    "elasticsearch": "elasticsearchagent",
    "apache": "apache",
    "tomcat": "tomcat",
    "haproxy": "haproxy",
    "redis": "redisdb",
    "mysql": "mysql",
    "mongod": "mongod",
    "mssql": "mssql",
    "postgres": "postgres",
    "nginx": "nginx",
    "tpcc": "tpcc",
    "kafka.Kafka": "kafkatopic",
    "kafkajmx": "kafkajmx",
    "zookeeper": "zookeeperjmx",
    "hxconnect": "hxconnect",
    "cassandra": "cassandra",
    "oozie": "oozie",
    "yarn": "yarn",
    "hdfs": "namenode",
    "spark2": "spark",
    "jvm": "jvm",
    "jmeter": "jmeter",
    "node-exporter": "prometheuslinux",
    "redis-exporter": "prometheusredis",
    "elasticsearch-exporter": "prometheuselasticsearch",
    "postgres-exporter": "prometheuspostgres",
    "mysql-exporter": "prometheusmysql",
    "jmx-exporter": "prometheusjmx",
    "apache-exporter": "prometheusapache",
    "nginx-exporter": "prometheusnginx",
    "jmeter-exporter": "prometheusjmeter",
    "nodejs": "nodejs",
    "nodejsapi": "nodejsapi"
}
POLLER_PLUGIN = ["elasticsearch"]
JMX_PLUGINS = ["kafka.Kafka", "zookeeper"]
JVM_ENABLED_PLUGINS = ["kafka.Kafka", "zookeeper", "elasticsearch", "tomcat"]
HADOOP_SERVICE = {
    "yarn-rm-log": { \
         "service-name": "org.apache.hadoop.yarn.server.resourcemanager.ResourceManager",
         "service-list": ["yarn-rm", "yarn-audit"],
         "plugin_name": "yarn"
                   },
    "yarn-timeline-server": { \
         "service-name": "org.apache.hadoop.yarn.server.applicationhistoryservice.ApplicationHistoryServer",
         "service-list": ["yarn-timeline"],
         "plugin_name": "yarn"
                            },
    "hdfs-namenode": { \
         "service-name": "org.apache.hadoop.hdfs.server.namenode.NameNode",
         "service-list": ["hdfs-namenode", "hdfs-audit", "hdfs-gc", "hdfs-zkfc-manager"],
         "plugin_name": "hdfs"
                     },
    "hdfs-journalnode": { \
         "service-name": "org.apache.hadoop.hdfs.qjournal.server.JournalNode",
         "service-list": ["hdfs-journalnode", "hdfs-gc", "hdfs-journalnode-manager"],
         "plugin_name": "hdfs"
                        },
    "oozie-server": { \
         "service-name": "oozie-server",
         "service-list": ["oozie-ops", "oozie-audit", "oozie-error-logs", "oozie-logs", "oozie-instrumentation", "oozie-jpa"],
         "plugin_name": "oozie"
                    },
    "hdfs-datanode": { \
         "service-name": "org.apache.hadoop.hdfs.server.datanode.DataNode",
         "service-list": ["hdfs-datanode"],
         "plugin_name": "hdfs"
                     }
}

'''
Java services. Format for dictionary is 
service_name: key string to search in ps cmdline
'''
JAVA_SERVICES = {
    "tomcat": "org.apache.catalina.startup.Bootstrap",
    "elasticsearch": "org.elasticsearch.bootstrap.Elasticsearch",
    "cassandra": "org.apache.cassandra",
    "kafka.Kafka": "kafka.Kafka",
    "zookeeper": "org.apache.zookeeper.server.quorum.QuorumPeerMain",
    "jmeter": "ApacheJMeter.jar"
}
DIFF_NAME_SERVICES = {
    "apache": ["httpd", "apache2"],
    "postgres": ["postmaster", "postgres"]
}
CUSTOM_SERVICES = ["tpcc", "esalogstore", "hxconnect"]


def connect_to_port(port):
    address = "127.0.0.1"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((address, port))
        logger.info("Port %s is listening" %str(port))
        s.close()
        return True
    except socket.error, err:
        logger.info("Port %s is not listening", str(port))
        return False


def discover_custom_services(service):
    if (service == "tpcc" and os.path.exists("/opt/VDriver/.tpcc_discovery")) or \
            (service == "hxconnect" and os.path.exists("/opt/VDriver/.hxconnect_discovery")):
        return "agent"

    elif service == "esalogstore" and os.path.exists("/opt/esa_conf.json"):
        return "logger"
    return ""

def discover_log_path():
    try:
        with open("/usr/lib/systemd/system/elasticsearch.service") as fp:
            for line in fp:
                if "ES_PATH_CONF" in line:
                    es_path = line.splitlines()[0].split('=')[2]
                    with open(es_path+"/elasticsearch.yml") as es_fp:
                        esconf = yaml.load(es_fp)
                        esconf_keys = esconf.keys()
                        if "path" in esconf_keys:
                            log_path = esconf["path"]["logs"]
                        else:
                            log_path = esconf["path.logs"]

                        if "cluster" in esconf_keys:
                            log_name = esconf["cluster"]["name"]
                        elif "cluster.name" in esconf_keys:
                            log_name = esconf["cluster.name"]
                        else:
                            log_name = "elasticsearch"
                    break

    except:
        return
    log_file = log_path+"/"+log_name+".log"
    with open("/opt/sfapm/configurator-exporter/config_handler/mapping/logging_plugins_mapping.yaml") as f:
        log_conf = yaml.load(f)
    log_conf["elasticsearch-general"]["source"]["path"] = log_file

    with open("/opt/sfapm/configurator-exporter/config_handler/mapping/logging_plugins_mapping.yaml", "w") as f:
        yaml.dump(log_conf, f)

def check_jmx_enabled(pid):
    """Check if jmx enabled for java process"""
    pid_detail = psutil.Process(pid)
    if re.search("Dcom.sun.management.jmxremote", str(pid_detail.cmdline())):
        return True
    return False


def get_jcmd_result():
    pid = ""
    try:
        res = exec_subprocess("sudo jcmd | grep -v 'sun.tools.jcmd'")
        if res:
            print "Sendind pid for jcmd"
            for process in res.splitlines():
                return process.split()[0]
        return ""
    except Exception as err:
	logger.error("Error in getting jcmd command output")


def get_process_id(service):
    '''
    :param service: name of the service
    :return: return a list of PID's assosciated with the service
    '''
    logger.info("Get process id for service %s", service)
    process_id = ""
    try:
        for proc in psutil.process_iter(attrs=['pid', 'name', 'username', 'cmdline']):
            # Java processes
            if service in JAVA_SERVICES:
                if proc.info.get("name") == "java" and JAVA_SERVICES[service] in proc.info.get("cmdline"):
                    process_id = proc.info.get("pid")
                    if service in JMX_PLUGINS and not check_jmx_enabled(process_id):
                        process_id = ""
                    break
            if service == "jmeter":
                if proc.info.get("name") == "java":
                    for cmnd in proc.info.get("cmdline"):
                        if re.search(JAVA_SERVICES[service], cmnd):
                            process_id = proc.info.get("pid")
                            break
                    if service in JMX_PLUGINS and not check_jmx_enabled(process_id):
                        process_id = ""
                        break


            # Processes with varying names
            elif service in DIFF_NAME_SERVICES:
                for name in DIFF_NAME_SERVICES[service]:
                    if name in str(proc.info.get("name")):
                        process_id = proc.info.get("pid")
                        break

            # Non java processes
            elif service in str(proc.info.get("name")):
                process_id = proc.info.get("pid")
                break

	if service == "jvm":
	    process_id = get_jcmd_result()

        ## add_pid_usage(process_id, pids)
        logger.info("PID %s", process_id)
        return process_id
    except BaseException:
        logger.info("PID %s", process_id)
        return process_id


def get_hadoop_pid(service):
    '''
        :param service: name of the service
        :return: return a list of PID's assosciated with the service
        '''
    logger.info("Get process id for service %s", service)
    process_id = ""
    try:
        for proc in psutil.process_iter(attrs=['pid', 'name', 'username', 'cmdline']):
            if service in proc.info.get("cmdline"):
                process_id = proc.info.get("pid")
                break
        return process_id
    except BaseException:
        logger.info("PID %s", process_id)
        return process_id


def exec_subprocess(cmd):
    """ execute subprocess cmd """
    cmd_output = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    res, err = cmd_output.communicate()
    return res


def check_nginx_plus():
    """ check nginx plus service  """
    logger.error('new in check condition')
    res = exec_subprocess("service nginx status")
    return res and 'Plus' in res.splitlines()[0]


def add_ports(pid, service):
    '''
    Add listening ports for the PID
    :param dict: dictionary returned by add_status
    :param service: name of the service
    :return: add listening ports for the PID to the dictionary
    '''
    #logger.debug("Add ports %s %s", service_dict, service)
    ports = []
    cmd = "netstat -anp | grep httpd"

    out = exec_subprocess("lsb_release -d")
    for line in out.splitlines():
        if "Ubuntu" in line:
            cmd = "netstat -anp | grep apache2"
            break

    out = exec_subprocess(cmd)
    for line in out.splitlines():
        line = line.split()
        if (line[5] == 'LISTEN') and (service == "apache" or str(pid) in line[6]):
            port = (line[3].split(':')[-1])
            if port not in ports:
                ports.append(port)
    return ports


def add_agent_config(service, service_dict=None):
    '''
    Find the input config for the plugin fieldname:defaultvalue
    :param service: name of the service
    :param dict: poller_dict as the input
    :return:
    '''
    if not service_dict:
        service_dict = dict()
    service_dict["agentConfig"] = {}
    agent_config = {}
    agent_config["config"] = {}
    for key, value in SERVICE_PLUGIN_MAPPING.items():
        if key == service:
            agent_config["name"] = value
            break
    config = configurator.get_metrics_plugins_params(agent_config["name"])
    for item in config["plugins"]:
        if item.get("config") and item.get("name") == agent_config["name"]:
            if agent_config["name"] == "kafkatopic":
                agent_config["config"]["process"] = service
                for parameter in item["config"]:
                    agent_config["config"][parameter["fieldName"]] = parameter["defaultValue"]
                break
            for parameter in item["config"]:
                agent_config["config"][parameter["fieldName"]] = parameter["defaultValue"]

    # In apache plugin replace the port default value with the listening ports for apache/httpd,
    # if there are multiple listening ports for the PID assosciate the first
    # port with the PID
    if service == "apache":
        if service_dict["ports"]:
            agent_config["config"]["port"] = service_dict["ports"][0]
            if agent_config["config"]["port"] == "443":
                agent_config["config"]["secure"] = "true"
    # topstats agent plugin is on demand (only explicit operations i.e. start/stop is allowed)
    # topstats plugin start/stop is not part of bulk operation
    elif service == "topstats":
        service_dict["agentConfig"]["on_demand"] = True
    else:
        service_dict["agentConfig"]["on_demand"] = False

    service_dict["agentConfig"].update(agent_config)
    logger.debug("Returning add_agent_config with {0}".format(service_dict))
    return service_dict


def add_poller_config(service, service_dict):
    '''
    Add poller config
    '''
    service_dict["pollerConfig"] = {}
    poller_config = {}
    poller_config["config"] = {}

    for key, value in SERVICE_PLUGIN_MAPPING.items():
        if key == service:
            poller_config["name"] = value
            break

    config = configurator.get_metrics_plugins_params(poller_config["name"])
    for item in config["plugins"]:
        if item.get("config") and item.get("name") == poller_config["name"]:
            for item1 in item["config"]:
                poller_config["config"][item1["fieldName"]] = item1["defaultValue"]
    service_dict["pollerConfig"].update(poller_config)

    return service_dict


def add_logger_config(service_dict, service):
    '''
    Add logger config
    '''
    discover_log_path()
    log_mapping = configurator.get_fluentd_plugins_mapping()
    service_dict["loggerConfig"] = []
    for item, value in configurator.get_fluentd_plugins_mapping().iteritems():
        if item.startswith(service.split(".")[0]):
            log_config = {}
            log_config["name"] = item
            log_config["recommend"] = True
            log_config["selected"] = True
            if 'collection_type' in value and value['collection_type'] == 'metric':
                log_config['fluentd_type'] = "fluentd_agent"
            else:
                log_config['fluentd_type'] = "fluentd_logging"
            log_config["config"] = {}
            log_config["config"]["filters"] = {}
            log_config["config"]["log_paths"] = log_mapping[item]["source"]["path"]
            service_dict["loggerConfig"].append(log_config)
    return service_dict


def discover_hadoop_services():
    hadoop_discovery = {}
    hadoop_logger = dict()
    hadoop_agent = dict()
    for service_name in HADOOP_SERVICE.keys():
        if get_hadoop_pid(HADOOP_SERVICE[service_name]["service-name"]):
            logger.info("Hadoop service %s" % service_name)
            plugin_name = HADOOP_SERVICE[service_name]['plugin_name']
            for service in HADOOP_SERVICE[service_name]['service-list']:
                logger.info("service detail: {}".format(service))
                logger_dict = dict()
                logger_dict = add_logger_config(logger_dict, service)
                if not logger_dict:
                    continue
                if plugin_name not in hadoop_logger:
                    hadoop_logger[plugin_name] = list()
                hadoop_logger[plugin_name].append(logger_dict)
        logger.info("hadoop loggers {0}".format(hadoop_logger))

        if get_hadoop_pid("org.apache.ambari.server.controller.AmbariServer"):
            for service in ["oozie", "hdfs", "yarn", "spark2"]:
                logger.info("Hadoop service is %s" % service)
                logger.debug("add_agent_config : {0}".format(add_agent_config(service)))
                hadoop_agent[service] = add_agent_config(service)['agentConfig']
        logger.info("hadoop agent {0}".format(hadoop_logger))

        for service in ["oozie", "hdfs", "yarn", "spark2"]:
            if not ((service in hadoop_agent) or (service in hadoop_logger)):
                continue
            hadoop_dict = dict()
            hadoop_dict['pollerConfig'] = dict()
            hadoop_dict["loggerConfig"] = hadoop_logger[service] if service in hadoop_logger else list()
            hadoop_dict["agentConfig"] = hadoop_agent[service] if service in hadoop_agent else dict()
            hadoop_discovery[service] = [hadoop_dict]
        logger.info("Hadoop discovered service %s", hadoop_discovery)
        return hadoop_discovery


def discover_prometheus_services(discovery):
    for service in PROMETHEUS_SERVICES:
        # If the underlying service is running, check if its associated prometheus exporter is also running
        # If the exporter is running, add config elements for the exporter
        service_dict = {}
        prometheus = connect_to_port(PROMETHEUS_SERVICES[service])
        if (service.split('-')[0] in discovery or service in ['node-exporter', 'jmx-exporter']) and prometheus:
            # node-exporter and jmx-exporter do not have an underlying service associated with them
            # hence they are directly added to discovered services if the exporter is running
            service_dict["loggerConfig"] = []
            service_dict["agentConfig"] = {}
            logger_dict = add_logger_config(service_dict, service)
            logger_dict["pollerConfig"] = {}
            final_dict = add_agent_config(service, logger_dict)
            final_dict["agentConfig"]["recommend"] = True
            final_dict["agentConfig"]["selected"] = False

	    if service == 'jmeter-exporter':
                discovery[SERVICE_NAME[service]][0]['loggerConfig'][0]['recommend'] = False

            # Initialize list for each service if its not already discovered.
            # This condition is for jmx-exporter and node-exporter
            if SERVICE_NAME[service] not in discovery:
                discovery[SERVICE_NAME[service]] = []
            discovery[SERVICE_NAME[service]].append(final_dict)

	for service in JVM_ENABLED_PLUGINS:
            if SERVICE_NAME[service] in discovery and SERVICE_NAME['jmx-exporter'] in discovery:
                discovery.pop('JMX')
                break

    return discovery


def discover_services():
    # Starting discovery services
    logger.info("Discover service started")
    discovery = {}
    service_list = set()
    logger_list = set()
    logger_list.add("jmeter")
    service_list.add("topstats")

    for service in SERVICE_PORT_MAPPING:
        # If the port for a given service is open, add the service to service_list
        discovered = connect_to_port(SERVICE_PORT_MAPPING[service])
        if discovered:
            service_list.add(service)

    for service in CUSTOM_SERVICES:
        # If the services in CUSTOM_SERVICES (tpcc, esalogstore, hxconnect) are discovered, add them to service_list
        discovered = discover_custom_services(service)
        if not discovered:
            continue
        if discovered == 'logger':
            # This condition is for esalogstore plugin, which is a standalone logger without an agent plugin
            logger_list.add(service)
        service_list.add(service)
    apache_ports = None
    for service in SERVICES:
        # For all services, check if the service, or its associated java service has a pid.
        # If a pid can be associated with the service, add it to service list
        pid = get_process_id(service)
        if pid:
            service_list.add(service)
            if service == "apache":
                apache_ports = add_ports(pid, service)

    for service in JVM_ENABLED_PLUGINS:
        if service in service_list and 'jvm' in service_list:
            service_list.remove('jvm')
            break

    if "node" in service_list:
        service_list.add("nodejs")
        service_list.add("nodejsapi")
        service_list.discard("node")

    if "kafka.Kafka" in service_list:
        service_list.add("kafkajmx")

    for service in service_list:
        # For all services in service_list, add config for agent, loggers and pollers.
        # This file is dedicated to agent discovery, and hence the poller config will be empty, except for elasticsearch
        service_dict = {}
        service_dict['loggerConfig'] = []
        service_dict['agentConfig'] = {}
        service_dict['pollerConfig'] = {}
        if service == "apache":
            service_dict['ports'] = apache_ports
        logger_dict = add_logger_config(service_dict, service)

        #if service in POLLER_PLUGIN:
         #   final_dict = add_poller_config(service, logger_dict)
        if service in logger_list:
            # This condition is only for esalogger
            final_dict = logger_dict
        else:
            final_dict = add_agent_config(service, logger_dict)
            final_dict["agentConfig"]["recommend"] = False
            final_dict["agentConfig"]["selected"] = False

	if SERVICE_NAME[service] not in discovery:
            discovery[SERVICE_NAME[service]] = []
        discovery[SERVICE_NAME[service]].append(final_dict)

    # Check if nginxplus process is running, if nginx has been discovered
    if 'nginx' in discovery and check_nginx_plus():
        var = discovery.pop('nginx')[0]
        var['agentConfig'] = {'name':'nginxplus'}
        discovery['nginxplus'] = [var]

    # Call discover_hadoop_services which handles the discovery of all hadoop services, add it to discovery dict
    hadoop_plugins = discover_hadoop_services()
    discovery.update(hadoop_plugins)

    discovery = discover_prometheus_services(discovery)

    recommend_agents_off = set()
    recommend_agents_off.update(logger_list)
    recommend_agents_off.add("linux")

    for service_name in discovery:
        for plugin in discovery[service_name]:
            if plugin['agentConfig'].get('name') and (plugin['agentConfig']["name"]).startswith("prometheus"):
                recommend_agents_off.add(service_name)

    for service_name in discovery:
        # If prometheus plugin is not discovered for a service, set recommend = True for the agent plugin
        if service_name not in recommend_agents_off:
            for plugin in discovery[service_name]:
                plugin['agentConfig']['recommend'] = True

    #for service_name in discovery:
        # If prometheus plugin is not discovered for a service, set recommend = True for the agent plugin
        #if len(discovery[service_name]) == 1 and service_name not in recommend_off:
            #discovery[service_name][0]['agentConfig']['recommend'] = True
    logger.info("Discovered services: %s" %str(discovery))
    return discovery
