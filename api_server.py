"""
*******************
*Copyright 2017, MapleLabs, All Rights Reserved.
*
********************
"""
#!/usr/bin/env python

import ConfigParser
import argparse
import web

from common.util import *
from config_handler import configurator
from service_discovery import discovery
from stat_exporter import collectd_exporter

urls = (
    "/", "Root",
    "/api", "Api",
    "/api/", "Api",
    "/api/collectd", "Collectd",
    "/api/collectd/", "Collectd",
    "/api/fluentd", "Fluentd",
    "/api/fluentd/", "Fluentd",
    "/api/collectd/stats", "CollectdStats",
    "/api/collectd/stats/.*", "CollectdStats",
    "/api/config", "Config",
    "/api/config/.*", "Config",
    "/api/collectd/process", "CollectdProcess",
    "/api/fluentd/process", "FluentdProcess",
    "/api/service", "Service",
    "/api/service/", "Service",
    "/api/target/status", "TargetStatus"

)

DEFAULT_PORT = 8585


# app = web.application(urls, globals())

class MyApplication(web.application):
    def run(self, host='0.0.0.0', port=DEFAULT_PORT, *middleware):
        func = self.wsgifunc(*middleware)
        return web.httpserver.runsimple(func, (host, port))


class Root:
    def GET(self):
        result = ["api"]
        return json.dumps(result)


class Api:
    def GET(self):
        result = ["config", "collectd", 'fluentd']
        return json.dumps(result)


class Collectd:
    def GET(self):
        result = ["stats", 'process']
        return json.dumps(result)


class Fluentd:
    def GET(self):
        result = ['process']
        return json.dumps(result)

class TargetStatus:
    def GET(self):
        result = {}
        result['targets'] = configurator.get_target_status()
        return json.dumps(result)

class CollectdStats:
    def GET(self):
        result = configurator.get_collectd_plugin_names()
        try:
            url_param = [i for i in web.ctx['path'].split('/') if i not in ['', 'api', 'collectd', 'stats']]
        except:
            error_msg = "URl not Found"
            raise web.notfound(error_msg)
        plugins = []
        if len(url_param) == 0:
            plugins.append(ALL)
        elif url_param[0] in configurator.get_collectd_plugins_mapping().keys():
            for name in configurator.get_collectd_plugin_names(url_param[0]):
                plugins.append(str(name).replace("_", ''))
        elif url_param[0] in result:
            plugins.append(str(url_param[0]).replace("_", ''))
        else:
            return json.dumps(result)

        if (url_param[0] == "linux"):
            plugins.append("linux")

        user_data = web.input(samples="1", instances="")
        plugin_instances = [ALL]
        if user_data.instances:
            # instance_list = str(user_data.instances[0])
            plugin_instances = user_data.instances.split(",")
        data = collectd_exporter.get_data(num_samples=int(
            user_data.samples), plugins=plugins, plugin_instances=plugin_instances)

        return json.dumps(data)


class Config:
    def POST(self):
        result = {METRICS: None, LOGGING: []}
        try:
            url_param = [i for i in web.ctx['path'].split('/') if i not in ['', 'api', 'config']]
        except:
            error_msg = "URl not Found"
            raise web.notfound(error_msg)
        if len(url_param) != 0:
            error_msg = "URl not Found"
            raise web.notfound(error_msg)

        try:
            data = json.loads(web.data())
        except:
            error_msg = "Data is not in Json format"
            raise web.badrequest(error_msg)

        metrics = data.get(METRICS, {})
        logging = data.get(LOGGING, {})
        targets = data.get(TARGETS, {})
        hostname = data.get("name")
        nodeId = data.get(NODEID)

        if not (metrics or logging):
            result[METRICS] = configurator.set_collectd_config(metrics)
            result[LOGGING] = configurator.set_fluentd_config(logging)
        elif metrics and not (metrics.get(PLUGINS, []) and metrics.get(TARGETS, [])):
            error_msg = "Invalid metrics config"
            raise web.badrequest(error_msg)
        elif logging and not (logging.get(PLUGINS, []) and logging.get(TARGETS, [])):
            error_msg = "Invalid logging config"
            raise web.badrequest(error_msg)

        if metrics:
            metrics = configurator.map_local_targets(targets, metrics)
            metrics["custom_hostname"] = hostname
            if nodeId:
                metrics[NODEID]= nodeId

            result[METRICS] = configurator.set_collectd_config(metrics)
        else:
            result[METRICS] = configurator.set_collectd_config(metrics)

        if logging:
            logging = configurator.map_local_targets(targets, logging)
            result[LOGGING] = configurator.set_fluentd_config(logging)
        else:
            result[LOGGING] = configurator.set_fluentd_config(logging)

        if data.get(HEARTBEAT, False):
            es_config = dict()
            for target in targets:
                if target[TYPE] == ELASTICSEARCH:
                    es_config = target
                    break
            if configurator.timer:
                try:
                    configurator.timer.cancel()
                    configurator.timer = None
                except:
                    pass
            h_interval = data.get(HEARTBEAT_INTERVAL, configurator.CONFIG_WRITE_INTERVAL)
            configurator.write_config_to_target(es_config, h_interval)
        return json.dumps(result)

    def GET(self):
        try:
            url_param = [i for i in web.ctx['path'].split('/') if i not in ['', 'api', 'config']]
        except:
            error_msg = "URl not Found"
            raise web.notfound(error_msg)

        result = {}
        try:
            import platform
            if float(".".join([platform.python_version_tuple()[0], platform.python_version_tuple()[1]])) < 2.6:
                result["distro"] = " ".join(platform.dist())
            else:
                result["distro"] = " ".join(platform.linux_distribution())
        except:
            result["distro"] = None

        if len(url_param) == 0:
            result[METRICS] = configurator.get_collectd_config()
            result[LOGGING] = configurator.get_fluentd_config()
        elif url_param[0] == SUPPORTED_PLUGINS:
            result[METRICS] = configurator.get_supported_metrics_plugins()
            result[LOGGING] = configurator.get_supported_logging_plugins()
        elif url_param[0] == SUPPORTED_TARGETS:
            result = configurator.get_supported_targets()
        elif url_param[0] == "mapping":
            result[METRICS] = configurator.get_collectd_plugins_mapping()
            result[LOGGING] = configurator.get_fluentd_plugins_mapping()
            result[TARGETS] = configurator.get_supported_targets_mapping()
        elif url_param[0] == "params":
            user_data = web.input(metrics_plugins="", logging_plugins="", targets="")
            metric_plugin_instances = []
            target_instances = []
            logging_plugin_instances = []
            # print user_data
            if user_data.metrics_plugins:
                metric_plugin_instances = user_data.metrics_plugins.split(",")
                result[METRICS] = configurator.get_metrics_plugins_params(metric_plugin_instances)
            if user_data.targets:
                target_instances = user_data.targets.split(",")
                result[TARGETS] = configurator.get_targets_params(target_instances)
            if user_data.logging_plugins:
                logging_plugin_instances = user_data.logging_plugins.split(",")
                result[LOGGING] = configurator.get_logging_plugins_params(logging_plugin_instances)
            if not (user_data.metrics_plugins or user_data.targets or user_data.logging_plugins):
                result[METRICS] = configurator.get_metrics_plugins_params(metric_plugin_instances)
                result[LOGGING] = configurator.get_logging_plugins_params(logging_plugin_instances)
                result[TARGETS] = configurator.get_targets_params(target_instances)
        else:
            error_msg = "URl not Found"
            raise web.notfound(error_msg)

        return json.dumps(result)


class CollectdProcess:
    def POST(self):
        try:
            data = json.loads(web.data())
        except:
            error_msg = "Data is not in json format"
            raise web.badrequest(error_msg)
        if ENABLED in data:
            result = configurator.enabled_collectd(data)
        else:
            error_msg = ENABLED + ' key Not Present'
            raise web.badrequest(error_msg)

        return json.dumps(result)

    def GET(self):
        result = configurator.get_collectd_process()
        return json.dumps(result)


class FluentdProcess:
    def POST(self):
        try:
            data = json.loads(web.data())
        except:
            error_msg = "Data is not in json format"
            raise web.badrequest(error_msg)
        if ENABLED in data:
            result = configurator.enabled_fluentd(data)
        else:
            error_msg = ENABLED + ' key Not Present'
            raise web.badrequest(error_msg)

        return json.dumps(result)

    def GET(self):
        result = configurator.get_fluentd_process()
        return json.dumps(result)


class Service:
    # Gives details of all running services on the server
    def GET(self):
        data = discovery.discover_services()
        return json.dumps(data)


# if __name__ == "__main__":
#     create_plugin_env()
#     app.run()

if __name__ == '__main__':
    """main function"""
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', type=int, action='store', dest='port',
                        help='port on which configurator will listen, Default {0}'.format(DEFAULT_PORT))
    parser.add_argument('-i', '--ip', action='store', dest='host',
                        help='host ip on which configurator will listen, Default 0.0.0.0')
    args = parser.parse_args()

    host = args.host
    port = args.port

    config = ConfigParser.ConfigParser()
    config.read('./config.ini')

    try:
        if not host:
            host = config.get('DEFAULT', 'host')

        if not port:
            port = config.get('DEFAULT', 'port')
    except:
        pass

    if not host:
        host = "0.0.0.0"
    if not port:
        port = DEFAULT_PORT

    create_plugin_env()
    app = MyApplication(urls, globals())
    app.run(host=host, port=int(port))
