"""
*******************
*Copyright 2017, MapleLabs, All Rights Reserved.
*
********************
"""

COLLECTDBIN = '/opt/sfapm/collectd/sbin/collectd'
CollectdPluginDestDir = '/opt/sfapm/collectd/plugins'
CollectdPluginConfDir = '/opt/sfapm/collectd/conf'
CollectdConfDir = '/opt/sfapm/collectd/etc'
TEMPLATE_DIR = 'config_handler/templates'
ConfigDataDir = 'config_handler/data'
RESP_NOERROR = 200
EXPORTER_PORT = 8000
LEVEL = 'DEBUG'
EXPORTERLOGPATH = 'log'
LOGFILE = 'configurator_exporter.log'
FORMATTER = '[*(asctime)s-*(filename)s:*(name)s:*(lineno)s-*(funcName)s()] -*(levelname)s: *(message)s'
STATS_DATADIR = "/opt/sfapm/collectd/var/lib/data"
FluentdPluginConfDir = "/opt/sfapm/td-agent/etc/td-agent"
