"""
*******************
*Copyright 2017, MapleLabs, All Rights Reserved.
*
********************
"""
"""
Logger Plugin manager
"""
import copy
from config_util import *
import base64

class FluentdPluginManager:
    """
    Fluentd Plugin manager
    """

    def __init__(self, template_data):
        """
        Initialize member variables for Fluentd manager
        :param template_data:
        :return:
        """
        # Initialize defaults
        self.plugin_path = "/opt/sfapm/td-agent/etc/td-agent" 
        self.service_name = 'td-agent'

        self.plugins = []
        self.enable = template_data.get(ENABLED, True)
        self.tags = template_data.get(TAGS, {})
        self.targets = template_data.get(TARGETS, [])
        self.logger_user_input = template_data

        # self.plugin_config = read_yaml_file(FluentdPluginMappingFilePath)
        # self.plugin_config = get_fluentd_plugins_components_mapping()
        self.plugin_config = get_fluentd_plugins_mapping()
        self.target_mapping_list = get_supported_targets_mapping()

        self.plugin_post_data, self.status = [], []

        # Initialize logger object
        self.logger = expoter_logging(FLUENTD_MGR)
        self.logger.info('Logger Object Successfully Initialized.')
        # self.logger.info('Targets Nodes : %s', str(self.nodelist))
        self.logger.info('User Input : %s', str(self.logger_user_input))

    def start(self):
        """
        Start call for td-agent service
        """
        self.logger.debug('Server - td-agent - start call.')
        self.change_service_status("start")

    def restart(self):
        """
        Restart call for td-agent service
        """
        self.logger.debug('Server - td-agent - restart call.')
        self.change_service_status("restart")

    def stop(self):
        """
        Stop call for td-agent service
        """
        self.logger.debug('Server - td-agent - stop call.')
        self.change_service_status("stop")

    # def teardown(self):
    #     """
    #     Teardown call for td-agent service
    #     """
    #     self.logger.debug('Server - td-agent - Teardown call.')
    #     self.change_service_status("stop")
    #
    #     # Clear the indexes from template created by input template.
    #     for target_details in self.logger_user_input.get(TARGETS, []):
    #         if target_details.get('type') == "elasticsearch":
    #             es_details = target_details
    #             es_conn = Elasticsearch([{'host': es_details.get(HOST),
    #                                       'port': int(es_details.get(PORT))}], verify_certs=True)
    #             status = es_conn.indices.delete(
    #                 index=es_details.get('index'), ignore=[400, 404])
    #             if status.get('acknowledged'):
    #                 self.logger.debug(
    #                     '%s: Index successfully Deleted.', es_details.get('index'))
    #             else:
    #                 self.logger.debug('Error: %s: %s', es_details.get('index'),
    #                                   status.get('error').get('reason'))
    #         else:
    #             self.logger.error(
    #                 'Target is not elastic search database(Yet to handle).')
    #     self.logger.info('Logger Teardown Complete.')

    def check_status(self):
        """
        Check status call for td-agent service
        """
        self.logger.debug('Server - td-agent - check_status call.')
        self.change_service_status("status")
        return self.status

    def change_service_status(self, operation):
        """
        Change service status call as per operation param passed
        :param operation: start/stop/status/restart
        :return: status message as per operation passed.
        """
        try:
            pass
        except Exception as err:
            self.logger.debug("Exception: %s ", str(err))

    def configure_plugin_data(self):
        """
        Generate plugin data based on template data as dictionary
        """
        # Read template config, merge them with plugin config and generate
        # plugin params
        self.logger.info('Configuring the plugin data.')
        x_comp_plugins = list()
        for x_plugin in self.logger_user_input.get(PLUGINS, []):
            temp = dict()
        #     if x_plugin.get(NAME) not in get_fluentd_plugins_mapping().keys():
        #         temp['name'] = x_plugin.get(NAME)
        #         strr = 'In-Valid input plugin type.' + x_plugin.get(NAME)
        #         self.logger.warning(strr)
        #         temp[STATUS] = "FAILED: Unsupported logging Plugin"
        #         self.plugins.append(temp)
        #         continue
        #     x_comps = x_plugin.get(CONFIG, {}).get(COMPONENTS, [])
        #     # x_comp_plugins = list()
        #     if x_comps:
        #         for x_comp in x_comps:
        #             n_plugin = {NAME: x_plugin[NAME] + '-' + x_comp[NAME]}
        #             n_plugin["filter"] = x_comp.get("filter")
        #             n_plugin[TAGS] = x_plugin.get('tags', {})
        #             x_comp_plugins.append(n_plugin)
        #     else:
        #         for x_comp_name in get_fluentd_plugins_mapping().get(x_plugin[NAME], {}).keys():
        #             n_plugin = {NAME: x_plugin[NAME] + '-' + x_comp_name}
        #             n_plugin["filter"] = dict()
        #             n_plugin[TAGS] = x_plugin.get('tags', {})
        #             x_comp_plugins.append(n_plugin)
        # self.logger.info("New plugins based on components %s", json.dumps(x_comp_plugins))
        # for x_plugin in x_comp_plugins:
        #     temp = dict()
            temp['source'] = {}
            temp['source']['tag'] = x_plugin.get('tags', {})
            temp['name'] = x_plugin.get(NAME)
            temp['collection_type'] = 'logger'

            if x_plugin.get(NAME) in self.plugin_config.keys():
                plugin = self.plugin_config.get(
                    x_plugin.get(NAME))
                temp['collection_type'] = plugin.get('collection_type', '')
                if x_plugin.get(NAME) == 'esalogstore':
                    temp['esalogsdownload'] = {}
                    temp['esalogsdownload'].update(plugin.get('esalogsdownload'))
                    temp['esalogsdownload']['command'] = plugin.get('esalogsdownload').get('command') + ' "'+ str(x_plugin[CONFIG].get('log_name',['system_logs']))+'"'
                temp['source'].update(plugin.get('source'))
                if x_plugin.get(CONFIG, {}).get('log_paths'):
                    temp['source']['path'] = x_plugin[CONFIG]['log_paths']
                temp['transform'] = plugin.get('transform')
                if plugin.get('geotag'):
                    temp['geotag'] = plugin.get('geotag')
                if x_plugin.get(NAME) == 'esalogstore':
                    hosts = None
                    esa_path = '/var/log/td-agent/esa_logs'
                    log_path = []
                    if os.path.exists('/opt/esa_conf.json'):
                        with open('/opt/esa_conf.json') as data_file:
                            data = json.load(data_file)
                            hosts = data['hosts']
                    if hosts:
                        for host in hosts:
                            for log_name in x_plugin[CONFIG].get('log_name',['systemlogs']):
                                log_path.append('{}/{}/{}'.format(esa_path, host['name']+"_"+host['uuid'], log_name.replace('_', '')))
                    else:
                        for log_name in x_plugin[CONFIG].get('log_name',['systemlogs']):
                            log_path.append('{}/{}'.format(esa_path, log_name.replace('_', '')))
                    temp['source']['path'] = ','.join(log_path)
                if plugin.get('parse'):
                    temp['parse'] = plugin.get('parse')
                elif plugin.get('multiline'):
                    temp['multiline'] = plugin.get('multiline')
                temp['match'] = plugin.get('match')
            else:
                strr = 'In-Valid input plugin type.' + x_plugin.get(NAME)
                self.logger.warning(strr)
                temp[STATUS] = "FAILED: Unsupported logging plugin component"
                self.plugins.append(temp)
                continue

            # filter_lower = [x.lower()
            #                 for x in x_plugin.get('filter', [])]
            # filter_upper = [x.upper()
            #                 for x in x_plugin.get('filter', [])]
            #
            # if 'WARNING' in filter_upper:
            #     filter_upper.remove('WARNING')
            #     filter_upper.append('WARN')
            #
            # if 'all' in filter_lower:
            #     if x_plugin.get(NAME) == 'linux-syslog':
            #         temp['source']['log_level'] = 'debug'
            #     else:
            #         if not temp['source'].get('format'):
            #             temp['source']['format'] = 'none'
            #         # temp['source']['format'] = 'none'
            #         temp['usr_filter'] = '(.*?)'
            # else:
            #     if x_plugin.get(NAME) == 'linux-syslog':
            #         temp['source']['log_level'] = filter_upper[0].lower()
            #     else:
            #         if not temp['source'].get('format'):
            #             temp['source']['format'] = 'none'
            #         # temp['source']['format'] = 'none'
            #         temp[
            #             'usr_filter'] = '(.*(' + '|'.join(filter_upper) + ').*?)'
	    if "rewrite_tag_filter" in plugin:
                temp['rewrite_tag_filter'] = plugin.get('rewrite_tag_filter')
            temp['usr_filter'] = {}
            if x_plugin.get(CONFIG, {}).get(FILTERS):
                for key, value in x_plugin[CONFIG][FILTERS].items():
                    if isinstance(value, list):
                        temp['usr_filter'][key] = '(.*(' + '|'.join(value) + ').*?)'
                    else:
                        temp['usr_filter'][key] = '(.*(' + str(value) + ').*?)'
            self.plugins.append(temp)
        self.logger.info('Plugin data successfully Configured.')
        return True

    def configure_plugin_file(self, data):
        """
        Push configured plugin data to file
        :param data: Generate plugin data based on param passed and push config to file
        :return: True if operation is successful
        """
        # Add source.
        logger.info("Configure plugin file, data %s" %json.dumps(data))
        source_tag = str()
        lines = ['<source>']
        if data.get('name') == "esalogstore":
            for key, value in data.get('esalogsdownload', {}).iteritems():
                lines.append('\t' + str(key) + ' ' + str(value))
            lines.append('</source>')
            lines.append('\n<source>')
        for key, val in data.get('source', {}).iteritems():
            # if isinstance(val, list):
            #     try:
            #         source_tag = val[0] + '.*'
            #     except Exception as err:
            #         self.logger.debug('Plugin tags not configured. Using plugin name as tag.'
            #                           'Exception - %s ', str(err))
            #         source_tag = data.get('name') + '.*'
            #         lines.append('\t' + key + ' ' + source_tag)
            #         continue
            #     '''
            #     source_tag = val[0]
            #     except:
            #         self.logger.debug('Plugin tags not configured. Using plugin name as tag.')
            #         source_tag = data.get('name')
            #     '''
            #     lines.append('\t' + key + ' ' + source_tag)
            #     continue
            if key == "tag":
                source_tag = data.get('name') + '.*'
                lines.append('\t' + key + ' ' + source_tag)
                continue
            # if key == "formats":
            #     for v in val:
            #         lines.append('\t' + "<pattern>")
            #         lines.append('\t' + 'format ' + str(v))
            #         lines.append('\t' + "</pattern>")
            #     continue
            lines.append('\t' + str(key) + ' ' + str(val))
        if 'parse' in data:
            lines.append('\t' + "<parse>")
            lines.append('\t\t' + '@type none')
            lines.append('\t' + "</parse>")
        elif 'multiline' in data:
            lines.append('\tformat multiline')
            for key, val in data.get('multiline', {}).iteritems():
                if key != "expression":
                    lines.append('\t' + key  + ' ' + val)
                    continue
                else:
                    i = 1
                    for v in val:
                        lines.append('\tformat' + str(i) + ' ' + v)
                        i+=1
                        continue
            lines.append('\tread_from_head true')
        lines.append('</source>')

	# Add rewrite tag filter
        if "rewrite_tag_filter" in data:
            lines.append('\n<match ' + source_tag + '*>')
            lines.append('\t' + '@type rewrite_tag_filter')
            for key,val in data.get('rewrite_tag_filter',{}).iteritems():
                lines.append('\t' + '<rule>')
                lines.append('\t\tkey message')
                lines.append('\t\tpattern '+ val)
                if key != 'clear':
                    lines.append('\t\ttag '+ key + '.${tag}')
                else:
                    lines.append('\t\ttag clear')
                lines.append('\t' + '</rule>')
            lines.append('</match>')
            # Add filter for seperate rule
            for key,val in data.get('parse',{}).iteritems():
                lines.append('\n<filter ' + key + '.**>')
                lines.extend(['\t@type parser', '\tkey_name message', '\t<parse>'])
                for key1,val1 in data.get('parse',{}).get(key,{}).iteritems():
                    if key1 == "expressions":
                        for v in val1:
                            lines.append('\t\t' + "<pattern>")
                            lines.append('\t\t\t' + 'format regexp')
                            lines.append('\t\t\t' + 'expression ' + v)
                            lines.append('\t\t' + "</pattern>")
                        continue
                    lines.append('\t\t' + key1  + ' ' + val1)
                lines.extend(['\t</parse>', '</filter>'])
            source_tag = '*.'+ source_tag
        elif 'parse' in data:
	    time_format = ""
	    types =""
            # Add parser filter. if data.get('match').has_key('tag'):
            if 'tag' in data.get('match'):
                lines.append('\n<filter ' + source_tag + '.' +
                       data.get('match').get('tag', []) + '>')
            else:
		lines.append('\n<filter ' + source_tag + '*>')
	    lines.extend(['\t@type parser', '\tkey_name message', '\t<parse>'])
	    for key, val in data.get('parse', {}).iteritems():
		if key == "time_format":
                    time_format = val
		if key == "types":
		    types = val
	    
	    for key, val in data.get('parse', {}).iteritems():	
		if key == "expressions":
		    for v in val:
			lines.append('\t\t' + "<pattern>")
			lines.append('\t\t\t' + 'format regexp')
			lines.append('\t\t\t' + 'expression ' + v)
			if time_format:
                            lines.append('\t\t\t' + 'time_format ' + time_format)
			if types:
			    lines.append('\t\t\t' + 'types ' + types)
			lines.append('\t\t' + "</pattern>")
		    continue
		lines.append('\t\t' + key  + ' ' + val)
	    lines.extend(['\t</parse>', '</filter>'])

        # Add record-transormation filter. if data.get('match').has_key('tag'):
        if 'tag' in data.get('match'):
            lines.append('\n<filter ' + source_tag + '.' +
                         data.get('match').get('tag', []) + '>')
        else:
            lines.append('\n<filter ' + source_tag + '*>')
        lines.append('\tenable_ruby')
        lines.extend(['\t@type record_transformer', '\t<record>'])
        for key, val in data.get('transform', {}).iteritems():
            lines.append('\t\t' + key + ' \"' + val + '\"')

        # lines.append('\t\ttags ' + str(self.tags + [data.get('source').get('tag')]))
        if data.get('name') == 'esalogstore':
            for tag_key, tag_val in self.tags.items():
                if tag_key == 'appName':
                    lines.append('\t\t' + '_tag_' + str(tag_key) + ' ' + '"' + str(tag_val) + '"')
        else:
            for tag_key, tag_val in self.tags.items():
                # tags = [str(x) for x in self.tags + data.get('source').get('tag')]
                lines.append('\t\t' + '_tag_' + str(tag_key) + ' ' + '"' + str(tag_val) + '"')
        lines.extend(['\t</record>', '</filter>'])

        # Add geotagging filter
        if 'geotag' in data:
            if 'tag' in data.get('match'):
                lines.append('\n<filter ' + source_tag + '.' +
                             data.get('match').get('tag', []) + '>')
            else:
                lines.append('\n<filter ' + source_tag + '*>')
            lines.append('\t@type geoip')
            for key, val in data.get('geotag', {}).iteritems():
                lines.append('\t' + key + ' ' + val)
            lines.append('\tbackend_library geoip2_c')
            lines.append('\t<record>')
            lines.append('\t\tcity ${city.names.en["host"]}')
            lines.append('\t\tlatitude ${location.latitude["host"]}')
            lines.append('\t\tlongitude ${location.longitude["host"]}')
            lines.append('\t\tcountry ${country.iso_code["host"]}')
            lines.append('\t\tcountry_name ${country.names.en["host"]}')
            lines.append('\t\tpostal_code ${postal.code["host"]}')
            lines.append('\t\tregion_code ${subdivisions.0.iso_code["host"]}')
            lines.append('\t\tregion_name ${subdivisions.0.names.en["host"]}')
            lines.append('\t</record>')
            lines.append('</filter>')

	# Add grep filter.
        if data.get('usr_filter', None):
            lines.append('\n<filter ' + source_tag + '*>')
            lines.append('\t@type grep')
            count = 0
            for key, value in data.get('usr_filter', {}).items():
                count = count + 1
                lines.append('\tregexp' + str(count) + ' ' + str(key) + ' ' + str(value))
            lines.append('</filter>')

        # Add match. if data.get('match').has_key('tag'):
        for x_targets in self.targets:
            if STATUS not in x_targets:
                if 'tag' in data.get('match'):
                    lines.append('\n<match ' + source_tag + '.' +
                                 data.get('match').get('tag') + '>')
                    data.get('match').pop('tag')

                if data.get('collection_type', '') == 'metric':
                    if x_targets.get("store_type") and x_targets['store_type'] == 'metric':
                        lines.append('\n<match ' + source_tag + '*>')
                        for key, val in x_targets.iteritems():
                            if key == "type":
                                key = "@" + key
                            if key == "index":
                                key += "_name"
                                val = val+"_write"
                            if key == "username":
                                key = "user"
                            if key == "password":
                                val = base64.b64decode(val)
                            if key == "protocol":
                                key = "scheme"
                            if key == "enable":
                                continue
                            lines.append('\t' + key + ' ' + val)
                        lines.append('\t' + 'ssl_verify ' + 'false')
                        lines.append('\t' + 'type_name' + ' ' + DOCUMENT)
                        for key, val in data.get('match', {}).iteritems():
                            lines.append('\t' + str(key) + ' ' + str(val))
                        lines.append('</match>')
                    #else:
                        #self.logger.info("Metric datasource not passed in fluentd config")
                        #return
                else:
                    if x_targets.get("store_type") and x_targets['store_type'] == 'logger':
                        lines.append('\n<match ' + source_tag + '*>')
                        for key, val in x_targets.iteritems():
                            if key == "type":
                                key = "@" + key
                            if key == "index":
                                key += "_name"
                                val = val+"_write"
                            if key == "username":
                                key = "user"
                            if key == "password":
                                val = base64.b64decode(val)
                            if key == "protocol":
                                key = "scheme"
                            if key == "enable":
                                continue
                            lines.append('\t' + key + ' ' + val)
                        lines.append('\t' + 'ssl_verify ' + 'false')
                        lines.append('\t' + 'type_name' + ' ' + DOCUMENT)

                        for key, val in data.get('match', {}).iteritems():
                            lines.append('\t' + str(key) + ' ' + str(val))
                        lines.append('</match>')
                #else:
                #    lines.append('\n<match ' + source_tag + '*>')

                #for key, val in x_targets.iteritems():
                #    if key == "type":
                #        key = "@" + key
                #    if key == "index":
                #        key += "_name"
                #        val = val+"_write"
                #    if key == "enable":
                #        continue
                #    lines.append('\t' + key + ' ' + val)
                #lines.append('\t' + 'type_name' + ' ' + DOCUMENT)

	# Add match, if clear is present in rewrite tag filter
	if 'rewrite_tag_filter' in data and 'clear' in data.get('rewrite_tag_filter',{}):
	    lines.append('\n<match clear>')
	    lines.append('\t@type null')
	    lines.append('</match>')
        filename = self.plugin_path + os.path.sep + data.get('name')
        self.plugin_post_data.append((filename, '\n'.join(lines)))
        return True

    def generate_plugins(self):
        """
        Generate plugin data
        :return: true if operation is successful
        """
        # Generate the files in the salt dir
        logger.debug("Generate plugins configs")
        self.configure_plugin_data()

        for x_plugin in self.plugins:
            if STATUS not in x_plugin:
                self.logger.debug('Configuring the plugin: %s', (str(x_plugin)))
                self.configure_plugin_file(x_plugin)
        return True

    def generate_fluentd_config_file(self):
        """
        Generate fluentd config file
        :return: True if operation is successful
        """
        self.logger.info('Generating fluentd config file (td-agent.conf).')
        lines = []
        for x_plugin in self.plugins:
            if STATUS not in x_plugin:
                lines.append('@include ' + x_plugin.get('name'))

        for x_targets in self.targets:
            if STATUS not in x_targets:
                lines.append('\n<match *>')
                # for key, val in self.logger_user_input.get('targets')[0].iteritems():
                for key, val in x_targets.iteritems():
                    if key == "type":
                        key = "@" + key
                    if key == "index":
                        key += "_name"
                        val = val+"_write"
                    if key == "username":
                        key = "user"
                    if key == "password":
                        val = base64.b64decode(val)
                    if key == "protocol":
                        key = "scheme"
                    if key == "enable":
                        continue
                    lines.append('\t' + key + ' ' + val)

                lines.append('\t' + 'ssl_verify ' + 'false')
                lines.append('\t' + 'flush_interval' + ' ' +
                             str(self.plugin_config.get('default_flush_interval', '60s')))
                lines.append('\t' + 'include_tag_key' + ' true')
                lines.append('</match>')

        filename = self.plugin_path + os.path.sep + 'td-agent.conf'
        self.plugin_post_data.append((filename, '\n'.join(lines)))
        return True

    # def deploy(self, oper):
    #     """
    #     Deploy logger based on operation
    #     :param oper: start/stop
    #     :return:
    #     """
    #     self.logger.info('Deployment Started.')
    #     self.logger.debug('Operation : ' + str(oper))
    #     self.logger.debug(
    #         'Enable : ' + str(self.logger_user_input.get('enable', False)))
    #
    #     salt_obj = SaltManager()
    #     # status = {}
    #     if oper == START:
    #         if self.logger_user_input.get('enable', False):
    #             self.generate_plugins()
    #             self.generate_fluentd_config_file()
    #             # print '\nPost Data: ', json.dumps(self.plugin_post_data)
    #
    #             self.logger.info('Pushing the configs to the target node.')
    #             self.logger.debug('self.plugin_post_data' +
    #                               json.dumps(self.plugin_post_data))
    #             status = salt_obj.push_config(
    #                 self.plugin_post_data, self.nodelist)
    #             self.logger.debug('Push Status :' + json.dumps(status))
    #             self.restart()
    #         else:
    #             self.stop()
    #     elif oper == STOP:
    #         if self.logger_user_input.get('enable', False):
    #             disable_files, disable_plugins = [], []
    #             for x_plugin in self.logger_user_input.get('plugins'):
    #                 disable_plugins.append(x_plugin.get('type'))
    #                 disable_files.append(
    #                     self.plugin_path + os.path.sep + x_plugin.get('type'))
    #
    #             self.logger.info(
    #                 'Plugin disable in progress : ' + str(disable_plugins))
    #             status = salt_obj.delete_files(disable_files, self.nodelist)
    #             new_config_data = salt_obj.reset_logger_config(
    #                 disable_plugins, self.nodelist)
    #             config_post_data = [[self.plugin_path + os.path.sep +
    #                                  'td-agent.conf', new_config_data]]
    #             self.logger.debug('self.plugin_post_data' +
    #                               json.dumps(config_post_data))
    #             config_status = salt_obj.push_config(
    #                 config_post_data, self.nodelist)
    #             self.logger.debug('Config Push Status :' +
    #                               json.dumps(config_status))
    #             status.update(config_status)
    #             self.restart()
    #         else:
    #             self.stop()
    #
    #     elif oper == 'teardown':
    #         self.logger.info('Teardown Started.')
    #         self.stop()
    #         return
    #
    #     else:
    #         pass
    #
    #     self.change_service_status("status")
    #     return self.status

    def create_conf_files(self):
        for cnf in self.plugin_post_data:
            file_writer(cnf[0], cnf[1])

    def bulid_set_config_result(self):
        logging = {}

        for x_plugin in self.plugins:
            if STATUS not in x_plugin:
                x_plugin[STATUS] = "SUCCESS: Plugin configured"

        logging[PLUGINS] = self.plugins

        for x_targets in self.targets:
            if STATUS not in x_targets:
                x_targets[STATUS] = "SUCCESS: targets configured"

        logging[TARGETS] = self.targets
        logging[ENABLED] = self.enable
        return logging

    def store_set_config(self):
        """

        :return:
        """
        error_msg = ""
        logging = {}
        plugins_list = copy.deepcopy(self.plugins)
        targets_list = copy.deepcopy(self.targets)
        try:
            # Build plugin Result
            for i in range(len(plugins_list)):
                if STATUS in plugins_list[i] and "FAILED" in plugins_list[i][STATUS]:
                    del plugins_list[i]
                    continue

                if STATUS in plugins_list[i]:
                    del plugins_list[i][STATUS]

            logging[PLUGINS] = plugins_list

            mapping_list = get_supported_targets_mapping()
            for i in range(len(targets_list)):
                if STATUS in targets_list[i] and "FAILED" in targets_list[i][STATUS]:
                    del targets_list[i]
                    continue

                if STATUS in targets_list[i]:
                    del targets_list[i][STATUS]

                # # Storing only value of  mapping file targets params
                # try:
                #     keys = []
                #     if TYPE in targets_list[i] and targets_list[i][TYPE] in mapping_list.keys():
                #         keys = mapping_list[targets_list[i][TYPE]].keys()
                #
                #     for key in targets_list[i].keys():
                #         if key not in keys:
                #             del targets_list[i][key]
                #
                # except:
                #     pass

            logging[TARGETS] = targets_list
            logging[ENABLED] = self.enable
            logging[TAGS] = self.tags
            # Store config data
            file_writer(FluentdData, json.dumps(logging))
            self.logger.info(" maintain set configuration data for configurator to use")

        except Exception as e:
            error_msg += "Logging configutration storing failed: "
            error_msg += str(e)
            self.logger.error(error_msg)

    def verify_targets(self):
        logger.info("Verify targets")
        for x_targets in self.targets:
            if x_targets[TYPE] in self.target_mapping_list.keys():
                keys = self.target_mapping_list[x_targets[TYPE]].keys()
                for key in x_targets.keys():
                    if key not in keys:
                        del x_targets[key]
            else:
                x_targets[STATUS] = "FAILED: Unsupported logging targets"

    def set_config(self):
        """
        configure fluentd
        :return:
        """
        return_dict = {}
        error_msg = ""
        try:
            self.logger.info('Deployment Started.')
            self.logger.debug(
                'Enable : ' + str(self.enable))

            success, error_msg = delete_fluentd_config()
            self.verify_targets()
            self.generate_plugins()
            self.generate_fluentd_config_file()

            self.logger.info('Pushing the configs to the target node.')
            self.logger.debug('self.plugin_post_data' +
                              json.dumps(self.plugin_post_data))
            self.create_conf_files()
            self.logger.info("Stop fluentd process")
            change_fluentd_status(STOP)
            if self.enable:
                # self.restart()
                try:
                    for plugin in self.plugins:
                        files = plugin.get("source", {}).get("path")
                        if files:
                            for filepath in files.split(','):
                                self.logger.info("changing file %s permission", filepath)
                                set_log_file_permission(filepath, 'o+r,o+x')
                except:
                    self.logger.error("Error in changing file permission")
                self.logger.info("Start fluentd process")
                change_fluentd_status(START)

            return_dict = self.bulid_set_config_result()
            self.logger.info("Bulid set configuration result completed")

            # Stored copnfiguration locally.
            self.store_set_config()

        except Exception as e:
            error_msg += str(e)
            return_dict[ERROR] = error_msg
            self.logger.error("Set fluentd config failed")
            self.logger.error(str(e))

        return return_dict
