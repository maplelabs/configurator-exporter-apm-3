"""
*******************
*Copyright 2017, MapleLabs, All Rights Reserved.
*
********************
"""

import copy
import socket
from mako.template import Template
import base64
from config_util import *


class CollectdManager:
    """
    Collectd Manager for generating config for collectd plugins
    """

    def __init__(self, metrics=None):
        """
        init template
        :param metrics:
        """
        self.collector_dict = metrics
        self.plugin_src_dir = CollectdPluginDestDir
        self.plugin_conf_dir = CollectdPluginConfDir
        self.collectd_conf_dir = CollectdConfDir
        self.interval = 10
        self.cfg_dict = {}
        self.tag_list = {}
        self.target_list = []
        self.seperate_files = True
        self.targets = {}
        self.tags = {}
        self.success_config = []
        self.logger = expoter_logging(COLLECTD_MGR)
        self.target_mapping_list = get_supported_targets_mapping()
        self.plugin_mapping_list = get_collectd_plugins_mapping()
        self.custom_hostname = socket.gethostname()
        self.nodeId = None 

    def set_targetandtag(self, plugin, plugin_targets=None, plugin_tags=None):
        """
        config filter conf
        :param plugin:
        :param plugin_targets:
        :param plugin_tags:
        :return:
        """
        if plugin_tags is None:
            plugin_tags = {}
        if plugin_targets is None:
            plugin_targets = []
        error_msg = ""
        try:
            self.logger.debug("plugin: " + str(plugin) + " targets: " +
                              str(plugin_targets) + " tags: " + str(plugin_tags))
            for ptarget in plugin_targets:
                for target in self.target_list:
                    if ptarget == target[TYPE]:
                        target_type = target[TYPE]
                        if target_type not in self.targets:
                            self.targets[target_type] = {}
                        if ptarget not in self.targets[target_type]:
                            self.targets[target_type][ptarget] = {
                                CONFIG: target, PLUGINS: []}
                        self.targets[target_type][ptarget][
                            PLUGINS].append(plugin)
            if plugin_tags:
                self.tags[plugin] = plugin_tags
            return True
        except Exception as e:
            error_msg += str(e)
        self.logger.error(error_msg)
        return False

    '''
    Input: Plugin name and dictionary of options.
    Output: Returns plugin config.
    '''

    def get_section_cfg(self, section_name, section):
        """
        generate section config
        :param section_name:
        :param section:
        :return:
        """
        error_msg = ""
        try:
            filename = section_name + EXTSN
            filename = os.path.join(os.getcwd(), TEMPLATE_DIR, filename)

            # Plugin directory location changed.
            # filename = os.path.join(settings.COLLECTOR_TEMPLATES, filename)

            mytemplate = Template(filename=filename)
            section_cfg = mytemplate.render(data=section)
            self.logger.debug(section_cfg)
            if section_cfg is not None:
                # filters and targets won't have name key
                if NAME in section and TARGETS in section and TAGS in section:
                    if self.set_targetandtag(section[NAME], section[TARGETS], section[TAGS]):
                        return True, section_cfg
                else:
                    return True, section_cfg
        except KeyError, e:
            error_msg = error_msg + str(e) + KEY_ERROR
        except Exception as e:
            error_msg += str(e)
        self.logger.error(error_msg)
        return False, None

    '''
    Iterates over the list of plugins generating config for each plugin.
    Then iterates over target list and generates config for targets.
    At the end generates config for filters.
    '''

    def generate(self):
        """
        generate config
        :return:
        """
        error_msg = ""
        success_overall = False
        self.logger.debug("config_list: " + str(self.cfg_dict))
        try:
            # generate config for plugins
            for profile, cfg_list in self.cfg_dict.items():
                for cfg in cfg_list:
                    if STATUS not in cfg:
                        filename = get_dest_filename(cfg[NAME])
                        (success, section_cfg) = self.get_section_cfg(
                            cfg[NAME], section=cfg)
                        if success:
                            self.logger.debug("Generated config for " + cfg[NAME])
                            self.success_config.append((filename, section_cfg))
                        else:
                            self.logger.debug(
                                "Config generation failed for " + cfg[NAME])
                            cfg[STATUS] = "FAILED: Config generation failed"

            # generate config for targets
            for target, conf in self.targets.items():
                filename = get_dest_filename(target)
                if 'password' in conf['elasticsearch']['config'] and conf['elasticsearch']['config']['password']:
                    conf['elasticsearch']['config']['password'] = base64.b64decode(conf['elasticsearch']['config']['password'])
                (success, section_cfg) = self.get_section_cfg(target, section=conf)
                self.logger.debug("success: " + str(success) +
                                  " section_cfg: " + section_cfg)
                if success:
                    self.logger.debug("Generated config for " + target)
                    self.success_config.append((filename, section_cfg))

                else:
                    for value in self.target_list:
                        value[STATUS] = "FAILED: Config generation failed"
                        self.logger.debug("Config generation failed for " + value)

                success_overall = success_overall or success

            # generate config for filters
            filename = get_dest_filename(FILTERS)
            # (success, cfg) = self.get_section_cfg(
            # FILTERS, {TAGS: self.tags, TARGETS: self.targets})
            section = {TAGS: self.tags, TARGETS: self.targets, CUSTOM_HOSTNAME: self.custom_hostname}
            if self.nodeId is not None:
                section[NODEID] = self.nodeId
            (success, cfg) = self.get_section_cfg( FILTERS, section)

            self.logger.debug("success: " + str(success) +
                              " section_cfg: " + cfg)
            if success:
                self.logger.debug("Generated config for filters")
                self.success_config.append((filename, cfg))
            else:
                self.logger.debug("Config generation failed for filters")

            success_overall = success_overall or success
            self.logger.debug(
                "plugin, target and filter config gen overall status: " + str(success_overall))
            self.logger.debug(
                "plugin, target and filter config gen details " + str(self.success_config))
            return True, error_msg
        except KeyError, e:
            error_msg = error_msg + str(e) + KEY_ERROR
        except Exception as e:
            error_msg += str(e)
        self.logger.error(error_msg)
        return False, error_msg
        # self.logger.error(str(return_dict[FAILED_LIST]))

    '''
    Input: Template in Orchestrator format.
    Functionality: Applies global level options on individual
                   plugins and sets list of plugins and targets.
    '''

    def create_cfg_list(self):
        """
        create list of config
        :return:
        """
        error_msg = ""
        target_names_list = []
        try:
            collector_dict = self.collector_dict
            if TAGS in collector_dict:
                self.tag_list = collector_dict[TAGS]

            # Match supported Targets
            if TARGETS in collector_dict:
                for target in collector_dict[TARGETS]:
                    if target[TYPE] in self.target_mapping_list.keys():
                        keys = self.target_mapping_list[target[TYPE]].keys()
                        for key in target.keys():
                            if key not in keys:
                                del target[key]

                        self.target_list.append(target)
                        target_names_list.append(target[TYPE])
                    else:
                        target[STATUS] = "FAILED: Unsupported metrics targets"
                        self.target_list.append(target)

            # plugin_disable_list = []

            if PLUGINS in collector_dict:
                for profile in collector_dict[PLUGINS]:
                    plugin_cfg_list = []
                    # Match supported Plugin
                    if profile[NAME] in self.plugin_mapping_list.keys():
                        plugin_list = self.plugin_mapping_list[profile[NAME]]
                        # print "plugin_list",plugin_list
                        # Verify Supported Plugin
                        for plugin in plugin_list:
                            plugin_temp = copy.deepcopy(plugin)
                            # Propulate CONFIG_DATA is applicable
                            if CONFIG_DATA in plugin_temp:
                                if CONFIG_DATA in profile:
                                    for key, value in profile[CONFIG_DATA].items():
                                        for item in plugin_temp[CONFIG_DATA]:
                                            if key in item.values():
                                                plugin_temp[key] = value
                                                break
                                del plugin_temp[CONFIG_DATA]
                            # Propulate TARGETS ,INTERVAL,TAGS in each plugin
                            plugin_temp[TARGETS] = target_names_list
                            if INTERVAL not in plugin_temp:
                                plugin_temp[INTERVAL] = self.interval
                            plugin_temp[TAGS] = self.tag_list
                            plugin_cfg_list.append(plugin_temp)
                    else:
                        # unsupported plugin
                        error_msg = "FAILED: Unsupported metrics plugin"
                        plugin_cfg_list.append({NAME: profile[NAME], STATUS: error_msg})

                    self.cfg_dict[profile[NAME]] = plugin_cfg_list
            if "custom_hostname" in collector_dict:
                self.custom_hostname = collector_dict["custom_hostname"]
            if NODEID in collector_dict:
                self.nodeId = collector_dict[NODEID]

            return True, error_msg
        except KeyError, e:
            error_msg = str(e) + KEY_ERROR
        except Exception as e:
            error_msg = str(e)
        self.logger.error(error_msg)
        return False, error_msg

    def bulid_set_config_result(self):
        """
        result builder
        :return:
        """
        error_msg = ""
        metrics = {}
        try:
            # Build plugin Result
            for profile, plugin_list in self.cfg_dict.items():
                for plugin in plugin_list:
                    if STATUS not in plugin:
                        plugin[STATUS] = "SUCCESS: Plugin configured"
                    if TARGETS in plugin:
                        del plugin[TARGETS]
                    if TAGS in plugin:
                        del plugin[TAGS]
            metrics[PLUGINS] = self.cfg_dict

            # Build Targets Result
            for target in self.target_list:
                if STATUS not in target:
                    target[STATUS] = "SUCCESS: targets configured"
            metrics[TARGETS] = self.target_list
            metrics[ENABLED] = self.collector_dict.get(ENABLED, True)
            return True, metrics
        except Exception as e:
            error_msg += "bulid set config result: "
            error_msg += str(e)
            metrics[ERROR] = error_msg
        self.logger.error(error_msg)
        return False, metrics

    def store_set_config(self):
        """

        :return:
        """
        error_msg = ""
        metrics = {}
        cfg_dict = copy.deepcopy(self.cfg_dict)
        target_list = copy.deepcopy(self.target_list)

        try:
            # Build plugin Result
            for profile, plugin_list in cfg_dict.items():
                for plugin in plugin_list:
                    if STATUS in plugin and "FAILED" in plugin[STATUS]:
                        del cfg_dict[profile]
                        continue
                    if STATUS in plugin:
                        del plugin[STATUS]
                    if TARGETS in plugin:
                        del plugin[TARGETS]
                    if TAGS in plugin:
                        del plugin[TAGS]
            metrics[PLUGINS] = cfg_dict

            # Build Targets Result
            mapping_list = get_supported_targets_mapping()
            for i in range(len(target_list)):
                if STATUS in target_list[i] and "FAILED" in target_list[i][STATUS]:
                    del target_list[i]
                    continue

                if STATUS in target_list[i]:
                    del target_list[i][STATUS]

                    # try:
                    #     keys = []
                    #     if TYPE in target_list[i] and target_list[i][TYPE] in mapping_list.keys():
                    #         keys = mapping_list[target_list[i][TYPE]].keys()
                    #
                    #     for key in target_list[i].keys():
                    #         if key not in keys:
                    #             del target_list[i][key]
                    #
                    # except:
                    #     pass

            metrics[TARGETS] = target_list
            for target in metrics[TARGETS]:
                if "password" in target and target['password']:
                    target["password"] = base64.b64encode(target["password"])
            metrics[ENABLED] = self.collector_dict.get(ENABLED, True)
            metrics[TAGS] = self.collector_dict.get(TAGS, {})
            # Store config data
            file_writer(CollectdData, json.dumps(metrics))
            self.logger.info(" maintain set configuration data for configurator to use")
        except Exception as e:
            error_msg += "configutration storing failed: "
            error_msg += str(e)
            self.logger.error(error_msg)

    def set_config(self):
        """
        set config for API call, root function
        :return:
        """
        error_msg = ""
        return_dict = {}
        if not self.plugin_mapping_list:
            self.logger.error("Plugin Mapping File Error")
            return
        try:
            # converting orchestrator input template to collectd format
            self.logger.info(
                "converting orchestrator input template to collectd format")
            (success, error_msg) = self.create_cfg_list()
            if not success:
                return_dict[ERROR] = error_msg
                self.logger.error("template conversion failed")
                return success, return_dict
            self.logger.info("template conversion successfull")

            # generating config
            self.logger.info("generating config")
            (success, error_msg) = self.generate()
            if not success:
                return_dict[ERROR] = error_msg
                return success, return_dict
            self.logger.info("generating config successfull")

            # delete exsiting configuration
            self.logger.info("delete exsiting configuration")
            (success, error_msg) = delete_collectd_config()
            if not success:
                return_dict[ERROR] = error_msg
                return success, return_dict
            self.logger.info("delete exsiting configuration successfull")

            # push new configuration
            self.logger.info("push configuration")
            (success, error_msg) = push_collectd_configaration(self.success_config)
            if not success:
                return_dict[ERROR] = error_msg
                return success, return_dict
            self.logger.info("push configuration successfull")

            # stop_collectd()
            if self.collector_dict.get(ENABLED, True):
                start_collectd()

            (success, result) = self.bulid_set_config_result()
            if not success:
                return success, result
            self.logger.info("Bulid set configuration result completed")

            # Stored copnfiguration locally.
            self.store_set_config()
            return True, result

        except Exception as e:
            error_msg += str(e)
            return_dict[ERROR] = error_msg
            self.logger.error("Set Collectd config failed")
            self.logger.error(str(e))

        return False, return_dict
