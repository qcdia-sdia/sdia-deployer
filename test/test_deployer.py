import copy
import json
import logging
import os
import os.path
import tempfile
import time
import urllib

import yaml
import re  # noqa: F401
from pathlib import Path
import unittest

import sure_tosca_client
from sure_tosca_client import Configuration, ApiClient
from sure_tosca_client.api import default_api

from service.deploy_service import DeployService
from service.tosca_helper import  ToscaHelper

sure_tosca_base_url = 'http://localhost:8081/tosca-sure/1.0.0'
polemarch_base_url = 'http://localhost:30001/api/v2'
semaphore_base_url = 'http://localhost:3000/api'


class TestDeployer(unittest.TestCase):

    def test_inventory(self):
        tosca_service_is_up = ToscaHelper.service_is_up(sure_tosca_base_url)
        semaphore_is_up = ToscaHelper.service_is_up(semaphore_base_url)
        if tosca_service_is_up and semaphore_is_up:
            parsed_json_message = self.get_request_message()
            tosca_template_path = self.get_tosca_template_path(parsed_json_message)
            tosca_helper = ToscaHelper(sure_tosca_base_url, tosca_template_path)
            nodes_pairs = tosca_helper.get_deployment_node_pipeline()
            vms=tosca_helper.get_vms()

    def test(self):
        parsed_json_message = self.get_request_message()
        tosca_template_path = self.get_tosca_template_path(parsed_json_message)
        # owner = parsed_json_message['owner']

        tosca_service_is_up = ToscaHelper.service_is_up(sure_tosca_base_url)
        semaphore_is_up = ToscaHelper.service_is_up(semaphore_base_url)

        if tosca_service_is_up and semaphore_is_up:
            tosca_helper = ToscaHelper(sure_tosca_base_url,tosca_template_path)
            self.assertIsNotNone(tosca_helper.doc_id)
            nodes_to_deploy = tosca_helper.get_application_nodes()
            self.assertIsNotNone(nodes_to_deploy)
            nodes_pairs = tosca_helper.get_deployment_node_pipeline()
            self.assertIsNotNone(nodes_pairs)

            username = 'admin'
            deployService = DeployService(polemarch_base_url=polemarch_base_url,polemarch_username=username,
                                          polemarch_password='admin', semaphore_base_url=semaphore_base_url,
                                          semaphore_username=username,semaphore_password='password',
                                          vms=tosca_helper.get_vms())
            for node_pair in nodes_pairs:
                deployService.deploy(node_pair)





    def get_request_message(self):
        logger = logging.getLogger(__name__)
        with urllib.request.urlopen(
                'https://raw.githubusercontent.com/qcdis-sdia/sdia-deployer/master/sample_requests/deploy_request.json') as stream:
            parsed_json_message = json.load(stream)
        return parsed_json_message

    def get_tosca_template_path(self,parsed_json_message):
        tosca_file_name = 'tosca_template'
        tosca_template_dict = parsed_json_message['toscaTemplate']

        tmp_path = tempfile.mkdtemp()
        tosca_template_path = tmp_path + os.path.sep + 'toscaTemplate.yml'
        with open(tosca_template_path, 'w') as outfile:
            yaml.dump(tosca_template_dict, outfile, default_flow_style=False)
        return tosca_template_path


if __name__ == '__main__':
    import unittest

    unittest.main()
