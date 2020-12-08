import copy
import json
import logging
import os
import copy
import json
import logging
import os
import os.path
import tempfile
import time
import unittest
from urllib.parse import urlparse

import requests
import yaml
import os.path
import tempfile
import time
import urllib

import yaml
import re  # noqa: F401
from pathlib import Path
import unittest


from service.awx_service import AWXService
import logging

from service.tosca_helper import ToscaHelper
sure_tosca_base_url = 'http://localhost:8081/tosca-sure/1.0.0'
awx_api = 'http://localhost/api/v2'
awx_username = 'admin'
awx_password = 'password'

class TestAWXService(unittest.TestCase):

    def test(self):
        # parsed_json_message = self.get_request_message_from_url('https://raw.githubusercontent.com/qcdis-sdia/sdia-deployer/develop/sample_requests/provision_request_workflow.json')
        # parsed_json_message = self.get_request_message_from_file('../sample_requests/provision_request_workflow.json')
        # owner = parsed_json_message['owner']
        # tosca_file_name = 'tosca_template'
        # tosca_template_dict = parsed_json_message['toscaTemplate']
        # tosca_template_dict = self.get_tosca_from_url('https://raw.githubusercontent.com/qcdis-sdia/sdia-tosca/develop/examples/workflows.yaml')
        tosca_template_dict = self.get_tosca_from_file('../../sdia-tosca/examples/workflows.yaml')
        topology_template = tosca_template_dict['topology_template']
        node_templates = topology_template['node_templates']
        # tosca_template_path = self.get_tosca_template_path(parsed_json_message)
        tosca_service_is_up = ToscaHelper.service_is_up(sure_tosca_base_url)
        if tosca_service_is_up:
            # tosca_helper = ToscaHelper(sure_tosca_base_url, tosca_template_path)
            # vms = tosca_helper.get_vms()
            # workflows = tosca_helper.get_workflows()
            awx = AWXService(api_url=awx_api,username=awx_username,password=awx_password)
            for tosca_node_name in node_templates:
                tosca_node = node_templates[tosca_node_name]
                worfflow_steps = awx.create_worfflow_steps(tosca_node)
            # if workflows:
            #     for workflow_name in workflows:
            #         workflow = workflows[workflow_name]
            #         awx.create_workflow(workflow,workflow_name)




    def get_request_message_from_url(self,url):
        with urllib.request.urlopen(
                url) as stream:
            parsed_json_message = json.load(stream)
        return parsed_json_message


    def get_tosca_from_url(self,url):
        with urllib.request.urlopen(
                url) as stream:
            parsed_json_message = yaml.load(stream)
        return parsed_json_message

    def get_request_message_from_file(self,path):
        with open(path) as json_file:
            return json.load(json_file)

    def get_tosca_template_path(self,parsed_json_message):
        tosca_file_name = 'tosca_template'
        tosca_template_dict = parsed_json_message['toscaTemplate']

        tmp_path = tempfile.mkdtemp()
        tosca_template_path = tmp_path + os.path.sep + 'toscaTemplate.yml'
        with open(tosca_template_path, 'w') as outfile:
            yaml.dump(tosca_template_dict, outfile, default_flow_style=False)
        return tosca_template_path

    def get_tosca_from_file(self, path):
        with open(path) as json_file:
            return yaml.load(json_file)


if __name__ == '__main__':
    unittest.main()
