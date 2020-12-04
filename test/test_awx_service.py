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
        parsed_json_message = self.get_request_message_from_url('https://raw.githubusercontent.com/qcdis-sdia/sdia-deployer/develop/sample_requests/provision_request_workflow.json')
        owner = parsed_json_message['owner']
        tosca_file_name = 'tosca_template'
        tosca_template_dict = parsed_json_message['toscaTemplate']
        tosca_template_path = self.get_tosca_template_path(parsed_json_message)
        tosca_service_is_up = ToscaHelper.service_is_up(sure_tosca_base_url)
        if tosca_service_is_up:
            tosca_helper = ToscaHelper(sure_tosca_base_url, tosca_template_path)
            workflows = tosca_helper.get_workflows()
            awx = AWXService(api_url=awx_api,username=awx_username,password=awx_password)
            if workflows:
                for workflow_name in workflows:
                    workflow = workflows[workflow_name]
                    awx.create_workflow(workflow,workflow_name)






    def get_request_message_from_url(self,url):
        logger = logging.getLogger(__name__)
        with urllib.request.urlopen(
                url) as stream:
            parsed_json_message = json.load(stream)
        return parsed_json_message

    def get_request_message_from_file(self,path):
        with open(path, 'w') as outfile:
            return yaml.dump(path, outfile, default_flow_style=False)

    def get_tosca_template_path(self,parsed_json_message):
        tosca_file_name = 'tosca_template'
        tosca_template_dict = parsed_json_message['toscaTemplate']

        tmp_path = tempfile.mkdtemp()
        tosca_template_path = tmp_path + os.path.sep + 'toscaTemplate.yml'
        with open(tosca_template_path, 'w') as outfile:
            yaml.dump(tosca_template_dict, outfile, default_flow_style=False)
        return tosca_template_path

if __name__ == '__main__':
    unittest.main()