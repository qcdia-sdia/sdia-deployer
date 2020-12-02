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

from ansible_task import AnsibleTask
from service.workflow_service import WorkflowService
import logging

class TestWorkflowService(unittest.TestCase):

    def test_something(self):
        tosca = self.get_tosca_file('https://raw.githubusercontent.com/qcdis-sdia/sdia-tosca/master/examples/workflows.yaml')
        workflows = tosca['topology_template'].pop('workflows')
        for workflow_name in workflows:
            workflow = workflows[workflow_name]
            for step_name in workflow['steps']:
                step = workflow['steps'][step_name]
                target = step['target']
                interfaces = tosca['topology_template']['node_templates'][target]['interfaces']
                for tasks in step['activities']:
                    call_operation = tasks['call_operation']
                    call_operation_parts = call_operation.split('.')
                    interface_name = call_operation_parts[0]
                    operation = call_operation_parts[1]
                    interface = interfaces[interface_name]




        # tasks = ['openstack/install_requirements.yaml','openstack/info/get_images.yaml','openstack/info/get_images.yaml']
        # for task in tasks:
        #
        #     task1 = AnsibleTask(repository='https://github.com/QCDIS/playbooks.git',
        #                         playbook_file='openstack/install_requirements.yaml')


        # wfs = WorkflowService(task1)

    def get_tosca_file(self,url):
        logger = logging.getLogger(__name__)
        with urllib.request.urlopen(
                url) as stream:
            tosca_dict = yaml.safe_load(stream)
        return tosca_dict

if __name__ == '__main__':
    unittest.main()
