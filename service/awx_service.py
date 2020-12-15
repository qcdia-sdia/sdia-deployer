import datetime
import tempfile
import time

import ansibleawx
import awxkit
import yaml
from ansible.inventory.manager import InventoryManager
from ansible.parsing.dataloader import DataLoader
from tower_cli import get_resource
from tower_cli.exceptions import Found, AuthError
from tower_cli.conf import settings
import os
import json
import requests
from base64 import b64encode


class AWXService:

    def __init__(self,api_url=None,username=None,password=None):
        self.login(username=username, password=password, api_url=api_url)

    def login(self, username=None, password=None, api_url=None,token=None):
        self._session = requests.Session()
        self.api_url = api_url
        self.headers = None
        if token:
            self.headers = {
                'Authorization': 'Bearer {0}'.format(token),
                'Content-Type' : 'application/json',
                'Accept': 'application/json'
            }
        elif username and password:
            user_pass = '{0}:{1}'.format(username, password).encode()
            user_pass_encoded = b64encode(user_pass).decode()
            self.headers = {
                'Authorization': 'Basic {0}'.format(user_pass_encoded),
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        r = self._session.get(self.api_url + '/me/', headers=self.headers)

        if r.status_code == 403 or r.status_code == 401:
            raise AuthError

    def create_project(self, project_name=None, scm_url=None,scm_branch=None,credential=None,scm_type=None):
        body = {
                'name': project_name,
                'description': '',
                'scm_type': scm_type,
                'scm_url': scm_url,
                'scm_branch': scm_branch,
                'scm_refspec': '',
                'scm_clean': False,
                'scm_delete_on_update': False,
                'credential': credential,
                'timeout': 0,
                'organization': 1,
                'scm_update_on_launch': True,
                'scm_update_cache_timeout': 0,
                'allow_override': False
            }

        return self.post(body,'projects')

    def create_inventory(self, inventory_name=None,inventory=None):
        loader = DataLoader()
        fd, inventory_path = tempfile.mkstemp()
        with os.fdopen(fd, 'w') as outfile:
            yaml.dump(inventory, outfile, default_flow_style=False)
        inventory_manager = InventoryManager(loader=loader, sources=inventory_path)

        body = {
                'name': inventory_name,
                'description': '',
                'organization': 1,
                'kind': '',
                'host_filter': None,
                'variables': '',
                'insights_credential': None
        }
        inventory_id = self.post(body, 'inventories')[0]
        for group_name in inventory_manager.groups:
            group = inventory_manager.groups[group_name]
            if group_name == 'all' or group_name == 'ungrouped':
                for host in group.hosts:
                    inventory_hosts_id = self.create_inventory_hosts(host,inventory_id=inventory_id)
            else:
                inventory_group_ids = self.create_inventory_group(group_name, group, inventory_id)
                for host in group.hosts:
                    inventory_hosts_id = self.create_inventory_hosts(host,inventory_group_id=inventory_group_ids[0])
        return inventory_id

    def create_workflow(self, tosca_workflow, workflow_name):
        description = ''
        if 'description' in tosca_workflow:
            description = tosca_workflow['description']
            steps = tosca_workflow['steps']
        for step_name in steps:
            step = steps[step_name]
            target = step['target']
            activities = step[activities]
        # now = datetime.datetime.now()
        # body = {
        #         'name': workflow_name+'_'+str(now),
        #         'description': description,
        #         'organization': 1,
        #         'survey_enabled': False,
        #         'allow_simultaneous': True,
        #         'ask_variables_on_launch': False,
        #         'scm_branch': '',
        #         'ask_inventory_on_launch': False,
        #         'ask_scm_branch_on_launch': False,
        #         'ask_limit_on_launch': False,
        #         'webhook_service': None,
        #         'webhook_credential': None
        # }
        # r = self._session.post(self.api_url + '/workflow_job_templates/', data=json.dumps(body),headers=self.headers)
        # r_json = r.json()
        # if r.status_code == 400:
        #     if '__all__' in r_json and 'already exists' in r_json['__all__'][0]:
        #         r = self._session.get(self.api_url + '/workflow_job_templates/?name='+workflow_name+'&organization='+str(body['organization']), headers=self.headers)
        #         r_json = r.json()
        #         awx_workflow = r_json.results[0]
        # elif r.status_code == 201:
        #     awx_workflow = r_json
        # print(awx_workflow)

    def post(self, body, api_path):

        r = self._session.post(self.api_url + '/'+api_path+'/', data=json.dumps(body), headers=self.headers)
        ids = []
        if r.status_code == 201:
            id = r.json()['id']
            ids.append(id)
            return ids
        elif r.status_code == 202:
            resp = r.json()
            ids.append(resp['id'])
            return ids
        elif r.status_code == 400 and 'already exists' in r.text:
            r = self._session.get(self.api_url + '/'+api_path+'/?name=' + body['name'],headers=self.headers)
            results = r.json()['results']

            for res in results:
                ids.append(res['id'])
            return ids
        else:
            Exception()
            raise Exception(r.text+'\nRequest Body: '+str(body))



    def create_inventory_group(self, group_name, group,inventory_id):
        if 'inventory_file' in group.vars:
            group.vars.pop('inventory_file')
        if 'inventory_dir' in group.vars:
            group.vars.pop('inventory_dir')
        body = {
            'name': group_name,
            'description': '',
            'variables': json.dumps(group.vars)
        }
        inventory_group_ids = self.post(body,'inventories/'+str(inventory_id)+'/groups')
        return inventory_group_ids

    def create_inventory_hosts(self, host, inventory_id=None,inventory_group_id=None):
        if 'inventory_file' in host.vars:
            host.vars.pop('inventory_file')
        if 'inventory_dir' in host.vars:
            host.vars.pop('inventory_dir')
        inventory_hosts_ids = []
        if inventory_id:
            body = {
                'name': host.address,
                'description': '',
                'inventory': inventory_id,
                'enabled': True,
                'instance_id': '',
                'variables': json.dumps(host.vars)
            }
            inventory_hosts_ids = self.post(body, 'hosts')
            return inventory_hosts_ids
        if inventory_group_id:
            body = {
                'name': host.address,
                'description': '',
                'enabled': True,
                'instance_id': '',
                'variables': json.dumps(host.vars)
            }
            inventory_hosts_ids = self.post(body, 'groups/'+str(inventory_group_id)+'/hosts')
        return inventory_hosts_ids

    def get_resources(self, api_path):
        r = self._session.get(self.api_url + '/' + api_path, headers=self.headers)
        if r.status_code == 200:
            return r.json()['results']
        if r.status_code == 404:
            return None
        else:
            raise Exception(r.text)


    def create_job_template(self,operation):
        job_templates = self.get_resources('job_templates')
        for job in job_templates:
            if job['name'] == operation['name'] and \
                job['inventory'] == operation['inventory'] and \
                job['project'] == operation['project'] and \
                job['playbook'] == operation['implementation']:
                    return [job['id']]

        body = {
            
                'name': operation['name'],
                'description': '',
                'job_type': 'run',
                'inventory': operation['inventory'],
                'project': operation['project'],
                'playbook': operation['implementation'],
                'scm_branch': '',
                'forks': 0,
                'limit': '',
                'verbosity': 0,
                'extra_vars': '',
                'job_tags': '',
                'force_handlers': False,
                'skip_tags': '',
                'start_at_task': '',
                'timeout': 0,
                'use_fact_cache': False,
                'host_config_key': '',
                'ask_scm_branch_on_launch': False,
                'ask_diff_mode_on_launch': False,
                'ask_variables_on_launch': False,
                'ask_limit_on_launch': False,
                'ask_tags_on_launch': False,
                'ask_skip_tags_on_launch': False,
                'ask_job_type_on_launch': False,
                'ask_verbosity_on_launch': False,
                'ask_inventory_on_launch': False,
                'ask_credential_on_launch': False,
                'survey_enabled': False,
                'become_enabled': False,
                'diff_mode': False,
                'allow_simultaneous': False,
                'custom_virtualenv': None,
                'job_slice_count': 1,
                'webhook_service': None,
                'webhook_credential': None
            }

        fail_count = 0
        job_templates_ids = None
        while fail_count<20:
            try:
                return self.post(body,'job_templates')
            except Exception as ex:
                if 'Playbook not found for project' in str(ex):
                    fail_count += 1
                    update_ids = self.update_project(operation['project'])
                    time.sleep(2)
                    return self.post(body, 'job_templates')
                if fail_count >= 20:
                    raise ex
                else:
                    raise ex
        return job_templates_ids


    def create_worfflow_steps(self, tosca_node):
        if 'interfaces' in tosca_node:
            workflow_steps = []
            interfaces = tosca_node['interfaces']
            for interface_name in interfaces:
                for step_name in interfaces[interface_name]:
                    workflow_step = {}
                    step = interfaces[interface_name][step_name]
                    if 'inputs' in step and 'repository' in step['inputs']:
                        repository_url = step['inputs']['repository']
                        workflow_step['name'] = interface_name+'.'+step_name
                        project_id = self.create_project(project_name=repository_url, scm_url=repository_url,
                                                        scm_branch='master', scm_type='git')
                        workflow_step['project'] = project_id[0]
                        inventory = step['inputs']['inventory']
                        inventory_id = self.create_inventory(inventory_name=workflow_step['name'],inventory=inventory)
                        workflow_step['inventory'] = inventory_id
                    if 'implementation' in interfaces[interface_name][step_name]:
                        workflow_step['implementation'] = interfaces[interface_name][step_name]['implementation']
                        workflow_step['job_template'] =  self.create_job_template(workflow_step)[0]
                    if workflow_step:
                        workflow_steps.append(workflow_step)
            return workflow_steps

    def update_project(self, project_id):
        body = {}
        resp = self.post(body,'projects/'+str(project_id)+'/update')
        pass