import json
import os
import tempfile
import time
import uuid
from base64 import b64encode
import networkx as nx
import logging
import matplotlib.pyplot as plt
import requests
import yaml
import ansible.inventory.manager
from ansible.inventory.manager import InventoryManager
from ansible.parsing.dataloader import DataLoader
import tower_cli.exceptions
logger = logging.getLogger(__name__)

class AWXService:

    def __init__(self, api_url=None, username=None, password=None):
        self.login(username=username, password=password, api_url=api_url)

    def login(self, username=None, password=None, api_url=None, token=None):
        self._session = requests.Session()
        self.api_url = api_url
        self.headers = None
        if token:
            self.headers = {
                'Authorization': 'Bearer {0}'.format(token),
                'Content-Type': 'application/json',
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
            raise tower_cli.exceptions.AuthError

    def create_project(self, project_name=None, scm_url=None, scm_branch=None, credential=None, scm_type=None):
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

        return self.post(body, 'projects')

    def create_inventory(self, inventory_name=None, inventory=None):
        loader = DataLoader()
        fd, inventory_path = tempfile.mkstemp()
        with os.fdopen(fd, 'w') as outfile:
            yaml.dump(inventory, outfile, default_flow_style=False)
        inventory_manager: InventoryManager = ansible.inventory.manager.InventoryManager(loader=loader, sources=inventory_path)

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
                    inventory_hosts_id = self.create_inventory_hosts(host, inventory_id=inventory_id)
            else:
                inventory_group_ids = self.create_inventory_group(group_name, group, inventory_id)
                for host in group.hosts:
                    inventory_hosts_id = self.create_inventory_hosts(host, inventory_group_id=inventory_group_ids[0])
        return inventory_id

    def create_workflow(self, description=None, workflow_name=None, topology_template_workflow_steps=None) -> list:
        description = ''
        body = {
            'name': workflow_name,
            'description': description,
            'organization': 1,
            'survey_enabled': False,
            'allow_simultaneous': True,
            'ask_variables_on_launch': False,
            'scm_branch': '',
            'ask_inventory_on_launch': False,
            'ask_scm_branch_on_launch': False,
            'ask_limit_on_launch': False,
            'webhook_service': None,
            'webhook_credential': None
        }
        return self.post(body, 'workflow_job_templates')




    def post(self, body, api_path):

        r = self._session.post(self.api_url + '/' + api_path + '/', data=json.dumps(body), headers=self.headers)
        ids = []
        if r.status_code == 201 or r.status_code == 202 or r.status_code == 204:
            if r.text:
                json_resp = r.json()
                if 'id' in json_resp:
                    id = json_resp['id']
                    ids.append(id)
            return ids
        elif r.status_code == 400 and 'already exists' in r.text:
            if 'name' in body:
                r = self._session.get(self.api_url + '/' + api_path + '/?name=' + body['name'], headers=self.headers)
            elif 'identifier' in body:
                r = self._session.get(self.api_url + '/' + api_path + '/?identifier=' + body['identifier'], headers=self.headers)
            results = r.json()['results']

            for res in results:
                ids.append(res['id'])
            return ids
        else:
            raise Exception('Response Code:'+ str(r.status_code) +' '+r.text + '\nRequest Body: ' + str(body))

    def create_inventory_group(self, group_name, group, inventory_id):
        if 'inventory_file' in group.vars:
            group.vars.pop('inventory_file')
        if 'inventory_dir' in group.vars:
            group.vars.pop('inventory_dir')
        body = {
            'name': group_name,
            'description': '',
            'variables': json.dumps(group.vars)
        }
        inventory_group_ids = self.post(body, 'inventories/' + str(inventory_id) + '/groups')
        return inventory_group_ids

    def create_inventory_hosts(self, host, inventory_id=None, inventory_group_id=None):
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
            inventory_hosts_ids = self.post(body, 'groups/' + str(inventory_group_id) + '/hosts')
        return inventory_hosts_ids

    def get_resources(self, api_path):
        r = self._session.get(self.api_url + '/' + api_path, headers=self.headers)
        if r.status_code == 200:
            res_json = r.json()
            if 'results' in res_json:
                return res_json['results']
            else:
                return res_json
        if r.status_code == 404:
            return None
        else:
            raise Exception(r.text)

    def create_job_template(self, operation):
        operation_name = list(operation.keys())[0]
        job_templates = self.get_resources('job_templates')
        for job in job_templates:
            if job['name'] == operation_name and \
                    job['inventory'] == operation[operation_name]['inventory'] and \
                    job['project'] == operation[operation_name]['project'] and \
                    job['playbook'] == operation[operation_name]['implementation']:
                return [job['id']]

        body = {

            'name': operation_name,
            'description': '',
            'job_type': 'run',
            'inventory': operation[operation_name]['inventory'],
            'project': operation[operation_name]['project'],
            'playbook': operation[operation_name]['implementation'],
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
        while fail_count < 60:
            try:
                return self.post(body, 'job_templates')
            except Exception as ex:
                if 'Playbook not found for project' in str(ex):
                    fail_count += 1
                    time.sleep(6.5)
                    logger.warning(str(ex) + '. Retrying to update project fail_count: '+str(fail_count))
                    update_ids = self.update_project(operation[operation_name]['project'])
                elif fail_count >= 60:
                    raise ex
                else:
                    raise ex
        return job_templates_ids

    def create_workflow_steps(self, tosca_node):
        if 'interfaces' in tosca_node:
            workflow_steps = {}
            interfaces = tosca_node['interfaces']
            for interface_name in interfaces:
                for step_name in interfaces[interface_name]:
                    workflow_step = {}
                    step = interfaces[interface_name][step_name]
                    wf_name = interface_name + '.' + step_name
                    logger.info('Creating steps: ' + wf_name)
                    if 'inputs' in step and 'repository' in step['inputs']:
                        repository_url = step['inputs']['repository']

                        project_id = self.create_project(project_name=repository_url, scm_url=repository_url,
                                                         scm_branch='master', scm_type='git')
                        workflow_step[wf_name] = {'project': project_id[0]}

                        inventory = step['inputs']['inventory']
                        inventory_id = self.create_inventory(inventory_name=wf_name, inventory=inventory)
                        workflow_step[wf_name]['inventory'] = inventory_id
                    if 'implementation' in interfaces[interface_name][step_name]:
                        workflow_step[wf_name]['implementation'] = interfaces[interface_name][step_name][
                            'implementation']
                        workflow_step[wf_name]['job_template'] = self.create_job_template(workflow_step)[0]
                    if workflow_step:
                        workflow_steps.update(workflow_step)
            return workflow_steps

    def update_project(self, project_id):
        body = {}
        resp = self.post(body, 'projects/' + str(project_id) + '/update')
        return resp

    def create_on_success_node(self, parent_node_id, success_job_template_id):
        body = {
            'extra_data': {},
            'inventory': None,
            'scm_branch': '',
            'job_type': None,
            'job_tags': '',
            'skip_tags': '',
            'limit': '',
            'diff_mode': None,
            'verbosity': None,
            'unified_job_template': str(success_job_template_id),
            'all_parents_must_converge': None,
            'identifier': str(uuid.uuid1())
        }
        success_node_ids = self.post(body,'workflow_job_template_nodes/'+str(parent_node_id)+'/success_nodes')
        return success_node_ids

    def create_dag(self,workflow_id=None,tosca_workflow=None,topology_template_workflow_steps=None):
        graph = nx.DiGraph()
        steps = tosca_workflow['steps']
        for step_name in steps:
            graph.add_node(step_name)
            logger.info('Creating step: '+step_name)
            step = steps[step_name]
            activities = step['activities']
            for activity in activities:
                if 'on_success' in activity:
                    graph = self.add_edge(graph=graph,parent_name=step_name, children=activity['on_success'],label='on_success')
                if 'on_failure' in activity:
                    graph = self.add_edge(graph=graph,parent_name=step_name, children=activity['on_failure'],label='on_failure')
        for step_name in graph:
            if graph.in_degree(step_name) == 0:
                step = steps[step_name]
                activities = step['activities']
                for activity in activities:
                    parent_node_ids = None
                    if 'call_operation' in activity:
                        call_operation = activity['call_operation']
                        parent_node_ids = self.create_root_workflow_node(workflow_id=workflow_id,
                                                                         job_template_id=topology_template_workflow_steps[call_operation]['job_template'],
                                                                         step_name=step_name)
                    on_success_children = None
                    on_failure_children = None
                    if parent_node_ids:
                        if 'on_success' in activity:
                            on_success_children = activity['on_success']
                        if 'on_failure' in activity:
                            on_failure_children = activity['on_failure']


                        if on_success_children:
                            label = 'on_success'
                            children=activity[label]
                            if isinstance(children, list):
                                for child in children:
                                    workflow_node_ids = self.create_workflow_nodes(parent_id=parent_node_ids[0],
                                                                                   child=child,
                                                                                   label=label,
                                                                                   steps=steps,
                                                                                   topology_template_workflow_steps=topology_template_workflow_steps)

                        if on_failure_children:
                            label = 'on_failure'
                            children=activity[label]
                            if isinstance(children, list):
                                for child in children:
                                    workflow_node_ids = self.create_workflow_nodes(parent_id=parent_node_ids[0],
                                                                                   child=child,
                                                                                   label=label,
                                                                                   steps=steps,
                                                                                   topology_template_workflow_steps=topology_template_workflow_steps)
        return None

    def add_edge(self,graph=None,parent_name=None, children=None,label=None):
        if isinstance(children, list):
            for child in children:
                self.add_edge(graph=graph,parent_name=parent_name, children=child,label=label)
        elif isinstance(children, str):
            child = children
            graph.add_edge(parent_name,child,label=label)
        return graph

    def create_root_workflow_node(self, workflow_id, job_template_id,step_name):
        body = {
                'extra_data': {},
                'inventory': None,
                'scm_branch': None,
                'job_type': None,
                'job_tags': None,
                'skip_tags': None,
                'limit': None,
                'diff_mode': None,
                'verbosity': None,
                'unified_job_template': job_template_id,
                'all_parents_must_converge': True,
                'identifier': step_name
                }
        workflow_job_template_node_ids = self.post(body,'workflow_job_templates/'+str(workflow_id)+'/workflow_nodes')
        return workflow_job_template_node_ids

    def create_workflow_nodes(self, parent_id, child, label, steps, topology_template_workflow_steps):
        path = 'workflow_job_template_nodes/' + str(parent_id) + '/'
        if label == 'on_success':
            path += 'success_nodes'
        if label == 'on_failure':
            path += 'failure_nodes'
        activities = steps[child]['activities']
        for activity in activities:
            if 'call_operation' in activity:
                call_operation = activity['call_operation']
                child_id = self.add_child_node(identifier=child,
                                               unified_job_template=topology_template_workflow_steps[call_operation]['job_template'],
                                               path=path)
                on_success_children = None
                on_failure_children = None
                if 'on_success' in activity:
                    on_success_children = activity['on_success']
                if 'on_failure' in activity:
                    on_failure_children = activity['on_failure']
                if on_success_children:
                    if isinstance(on_success_children, list) and child_id:
                        for child in on_success_children:
                            self.create_workflow_nodes(parent_id=child_id,
                                                       child=child,
                                                       label='on_success',
                                                       steps=steps,
                                                       topology_template_workflow_steps=topology_template_workflow_steps)
                    if isinstance(on_success_children, str) and child_id:
                        child = on_success_children
                        self.create_workflow_nodes(parent_id=child_id,
                                                   child=child,
                                                   label='on_success',
                                                   steps=steps,
                                                   topology_template_workflow_steps=topology_template_workflow_steps)
                if on_failure_children:
                    if isinstance(on_failure_children, list) and child_id:
                        for child in on_failure_children:
                            self.create_workflow_nodes(parent_id=child_id,
                                                       child=child,
                                                       label='on_failure',
                                                       steps=steps,
                                                       topology_template_workflow_steps=topology_template_workflow_steps)
                    if isinstance(on_failure_children, str) and child_id:
                        child = on_success_children
                        self.create_workflow_nodes(parent_id=child_id,
                                                   child=child,
                                                   label='on_failure',
                                                   steps=steps,
                                                   topology_template_workflow_steps=topology_template_workflow_steps)
        return None

    def add_child_node(self, identifier, unified_job_template, path):
        res = self.get_resources('workflow_job_template_nodes/?identifier=' + identifier)
        child_id = None
        if res:
            child_id = res[0]['id']

        body = {
            'id': child_id,
            'extra_data': {},
            'inventory': None,
            'scm_branch': '',
            'job_type': None,
            'job_tags': '',
            'skip_tags': '',
            'limit': '',
            'diff_mode': None,
            'verbosity': None,
            'unified_job_template': unified_job_template,
            'all_parents_must_converge': True,
            'identifier': identifier
        }
        res = self.post(body, path)
        if not child_id and res:
            child_id = res[0]
        return child_id

    def launch(self, wf_id):
        path = 'workflow_job_templates/'+str(wf_id)+'/launch'
        body = {
            'ask_limit_on_launch': False,
            'ask_scm_branch_on_launch': False
        }
        wf_job_ids = self.post(body, path)
        return wf_job_ids

    # def get_workflow_nodes(self, launched_id):
    #     path = 'workflow_jobs/'+str(launched_id)+'/workflow_nodes'
    #     workflow_nodes = self.get_resources(path)
    #     return workflow_nodes

    def get_job_artefacts(self, attributes_job_id):
        job_output = self.get_resources('jobs/'+str(attributes_job_id)+'/')
        return job_output['artifacts']

    def get_attribute_job_id(self, wf_job_id):
        workflow_nodes = self.get_resources('workflow_jobs/'+str(wf_job_id)+'/workflow_nodes/')
        for wf_node in workflow_nodes:
            if not wf_node['success_nodes'] and not wf_node['failure_nodes']and not wf_node['always_nodes']:
                return wf_node['id']
        return None

    def get_job_status(self, launched_id):
        workflow = self.get_resources('workflow_jobs/' + str(launched_id) + '/')
        return workflow['status']

    def set_tosca_node_attributes(self, tosca_template_dict, attributes):
        for node in tosca_template_dict['topology_template']['node_templates']:
            if 'attributes' in node:
                node['attributes'].update(attributes)
        return tosca_template_dict




