import base64
import json
import logging
import os
import random
import string
import tempfile
import time
import uuid
from base64 import b64encode

import ansible.inventory.manager
import networkx as nx
import requests
import tower_cli.exceptions
import validators
import yaml
from ansible.inventory.manager import InventoryManager
from ansible.parsing.dataloader import DataLoader

logger = logging.getLogger(__name__)

class AWXService:

    def __init__(self, api_url=None, username=None, password=None,tosca_helper=None):
        self.login(username=username, password=password, api_url=api_url)
        self.tosca_helper = tosca_helper

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
        r = self._session.get(self.api_url + '/me/', headers=self.headers,verify=False)

        if r.status_code == 403 or r.status_code == 401:
            raise tower_cli.exceptions.AuthError

    def create_project(self, project_name=None, scm_url=None, scm_branch=None, credential=None, scm_type=None,organization_id=None):

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
            'organization': organization_id,
            'scm_update_on_launch': True,
            'scm_update_cache_timeout': 0,
            'allow_override': False
        }

        return self.post(body, 'projects')

    def create_inventory(self, inventory_name=None, inventory=None,organization_id=None):
        loader = DataLoader()
        fd, inventory_path = tempfile.mkstemp()
        with os.fdopen(fd, 'w') as outfile:
            yaml.dump(inventory, outfile, default_flow_style=False)
        inventory_manager: InventoryManager = ansible.inventory.manager.InventoryManager(loader=loader, sources=inventory_path)

        body = {
            'name': inventory_name,
            'description': '',
            'organization': organization_id,
            'kind': '',
            'host_filter': None,
            'variables': '',
            'insights_credential': None
        }
        inventory_ids = self.get_resources('inventories/?name='+inventory_name+'&organization='+str(organization_id))
        if inventory_ids and inventory_ids[0]:
            inventory_id = self.put(body, 'inventories/'+str(inventory_ids[0]['id']))[0]
        else:
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

    def create_workflow(self, description=None, workflow_name=None, topology_template_workflow_steps=None,organization_id=None) -> list:
        description = ''
        body = {
            'name': workflow_name,
            'description': description,
            'organization': organization_id,
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
        r = self._session.post(self.api_url + '/' + api_path + '/', data=json.dumps(body), headers=self.headers,verify=False)
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
                r = self._session.get(self.api_url + '/' + api_path + '/?name=' + body['name'], headers=self.headers,verify=False)
            elif 'identifier' in body:
                r = self._session.get(self.api_url + '/' + api_path + '/?identifier=' + body['identifier'], headers=self.headers,verify=False)
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
        self.delete('inventories', '?name=' + group_name)
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
            # hosts = self.get_resources('hosts/?name='+host.address)
            # if hosts and hosts[0]:
            #     inventory_hosts_ids = self.put(body, 'hosts/'+str(hosts[0]['id']))
            # else:
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
            self.delete('groups', '?name=' + host.address)
            inventory_hosts_ids = self.post(body, 'groups/' + str(inventory_group_id) + '/hosts')
        return inventory_hosts_ids

    def get_resources(self, api_path):
        r = self._session.get(self.api_url + '/' + api_path, headers=self.headers,verify=False)
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

    def create_job_template(self, operation=None,credential=None,organization_id=None,extra_vars=None):
        operation_name = list(operation.keys())[0]

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
            'extra_vars': json.dumps(extra_vars),
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
                job_templates = \
                self.get_resources('job_templates/?name=' + operation_name + '&organization=' + str(organization_id))
                if job_templates:
                    job_template = job_templates[0]
                    job_templates_ids = self.put(body, 'job_templates/'+str(job_template['id']))
                else:
                    job_templates_ids = self.post(body, 'job_templates')
                if credential:
                    # rnd_str = ''.join(random.choice(string.ascii_lowercase) for i in range(5))
                    credential_ids = self.add_credentials(credential=credential,
                                                          path='job_templates/'+str(job_templates_ids[0])+'/credentials',
                                                          organization_id=organization_id,name=operation_name)
                return job_templates_ids
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

    def create_workflow_steps(self, tosca_node,organization_id=None,credential=None):
        if 'interfaces' in tosca_node:
            workflow_steps = {}
            interfaces = tosca_node['interfaces']
            for interface_name in interfaces:
                ancestors = self.tosca_helper.get_interface_ancestors(interface_name)
                if 'tosca.interfaces.QC.Ansible' in ancestors:
                    for step_name in interfaces[interface_name]:
                        workflow_step = {}
                        step = interfaces[interface_name][step_name]
                        wf_name = interface_name + '.' + step_name
                        logger.info('Creating steps: ' + wf_name)
                        extra_variables = None
                        if 'inputs' in step and 'repository' in step['inputs']:
                            repository_url = step['inputs']['repository']
                            project_id = self.create_project(project_name=repository_url, scm_url=repository_url,
                                                             scm_branch='master', scm_type='git',organization_id=organization_id)
                            workflow_step[wf_name] = {'project': project_id[0]}
                            if not 'inventory' in step['inputs']:
                                raise Exception(step_name + ' has no inventory')
                            inventory = step['inputs']['inventory']
                            inventory_id = self.create_inventory(inventory_name=wf_name, inventory=inventory,organization_id=organization_id)
                            workflow_step[wf_name]['inventory'] = inventory_id
                        if 'implementation' in step['inputs']:
                            if 'extra_variables' in step['inputs']:
                                extra_variables = self.get_variables(extra_variables=step['inputs']['extra_variables'])
                            workflow_step[wf_name]['implementation'] = step['inputs'][
                                'implementation']
                            workflow_step[wf_name]['job_template'] = self.create_job_template(workflow_step,
                                                                                              credential=credential,
                                                                                              organization_id=organization_id,
                                                                                              extra_vars=extra_variables)[0]
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
        # Don't look at this you face will melt
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
                    parent_node_ids = []
                    if 'call_operation' in activity:
                        call_operation = activity['call_operation']
                        parent_node_ids.append(self.create_root_workflow_node(workflow_id=workflow_id,
                                                                            job_template_id=topology_template_workflow_steps[call_operation]['job_template'],
                                                                            step_name=step_name)[0])
                    for parent_node in parent_node_ids:
                        for outcome in ['on_failure', 'on_success']:
                            if outcome in activity:
                                node_children = activity[outcome]
                                children = []
                                if isinstance(node_children, str):
                                    children.append(node_children)
                                elif isinstance(node_children, list):
                                    children = node_children
                                for child in children:
                                    workflow_node_ids = self.create_workflow_nodes(parent_id=parent_node,
                                                                                    child=child,
                                                                                    label=outcome,
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
                for outcome in ['on_failure','on_success']:
                    if outcome in activity:
                        node_children = activity[outcome]
                        children = []
                        if isinstance(node_children, str):
                            children.append(node_children)
                        elif isinstance(node_children, list):
                            children = node_children
                        for child in children:
                            self.create_workflow_nodes(parent_id=child_id,
                                                       child=child,
                                                       label=outcome,
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

    def get_job_artifacts(self, attributes_job_id):
        job_output = self.get_resources('jobs/'+str(attributes_job_id)+'/')
        return job_output['artifacts']

    def get_attribute_job_id(self, wf_job_id):
        workflow_nodes = self.get_resources('workflow_jobs/'+str(wf_job_id)+'/workflow_nodes/')
        for wf_node in workflow_nodes:
            if not wf_node['success_nodes'] and not wf_node['failure_nodes'] and not wf_node['always_nodes'] and 'job' \
                    in wf_node and 'attributes' in wf_node['identifier']:
                return wf_node['job']
        return None

    def get_job_status(self, launched_id):
        workflow = self.get_resources('workflow_jobs/' + str(launched_id) + '/')
        return workflow['status']

    def set_tosca_node_attributes(self, tosca_template_dict, attributes):
        node_templates = tosca_template_dict['topology_template']['node_templates']
        for node_name in attributes:
            if 'attributes' in node_templates[node_name]:
                node_attributes = node_templates[node_name]['attributes']
            else:
                node_attributes ={}
            node_attributes.update(attributes[node_name])
            node_templates[node_name]['attributes'] = node_attributes
        return tosca_template_dict

    def add_credentials(self, credential=None,organization_id=None,path=None,name=None):
        if credential:
            body = {}
            if 'protocol' in credential and 'ssh' == credential['protocol']:
                decoded_key = base64.b64decode(credential['keys']['private_key'])
                decoded_key_str = str(decoded_key, "utf-8")
                body = {
                    "name": name,
                    "organization": organization_id,
                    "credential_type": 1,
                    "inputs": {
                        "ssh_key_data": decoded_key_str,
                    }
                }
            if 'cloud_provider_name' in credential:
                if credential['cloud_provider_name'] == 'Azure':
                    body = {
                        "name": name,
                        "organization": organization_id,
                        "credential_type": 11,
                        "inputs": {
                            "client": credential['user'],
                            "secret": credential['token'],
                            "tenant": credential['extra_properties']['tenant'],
                            "subscription": credential['extra_properties']['subscription_id']
                        }
                }
            credentials = self.get_resources('credentials/?name='+name+'&organization='+str(organization_id))
            if credentials and credentials[0]:
                credential_ids = self.put(body,'credentials/'+str(credentials[0]['id']))
            else:
                credential_ids = self.post(body, path)
            return credential_ids
        return None

    def create_organization(self, name):
        body = {
            "name": name,
            "description": "",
            "max_hosts": 99
        }
        organization_id = self.post(body, 'organizations')
        return organization_id[0]

    def delete(self, api_path,query):
        resources = self.get_resources(api_path+'/'+query)
        if resources:
            for inventory in resources:
                r = self._session.delete(self.api_url +'/'+api_path+'/' + str(inventory['id']), headers=self.headers, verify=False)
        # else:
        #     raise Exception('Response Code:'+ str(r.status_code) +' '+r.text + '\nRequest Body: ' + str(body))

    def get_variables(self, extra_variables):
        if not isinstance(extra_variables,dict):
            valid = validators.url(extra_variables)
            if valid == True:
                url = requests.get(extra_variables)
                text = url.text
                try:
                    tup_json = json.loads(text)
                    return tup_json
                except:
                    return yaml.load(text)
        elif isinstance(extra_variables, dict):
            return extra_variables

    def put(self, body, api_path):
        r = self._session.put(self.api_url + '/' + api_path + '/', data=json.dumps(body), headers=self.headers,verify=False)
        ids = []
        if r.status_code == 200:
            if r.text:
                json_resp = r.json()
                if 'id' in json_resp:
                    id = json_resp['id']
                    ids.append(id)
            return ids
        else:
            raise Exception('Response Code:'+ str(r.status_code) +' '+r.text + '\nRequest Body: ' + str(body))
        pass