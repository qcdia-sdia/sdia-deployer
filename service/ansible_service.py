import base64
import logging
from time import sleep

import yaml
from semaphore_client.semaphore_helper import SemaphoreHelper

yaml.Dumper.ignore_aliases = lambda *args : True

logger = logging.getLogger(__name__)
if not getattr(logger, 'handler_set', None):
    logger.setLevel(logging.INFO)
    h = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    h.setFormatter(formatter)
    logger.addHandler(h)
    logger.handler_set = True


class AnsibleService:

    def __init__(self, semaphore_base_url=None,semaphore_username=None,semaphore_password=None):
        self.semaphore_base_url = semaphore_base_url
        self.semaphore_username = semaphore_username
        self.semaphore_password = semaphore_password
        self.semaphore_helper = SemaphoreHelper(self.semaphore_base_url, self.semaphore_username, self.semaphore_password)
        self.repository_id = None
        self.template_id = None



    def execute(self,nodes_pair):
        vms = nodes_pair[0]
        orchestrator = nodes_pair[1]
        name = orchestrator.name
        desired_state = None
        interfaces = orchestrator.node_template.interfaces
        if 'current_state' in orchestrator.node_template.attributes:
            current_state = orchestrator.node_template.attributes['current_state']
        if 'desired_state' in orchestrator.node_template.attributes:
            desired_state = orchestrator.node_template.attributes['desired_state']

        if desired_state:
            project_id = self.semaphore_helper.create_project(orchestrator.name)
            inventory_contents = yaml.dump( self.build_yml_inventory(vms),default_flow_style=False)
            private_key = self.get_private_key(vms)
            key_id = self.semaphore_helper.create_ssh_key(orchestrator.name, project_id, private_key)
            inventory_id = self.semaphore_helper.create_inventory(orchestrator.name, project_id, key_id,inventory_contents)
            if 'RUNNING' == desired_state:
                standard = interfaces['Standard']
                create = standard['create']
                inputs = create['inputs']
                git_url = inputs['repository']
                playbook_names = inputs['playbooks']
                for playbook_name in playbook_names:
                    task_id = self.run_task(name, project_id, key_id, git_url, inventory_id, playbook_name)
                    if self.semaphore_helper.get_task(project_id, task_id).status != 'success':
                        break

                if self.semaphore_helper.get_task(project_id,task_id).status == 'success':
                    configure = standard['configure']
                    inputs = configure['inputs']
                    git_url = inputs['repository']
                    playbook_names = inputs['playbooks']
                    for playbook_name in playbook_names:
                        task_id = self.run_task(name, project_id, key_id, git_url, inventory_id, playbook_name)
                        if self.semaphore_helper.get_task(project_id, task_id).status != 'success':
                            break

    def build_yml_inventory(self, vms):
        # loader = DataLoader()
        # inventory = InventoryManager(loader=loader)
        # variable_manager = VariableManager()
        inventory = {}
        all = {}
        vars = {'ansible_ssh_common_args':'-o StrictHostKeyChecking=no'}
        vars['ansible_ssh_user'] = vms[0].node_template.properties['user_name']
        children = {}
        for vm in vms:
            attributes = vm.node_template.attributes
            role = attributes['role']
            public_ip = attributes['public_ip']
            if role not in children:
                hosts = {}
            else:
                hosts = children[role]
            host = {}
            host[public_ip] =  vars
            hosts['hosts'] = host
            children[role] = hosts
            # inventory.add_group(role)
            # inventory.add_host(public_ip,group=role)
        all['children'] = children
        inventory['all'] = all
        return inventory

    def get_private_key(self, vms):
        private_key = vms[0].node_template.attributes['user_key_pair']['keys']['private_key']
        return base64.b64decode(private_key).decode('utf-8').replace(r'\n', '\n')

    def run_task(self, name, project_id, key_id, git_url, inventory_id, playbook_name):
        logger.info('project_id: '+str(project_id)+ ' task name: ' + str(name)+ ' git url: '+git_url+' playbook: '+playbook_name)
        if not self.repository_id:
            self.repository_id = self.semaphore_helper.create_repository(name, project_id, key_id, git_url)
        template_id = self.semaphore_helper.create_template(project_id, key_id, inventory_id, self.repository_id,
                                                            playbook_name)
        task_id = self.semaphore_helper.execute_task(project_id, template_id, playbook_name)
        task = self.semaphore_helper.get_task(project_id, task_id)
        last_output = ''
        while task.status == 'waiting' or task.status == 'running':
            task = self.semaphore_helper.get_task(project_id, task_id)
            logger.info('task name: '+name+ ' task status: ' + str(task.status))
            task_outputs = self.semaphore_helper.get_task_outputs(project_id, task_id)
            this_output = task_outputs[len(task_outputs)-1].output.replace(r'\n', '\n').replace(r'\r', '\r')
            if last_output != this_output:
                logger.info('task output: ' + str(this_output))
            last_output = this_output

            # logger.info('task output: ' + str(latask name:st_output))
            sleep(3)
        return task_id

