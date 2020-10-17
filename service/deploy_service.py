import json
import logging

from service import tosca_helper
from service.ansible_service import AnsibleService

logger = logging.getLogger(__name__)
if not getattr(logger, 'handler_set', None):
    logger.setLevel(logging.INFO)
    h = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    h.setFormatter(formatter)
    logger.addHandler(h)
    logger.handler_set = True

class DeployService:

    def __init__(self, polemarch_base_url=None,polemarch_username=None,polemarch_password=None,
                 semaphore_base_url=None,semaphore_username=None,semaphore_password=None, vms=None):
        # self.polemarch_base_url = polemarch_base_url
        # self.polemarch_username=polemarch_username
        # self.polemarch_password = polemarch_password
        self.semaphore_base_url = semaphore_base_url
        self.semaphore_username = semaphore_username
        self.semaphore_password = semaphore_password
        self.vms = vms
        for vm in vms:
            if vm.node_template.attributes['role'] == 'master':
                self.master_ip = vm.node_template.attributes['public_ip']
                break

    def deploy(self, application):
        # target = nodes_pair[0]
        # source = nodes_pair[1]
        interface_types = tosca_helper.get_interface_types(application)
        if interface_types:
            ansible_service = AnsibleService(self.semaphore_base_url, self.semaphore_username, self.semaphore_password)
            env_vars = self.get_env_vars(application)
            if 'Standard' in interface_types:
                task_outputs = ansible_service.execute(application, 'Standard', self.vms, env_vars=env_vars)
                application = self.set_attributes(task_outputs, application)
            if 'Kubernetes' in interface_types:
                task_outputs = ansible_service.execute(application, 'Kubernetes', self.vms, env_vars=env_vars)
                application = self.set_attributes(task_outputs, application)
        return application

    def get_env_vars(self, source):
        # target = nodes_pair[0]
        # source = nodes_pair[1]
        env_vars = {'K8s_NAMESPACE': 'default'}
        if source.node_template.type == 'tosca.nodes.QC.Container.Application.Docker':
            env_vars['DOCKER_IMAGE'] = source.node_template.artifacts['image']['file']
            env_vars['DOCKER_SERVICE_NAME'] = source.name
            env_vars['CONTAINER_PORT'] = '80'
            if 'ports' in source.node_template.properties:
                env_vars['CONTAINER_PORT'] = source.node_template.properties['ports'][0].split(':')[1]
            if 'environment' in source.node_template.properties:
                env_vars['DOCKER_ENV_VARIABLES'] = source.node_template.properties['environment']
        return env_vars

    def set_attributes(self, task_outputs,source):
        # target = nodes_pair[0]
        # source = nodes_pair[1]
        if source.node_template.type == 'tosca.nodes.QC.docker.Orchestrator.Kubernetes':
            source = self.set_kubernetes_attributes(source=source,task_outputs=task_outputs)
        if source.node_template.type == 'tosca.nodes.QC.Container.Application.Docker':
            source = self.set_docker_attributes(source=source, task_outputs=task_outputs)
        if source.node_template.type == 'tosca.nodes.QC.Application.TIC':
            source = self.set_tic_attributes(source=source, task_outputs=task_outputs)
        # lst = list(nodes_pair)
        # lst[1] = source
        # nodes_pair = tuple(lst)
        return source



    def parse_ansible_var(self,var_name, output_array):
        index = 0
        start_index = -1
        end_index = -1
        for out in output_array:
            index += 1
            if 'TASK' in out.output or 'PLAY RECAP' in out.output:
                if start_index > -1:
                    end_index = index - 1
                    break
            if start_index <=-1 and '"' + var_name + '":' in out.output:
                start_index = index - 1
        if start_index <= -1:
            return None
        ansible_var = output_array[start_index:end_index]
        json_ansible_var = '{'
        for item in ansible_var:
            json_ansible_var = json_ansible_var + item.output
        logger.info('found '+var_name +': '+ str(json_ansible_var))
        return json.loads(json_ansible_var)

    def get_dashboard_token(self, k8s_dashboard_token):
        k8s_dashboard_token = k8s_dashboard_token['k8s_dashboard_token']
        # if 'resources' in k8s_secrets:
        #     return self.get_secret_from_k8s_info(k8s_secrets)
        if 'stdout' in k8s_dashboard_token:
            return self.get_secret_from_stdout(k8s_dashboard_token)


    def get_service_port(self, k8s_services, service_name,port_type):
        resources = k8s_services['k8s_services']['resources']
        for resource in resources:
            name = resource['metadata']['name']
            if name == service_name:
                ports = resource['spec']['ports']
                for port in ports:
                    if port_type in port:
                        return port[port_type]
        return None

    def get_secret_from_k8s_info(self, k8s_secrets):
        resources = k8s_secrets['resources']
        for resource in resources:
            metadata = resource['metadata']
            if 'admin-user-token' in  metadata['name']:
                dashboard_token = resource['data']['token']
                logger.info('found dashboard_token: ' + str(dashboard_token))
                return resource['data']['token']
        return None

    def get_secret_from_stdout(self, k8s_dashboard_token):
        return k8s_dashboard_token['stdout'].replace('token:     ', '')

    def set_kubernetes_attributes(self, source=None,task_outputs=None):
        attributes = source.node_template.attributes
        if 'tokens' not in attributes:
            tokens = []
            attributes['tokens'] = tokens
        else:
            tokens = attributes['tokens']

        if 'dashboard_url' not in source.node_template.attributes:
            dashboard_url = ''
            attributes['dashboard_url'] = dashboard_url
        else:
            dashboard_url = attributes['dashboard_url']

        k8s_dashboard_token = None
        k8s_services = None
        for task_output_key in task_outputs:
            task_output = task_outputs[task_output_key]
            if not k8s_dashboard_token:
                k8s_dashboard_token = self.parse_ansible_var('k8s_dashboard_token', task_output)
            if not k8s_services:
                k8s_services = self.parse_ansible_var('k8s_services', task_output)
            if k8s_services and k8s_dashboard_token:
                credential = {'token_type': 'k8s_dashboard_token'}
                credential['token'] = self.get_dashboard_token(k8s_dashboard_token)
                tokens.append(credential)

                service_port = self.get_service_port(k8s_services, 'kubernetes-dashboard', 'nodePort')
                dashboard_url = 'https://' + self.master_ip + ':' + str(service_port)
                attributes['dashboard_url'] = dashboard_url
                logger.info('source.node_template.attributes: ' + str(attributes))
                return source
        raise Exception(
            'Did not find k8s_services and/or k8s_dashboard_token')
        return None

    def set_docker_attributes(self, source, task_outputs):
        attributes = source.node_template.attributes
        if 'service_url' not in source.node_template.attributes:
            service_url = ''
            attributes['service_url'] = service_url
        for task_output_key in task_outputs:
            task_output = task_outputs[task_output_key]
            k8s_services = self.parse_ansible_var('k8s_services', task_output)
            service_port = self.get_service_port(k8s_services, source.name, 'nodePort')
            if service_port:
                service_url = 'http://' + self.master_ip + ':' + str(service_port)
                attributes['service_url'] = service_url
                logger.info('source.node_template.attributes: ' + str(attributes))
            return source

    def set_tic_attributes(self, source, task_outputs):
        attributes = source.node_template.attributes
        if 'service_urls' not in source.node_template.attributes:
            service_urls = []
            attributes['service_urls'] = service_urls
            for port in ['8090','9000','9090']:
                service_urls.append('http://' + self.master_ip + ':' + str(port))
            attributes['service_urls'] = service_urls
        return source
