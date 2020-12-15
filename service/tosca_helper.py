import copy
import hashlib
import os
import sys
import urllib.request

import yaml
from sure_tosca_client import Configuration, ApiClient, NodeTemplate
from sure_tosca_client.api import default_api
import networkx as nx
from toscaparser.tosca_template import ToscaTemplate


class ToscaHelper:

    def __init__(self, sure_tosca_base_url, tosca_template_path):
        self.function_names = {'get_property':'properties','get_attribute':'attributes','get_input':'inputs'}
        self.sure_tosca_base_url = sure_tosca_base_url
        self.tosca_template_path = tosca_template_path

        self.tosca_template_dict = self.get_tosca_from_file(tosca_template_path)
        self.tosca_client = self.init_sure_tosca_client(sure_tosca_base_url)
        self.doc_id = self.upload_tosca_template(tosca_template_path)


    def upload_tosca_template(self, file_path):
        file_id = self.tosca_client.upload_tosca_template(file_path)
        return file_id


    def init_sure_tosca_client(self,sure_tosca_base_path):
        configuration = Configuration()
        configuration.host = sure_tosca_base_path
        api_client = ApiClient(configuration=configuration)
        api = default_api.DefaultApi(api_client=api_client)
        return api

    def get_interface_types(target):
        interface_types = []
        for interface in target.node_template.interfaces:
            interface_types.append(interface)

        return interface_types

    def get_application_nodes(self):
        return self.tosca_client.get_node_templates(self.doc_id, type_name='tosca.nodes.QC.Application')

    def get_vm_topologies(self):
        return self.tosca_client.get_node_templates(self.doc_id, type_name='tosca.nodes.QC.VM.topology')

    def get_deployment_node_pipeline(self):
        vm_topologies = self.get_vm_topologies()
        nodes_to_deploy = []
        for vm_topology_map in vm_topologies:
            vm_topology = vm_topology_map.node_template
            if hasattr(vm_topology,'attributes') and \
                    'desired_state' in vm_topology.attributes and \
                    vm_topology.attributes['desired_state'] == 'RUNNING':
                if 'current_state' in vm_topology.attributes  and \
                        vm_topology.attributes['current_state'] == 'RUNNING':
                    continue
                else:
                    nodes_to_deploy.append(vm_topology_map)
        nodes_to_deploy.extend(self.get_application_nodes())
        G = nx.DiGraph()
        sorted_nodes = []
        for node in nodes_to_deploy:
            related_nodes = self.tosca_client.get_related_nodes(self.doc_id,node.name)
            for related_node in related_nodes:
                G.add_edge(node.name, related_node.name)
            #     # We need to deploy the docker orchestrator on the VMs not the topology.
            #     # But the topology is directly connected to the orchestrator not the VMs.
            #     # So we explicitly get the VMs
            #     # I don't like this solution but I can't think of something better.
            #     if related_node.node_template.type == 'tosca.nodes.QC.VM.topology':
            #         vms = self.get_vms()
            #         related_node = vms
            #     pair = (related_node, node)
            #     nodes_pairs.append(pair)
        sorted_graph = sorted(G.in_degree, key=lambda x: x[1], reverse=True)
        for node_tuple in sorted_graph:
            node_name = node_tuple[0]
            for node in nodes_to_deploy:
                if node.name == node_name:
                    sorted_nodes.append(node)
        return sorted_nodes

    @classmethod
    def service_is_up(cls, url):
        code = None
        try:
            code = urllib.request.urlopen(url).getcode()
        except Exception as e:
            if hasattr(e, 'code') and e.code == 404:
                return True
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return False
            # if not e.reason and not e.reason.errno and e.code:
            #     return False
            # else:
            #     return True

        return True

    def get_vms(self):
        return self.tosca_client.get_node_templates(self.doc_id, type_name='tosca.nodes.QC.VM.Compute')

    def set_node(self, updated_node, tosca_template_dict):
        node_templates = tosca_template_dict['topology_template']['node_templates']
        for node_name in node_templates:
            if node_name == updated_node.name:
                node_templates[node_name] = updated_node.node_template.to_dict()
                return tosca_template_dict

    def get_workflows(self):
        with open(self.tosca_template_path) as file:
            # The FullLoader parameter handles the conversion from YAML
            # scalar values to Python the dictionary format
            tosca_template = yaml.load(file, Loader=yaml.FullLoader)

        if 'workflows' in tosca_template['topology_template']:
            return tosca_template['topology_template']['workflows']

    def get_function_value(self,function):
        target_node = self.tosca_template_dict['topology_template']['node_templates'][function['target']]
        name = self.function_names[function['name']]
        value_name = function['value_name']
        if name in target_node:
            return target_node[name][value_name]

    @classmethod
    def get_tosca_from_file(cls, path):
        with open(path) as json_file:
            return yaml.safe_load(json_file)

    def resolve_function_values(self, tosca_node):
        functions = []
        functions = self.find_functions(tosca_node,functions=functions)
        for function in functions:
            value = self.get_function_value(function)
            if value:
                tosca_node = self.replace_value(tosca_node,function,value)
        return tosca_node

    def replace_value(self,obj, function, replace_value):
        for k, v in obj.items():
            if isinstance(v, dict):
                obj[k] = self.replace_value(v, function, replace_value)
        if function['name'] in obj and \
                obj[function['name']][0] == function['target'] and \
                obj[function['name']][1] == function['value_name']:
            obj = replace_value
        return obj

    def find_functions(self,d,functions=None):
        for k, v in d.items():
            for function_name in self.function_names:
                if function_name == k:
                    function = {'name': function_name, 'target': d[function_name][0], 'value_name': d[function_name][1]}
                    functions.append(function)
            if isinstance(v, list):
                for elem in v:
                    if isinstance(elem, dict):
                        self.find_functions(elem, functions=functions)
            if isinstance(v, dict):
                self.find_functions(v,functions=functions)
        return functions




def get_interface_types(node):
    interface_type_names = []
    if node.node_template.interfaces:
        for interface in node.node_template.interfaces:
            interface_type_names.append(interface)
        return interface_type_names