import copy
import os
import sys
import urllib.request

from sure_tosca_client import Configuration, ApiClient, NodeTemplate
from sure_tosca_client.api import default_api
import networkx as nx
import matplotlib.pyplot as plt


class ToscaHelper:

    def __init__(self, sure_tosca_base_url, tosca_template_path):
        self.sure_tosca_base_url = sure_tosca_base_url
        self.tosca_template_path = tosca_template_path
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

    def get_deployment_node_pipeline(self):
        nodes_to_deploy = self.get_application_nodes()
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


def get_interface_types(node):
    interface_type_names = []
    if node.node_template.interfaces:
        for interface in node.node_template.interfaces:
            interface_type_names.append(interface)
        return interface_type_names


