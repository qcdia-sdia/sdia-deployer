from service import tosca_helper, ansible_service
from service.ansible_service import AnsibleService


class DeployService:

    def __init__(self, polemarch_base_url=None,polemarch_username=None,polemarch_password=None,
                 semaphore_base_url=None,semaphore_username=None,semaphore_password=None):
        # self.polemarch_base_url = polemarch_base_url
        # self.polemarch_username=polemarch_username
        # self.polemarch_password = polemarch_password
        self.semaphore_base_url = semaphore_base_url
        self.semaphore_username = semaphore_username
        self.semaphore_password = semaphore_password

    def deploy(self,nodes_pair):
        target = nodes_pair[0]
        source = nodes_pair[1]

        interface_types = tosca_helper.get_interface_types(source)
        if interface_types:
            if 'Standard' in interface_types:
                ansible_service = AnsibleService(self.semaphore_base_url,self.semaphore_username,self.semaphore_password)
                ansible_service.execute(nodes_pair)
            else:
                print(interface_types)

        return None
