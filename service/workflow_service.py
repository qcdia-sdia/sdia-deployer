from workflow_manager.manager import Manager

class WorkflowService:

    def __init__(self,ansible_task):
        self.manager = Manager()
        self.manager.register_initial_task(ansible_task)


    def run(self):
        self.manager.run()