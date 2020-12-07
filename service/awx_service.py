import datetime

import ansibleawx
import awxkit
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
        # r = self._session.post(self.api_url + '/projects/', data=json.dumps(body),headers=self.headers)
        # project_id = None
        # if r.status_code == 201:
        #     project = r.json()
        #     project_id = project['id']
        # elif r.status_code == 400 and 'already exists' in r.text:
        #     r = self._session.get(self.api_url + '/projects/?name='+project_name+'&scm_url='+scm_url, headers=self.headers)
        #     project = r.json()['results'][0]
        #     project_id = project['id']
        # return project_id

    def create_inventory(self, inventory_name=None):
        body = {
                'name': inventory_name,
                'description': '',
                'organization': 1,
                'kind': '',
                'host_filter': None,
                'variables': '',
                'insights_credential': None
        }

        return self.post(body,'inventories')


    def create_workflow(self, tosca_workflow, workflow_name):
        description = ''
        if 'description' in tosca_workflow:
            description = tosca_workflow['description']
            steps = tosca_workflow['steps']
        for step_name in steps:
            step = steps[step_name]
            target = step['target']
            activities = step[activities]
            print(step)
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
        id = None
        if r.status_code == 201:
            id = r.json()['id']
        elif r.status_code == 400 and 'already exists' in r.text:
            r = self._session.get(self.api_url + '/'+api_path+'/?name=' + body['name'],headers=self.headers)
            results = r.json()['results']
            if len(results) > 1:
                raise Exception('Got back more than one results for name: '+body['name'])
            id = results[0]['id']
        return id





