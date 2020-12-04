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

    def create_workflow(self, workflow, workflow_name):
        body = {
                'name': workflow_name,
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
        r = self._session.post(self.api_url + '/workflow_job_templates/', data=json.dumps(body),headers=self.headers)
        r_json = r.json()
        if r.status_code == 400:
            if '__all__' in r_json and 'already exists' in r_json['__all__'][0]:
                r = self._session.get(self.api_url + '/workflow_job_templates/?name='+workflow_name+'&organization='+str(body['organization']), headers=self.headers)
                r_json = r.json()[0]
        print(r_json)





