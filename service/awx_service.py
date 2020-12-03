import ansibleawx


API_URL = "http://my-ansibleawx.com/api/v2"

class AWXService:

    def __init__(self,api_url=None,username=None,password=None):
        self.client = ansibleawx.Api(username=username, password=password, api_url=api_url)
