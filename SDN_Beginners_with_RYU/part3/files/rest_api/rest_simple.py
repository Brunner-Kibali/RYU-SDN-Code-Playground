'''
demonstrate the rest api in ryu framework

How to run:
No mininet topology required

1) ryu-manager <filename>

2. curl localhost:8080/apps


'''

from ryu.app.wsgi import WSGIApplication
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import Response
from ryu.base import app_manager
import json


class DeviceController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(DeviceController, self).__init__(req, link, data, **config)
        self.data = data
	#self.data["apps"]
    def get_apps(self, req, **kwargs):
        apps = self.data["apps"]
        body = json.dumps(apps)
        return Response(content_type='application/json', body=body)


class myapp(app_manager.RyuApp):

    _CONTEXTS = {
                'wsgi': WSGIApplication,
                }

    def __init__(self, *args, **kwargs):
        super(myapp, self).__init__(*args, **kwargs)
        self.data = {}
        self.data['apps'] = ["L2Switch", "L3Switch", "L4Switch"]

        # REST handler
        wsgi = kwargs['wsgi']
        mapper = wsgi.mapper
        wsgi.registory['DeviceController'] = self.data

        # API linkages
        uri = "/apps"
        mapper.connect('stats', uri,
                       controller=DeviceController, action='get_apps',
                       conditions=dict(method=['GET']))


  #GET localhost:8080/apps
  #["L2Switch", "L3Switch", "L4Switch"]

