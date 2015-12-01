from collections import defaultdict
from urllib2 import urlparse, unquote

import oauth2
import time

from launch_params import LaunchParamsMixin
from request_validator import RequestValidatorMixin
from utils import InvalidLTIConfigError, generate_identifier

accessors = [
    'consumer_key',
    'consumer_secret',
    'launch_url',
]

class ToolConsumer(LaunchParamsMixin, RequestValidatorMixin, object):
    def __init__(self, consumer_key, consumer_secret, params = {}):
        '''
        Create new ToolConsumer.
        '''
        # Initialize all class accessors to None
        for opt in accessors:
            setattr(self, opt, None)

        # These are hyper important class members that we init first
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret

        # Call superclass initializers
        super(ToolConsumer, self).__init__()

        self.non_spec_params = defaultdict(lambda: None)

        self.launch_url = params.get('launch_url')
        self.process_params(params)

    def set_config(self, config):
        '''
        Set launch data from a ToolConfig.
        '''
        if self.launch_url == None:
            self.launch_url = config.launch_url
            self.custom_params.update(config.custom_params)

    def has_required_params(self):
        '''
        Check if required parameters for a tool launch are set.
        '''
        return self.consumer_key and\
                self.consumer_secret and\
                self.resource_link_id and\
                self.launch_url

    def _params_update(self):
        return {
            'oauth_nonce': str(generate_identifier()),
            'oauth_timestamp': str(int(time.time())),
        }

    def generate_launch_data(self, role, privacy):
        # Validate params
        if not self.has_required_params():
            raise InvalidLTIConfigError('ToolConsumer does not have all required attributes: consumer_key = %s, consumer_secret = %s, resource_link_id = %s, launch_url = %s' %(self.consumer_key, self.consumer_secret, self.resource_link_id, self.launch_url))

        params = self.to_params()
        #print params['roles']

        #RCH 11/17/2015 - For some reason the 'roles' param is now surrounded by brackets
        #IMS Global doesn't like this so it is being removed here
        #role = re.sub(r'\[\]','',params.get('roles'))
        params.update({'roles': role} )
        #params.update({'roles':'Instructor'})

        #SSD 11/19/2015 Adding a parameter to pass on privacy settings

        if privacy == 'name':
            del params['lis_person_contact_email_primary']
        elif privacy == 'email':
            del params['lis_person_name_full']
            del params['lis_person_name_family']
            del params['lis_person_name_given']
        elif privacy == 'none':
            del params['lis_person_contact_email_primary']
            del params['lis_person_name_full']
            del params['lis_person_name_given']
            del params['lis_person_name_family']


        if not params.get('lti_version', None):
            params['lti_version'] = 'LTI-1p0'


        params['lti_message_type'] = 'basic-lti-launch-request'

        # Get new OAuth consumer
        consumer = oauth2.Consumer(key = self.consumer_key,\
                secret = self.consumer_secret)

        params.update(self._params_update())
        params.update({'oauth_consumer_key': consumer.key})

        #RCH 11/17/2015 - commented the following lines below because it's adding the query string parameters twice to the base signature which
        #                   prevents it from matching to ims global's base signature
        # uri = urlparse.urlparse(self.launch_url)
        # if uri.query != '':
        #     for param in uri.query.split('&'):
        #         key, val = param.split('=')
        #         if params.get(key) == None:
        #             params[key] = str(val)

        request = oauth2.Request(method = 'POST',
                url = self.launch_url,
                parameters = params, is_form_encoded=True)

        signatureMethod = oauth2.SignatureMethod_HMAC_SHA1()
        #print signatureMethod.signing_base(request, consumer, None)

        request.sign_request(oauth2.SignatureMethod_HMAC_SHA1(), consumer, None)

        # Request was made by an HTML form in the user's browser.
        # Return the dict of post parameters ready for embedding
        # in an html view.
        return_params = {}
        for key in request:
            if request[key] == None:
                return_params[key] = None
            elif isinstance(request[key], list):
                return_params[key] = request.get_parameter(key)
            else:
                return_params[key] = unquote(request.get_parameter(key))
        return return_params

