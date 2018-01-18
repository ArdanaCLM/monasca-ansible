#!/usr/bin/python
#
# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
# (c) Copyright 2017 SUSE LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
DOCUMENTATION = '''
---
module: monasca_alarm_cleanup
short_description: Cleanup Alarms based on included metrics
description:
    - Deletes Alarms that match the given criteria
    - Monasca project homepage - https://wiki.openstack.org/wiki/Monasca
requirements: [ python-monascaclient ]
options:
    alarm_definition_name:
        required: false
        description:
            -  If given, only alarms that belong to the Alarm Definition with that name will be deleted
    api_version:
        required: false
        default: '2_0'
        description:
            - The monasca api version.
    keystone_password:
        required: false
        description:
            - Keystone password to use for authentication, required unless a keystone_token is specified.
    keystone_url:
        required: false
        description:
            - Keystone url to authenticate against, required unless keystone_token is defined.
              Example http://192.168.10.5:5000/v3
    keystone_token:
        required: false
        description:
            - Keystone token to use with the monasca api. If this is specified the monasca_api_url is required but
              the keystone_user and keystone_password aren't.
    keystone_user:
        required: false
        description:
            - Keystone user to log in as, required unless a keystone_token is specified.
    keystone_project:
        required: false
        description:
            - Keystone project name to obtain a token for, defaults to the user's default project
    keystone_project_domain:
        required: false
        description:
            - Keystone project domain to obtain a token for, defaults to the default project domain
    keystone_user_domain:
        required: false
        description:
            - Keystone project domain to obtain a token for, defaults to the default user domain
    keystone_verify:
        required: false
        description:
            - See 'verify' parameter in
              https://github.com/openstack/keystoneauth/blob/master/keystoneauth1/session.py
              The verification arguments to pass to requests. These are of
              the same form as requests expects, so True or False to
              verify (or not) against system certificates or a path to a
              bundle or CA certs to check against or None for requests to
              attempt to locate and use certificates. (optional, defaults to True)
    metric_dimensions:
        required: true
        description:
            - Map of name/value pairs. All alarms which have all metrics matching these dimension names and values will be deleted
    monasca_api_url:
        required: false
        description:
            - If unset the service endpoint registered with keystone will be used.
'''

EXAMPLES = '''
- name: Host Alive Alarm
  monasca_alarm_cleanup:
    metric_dimensions:
       process_name: storm.nimbus
    keystone_url: "{{monasca_keystone_url}}"
    keystone_user: "{{monasca_keystone_user}}"
    keystone_password: "{{monasca_keystone_password}}"
  tags:
    - alarms
  register: out
'''

from ansible.module_utils.basic import *
import os

try:
    from monascaclient import client
except ImportError:
    paths = ["/opt/stack/service/monascaclient/venv", "/opt/monasca"]
    for path in paths:
        activate_this = os.path.realpath(path + '/bin/activate_this.py')
        if not os.path.exists(activate_this):
            continue
        try:
            execfile(activate_this, dict(__file__=activate_this))
            from monascaclient import client
        except ImportError:
            monascaclient_found = False
        else:
            monascaclient_found = True
            break
else:
    monascaclient_found = True


# With Ansible modules including other files presents difficulties otherwise this would be in its own module
class MonascaAnsible(object):
    """ A base class used to build Monasca Client based Ansible Modules
        As input an ansible.module_utils.basic.AnsibleModule object is expected. It should have at least
        these params defined:
        - api_version
        - keystone_token and monasca_api_url or keystone_url, keystone_user and keystone_password and optionally
          monasca_api_url
    """
    def __init__(self, module):
        self.module = module
        self.api_url = self.module.params['monasca_api_url']
        auth_args = self._get_keystone_auth_args()
        auth_args["endpoint"] = self.api_url
        self.monasca = client.Client(self.module.params['api_version'],
                                     **auth_args)
        self.exit_data = {'monasca_api_url': self.api_url}

    def _exit_json(self, **kwargs):
        """ Exit with supplied kwargs combined with the self.exit_data
        """
        kwargs.update(self.exit_data)
        self.module.exit_json(**kwargs)

    def _get_keystone_auth_args(self):
        """get arguments that should be passed on to monascaclient. """
        if self.module.params['monasca_api_url'] is None:
            self.module.fail_json(msg='Error: monasca_api_url is required')

        keystone_verify = self.module.params.get('keystone_verify', None)
        if keystone_verify and keystone_verify == "True":
            verify_flag = True
        elif keystone_verify and keystone_verify == "False":
            verify_flag = False
        else:
            # path to ca cert
            verify_flag = keystone_verify

        keystone_auth_args = {'auth_url': self.module.params['keystone_url'],
                              'project_name': self.module.params['keystone_project'],
                              'project_domain_name': self.module.params['keystone_project_domain'],
                              'user_domain_name': self.module.params['keystone_user_domain'],
                              'verify': verify_flag}

        if self.module.params['keystone_token'] is not None:
            keystone_auth_args['token'] = self.module.params['keystone_token']
        else:
            keystone_auth_args['username'] = self.module.params['keystone_user']
            keystone_auth_args['password'] = self.module.params['keystone_password']

        return keystone_auth_args


class MonascaAlarmCleanup(MonascaAnsible):
    def run(self):
        alarm_definition_name = self.module.params['alarm_definition_name']
        metric_dimensions = self.module.params['metric_dimensions']

        deleted_alarms = False
        # Find alarms that match the dimensions
        alarms = self.monasca.alarms.list(metric_dimensions=metric_dimensions)

        for alarm in alarms:
            if alarm_definition_name and alarm_definition_name != alarm['alarm_definition']['name']:
                continue

            self.monasca.alarms.delete(alarm_id=alarm['id'])
            deleted_alarms = True
        self._exit_json(changed=deleted_alarms)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            alarm_definition_name=dict(required=False, type='str'),
            api_version=dict(required=False, default='2_0', type='str'),
            keystone_password=dict(required=False, type='str'),
            keystone_token=dict(required=False, type='str'),
            keystone_url=dict(required=False, type='str'),
            keystone_user=dict(required=False, type='str'),
            keystone_project=dict(required=False, type='str'),
            keystone_user_domain=dict(required=False, type='str'),
            keystone_project_domain=dict(required=False, type='str'),
            keystone_verify=dict(required=False, type='str'),
            metric_dimensions=dict(default=['hostname'], type='dict'),
            monasca_api_url=dict(required=False, type='str')
        ),
        supports_check_mode=True,
        no_log=True
    )

    if not monascaclient_found:
        module.fail_json(msg="python-monascaclient >= 1.0.9 is required")

    cleanup = MonascaAlarmCleanup(module)
    try:
        cleanup.run()
    except Exception, e:
        cleanup.module.fail_json(msg='Monascaclient Exception: %s' % e)

if __name__ == "__main__":
    main()
