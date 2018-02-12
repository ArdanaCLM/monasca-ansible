#!/usr/bin/python
#
# (c) Copyright 2015-2016 Hewlett Packard Enterprise Development LP
# (c) Copyright 2017-2018 SUSE LLC
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
module: monasca_notification_method
short_description: crud operations for Monasca notifications methods
description:
    - Performs crud operations (create/update/delete) on monasca notification methods
    - Monasca project homepage - https://wiki.openstack.org/wiki/Monasca
    - When relevant the notification_id is in the output and can be used with the register action
author: Tim Kuhlman <tim@backgroundprocess.com>
requirements: [ python-monascaclient ]
options:
    address:
        required: true
        description:
            - The notification method address corresponding to the type.
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
            - Keystone url to authenticate against, required unless keystone_token isdefined.
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
    monasca_api_url:
        required: false
        description:
            - If unset the service endpoing registered with keystone will be used.
    name:
        required: true
        description:
            - The notification method name
    state:
        required: false
        default: "present"
        choices: [ present, absent ]
        description:
            - Whether the notification should exist.  When C(absent), removes the user notification.
    type:
        required: true
        description:
            - The notification type. This must be one of the types supported by the Monasca API.
    overwrite:
        required: false
        default: false
        choices: [ true, false ]
        description:
            - If true and notification exists, overwrite the address and type with given values,
              If false and notification exists, do nothing,
              If notification does not exist, create notification with given values

'''

EXAMPLES = '''
- name: Setup root email notification method
  monasca_notification_method:
    name: "Email Root"
    type: 'EMAIL'
    address: 'root@localhost'
    keystone_url: "{{keystone_url}}"
    keystone_user: "{{keystone_user}}"
    keystone_password: "{{keystone_password}}"
  register: out
- name: Create System Alarm Definitions
  monasca_alarm_definition:
    name: "Host Alive Alarm"
    expression: "host_alive_status > 0"
    keystone_token: "{{out.keystone_token}}"
    monasca_api_url: "{{out.monasca_api_url}}"
    alarm_actions:
      - "{{out.notification_method_id}}"
    ok_actions:
      - "{{out.notification_method_id}}"
    undetermined_actions:
      - "{{out.notification_method_id}}"
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


class MonascaNotification(MonascaAnsible):
    def run(self):
        name = self.module.params['name']
        type = self.module.params['type']
        address = self.module.params['address']
        notifications = {notif['name']: notif for notif in self.monasca.notifications.list()}
        if name in notifications.keys():
            notification = notifications[name]
        else:
            notification = None

        if self.module.params['state'] == 'absent':
            if notification is None:
                self._exit_json(changed=False)
            else:
                self.monasca.notifications.delete(notification_id=notification['id'])
                self._exit_json(changed=True)
        else:  # Only other option is present
            if notification is None:
                body = self.monasca.notifications.create(name=name, type=type, address=address)
                self._exit_json(changed=True, notification_method_id=body['id'])
            else:
                changed = False
                if self.module.params['overwrite'] and (
                   notification['type'] != type or
                   notification['address'] != address):
                    self.monasca.notifications.update(notification_id=notification['id'],
                                                      name=name, type=type, address=address)
                    changed = True
                self._exit_json(changed=changed, notification_method_id=notification['id'])


def main():
    module = AnsibleModule(
        argument_spec=dict(
            address=dict(required=True, type='str'),
            api_version=dict(required=False, default='2_0', type='str'),
            keystone_password=dict(required=False, type='str'),
            keystone_token=dict(required=False, type='str'),
            keystone_url=dict(required=False, type='str'),
            keystone_user=dict(required=False, type='str'),
            keystone_project=dict(required=False, type='str'),
            keystone_user_domain=dict(required=False, type='str'),
            keystone_project_domain=dict(required=False, type='str'),
            keystone_verify=dict(required=False, type='str'),
            monasca_api_url=dict(required=False, type='str'),
            name=dict(required=True, type='str'),
            state=dict(default='present', choices=['present', 'absent'], type='str'),
            overwrite=dict(required=False, default=False, type='bool'),
            type=dict(required=True, type='str')
        ),
        supports_check_mode=True,
        no_log=True
    )

    if not monascaclient_found:
        module.fail_json(msg="python-monascaclient >= 1.0.9 is required")

    notification = MonascaNotification(module)
    try:
        notification.run()
    except Exception, e:
        notification.module.fail_json(msg='Monascaclient Exception: %s' % e)


if __name__ == "__main__":
    main()
