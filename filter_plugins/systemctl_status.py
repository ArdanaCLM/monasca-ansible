#
# (c) Copyright 2020 SUSE LLC
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

from exceptions import KeyError, ValueError

# given a result object from running a systemctl status for a service
# return true if the Active line indicates one of "active (running)",
# "active (exited)" or "inactive (dead)" with the appropriate command
# exit status.
def active_or_dead(result):
    if not result.has_key('cmd'):
        raise KeyError("Not a shell or command action result")
    if (('systemctl' not in result['cmd']) and
        ('status' not in result['cmd'])):
        raise ValueError("Not a systemctl status command")

    active_lines = [l for l in result['stdout'].splitlines()
                    if l.strip().startswith('Active: ')]
    if len(active_lines) > 1:
        raise ValueError("Multiple 'Active:' lines detected")
    elif len(active_lines) < 1:
        raise ValueError("No 'Active:' lines detected")

    active_line = active_lines[0]

    if (((": active (exited)" in active_line) or
        (": active (running)" in active_line)) and
        (int(result['rc']) == 0)):
        return True

    if (": inactive (dead)" in active_line) and int(result['rc']) != 0:
        return True

    return False


def test():
    pass


class FilterModule(object):
    def filters(self):
        return {
            'systemctl_active_or_dead': active_or_dead
        }


if __name__ == "__main__":
    test()
