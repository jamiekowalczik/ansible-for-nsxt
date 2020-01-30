#!/usr/bin/env python
#
# Copyright 2018 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause OR GPL-3.0-only
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
# BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: nsxt_controller_vip
short_description: 'Add a virtual ip to the controller cluster'
description: "This will add a new virtual ip to the controller cluster."
version_added: '2.7'
author: 'Jamie Kowalczik'
options:
    hostname:
        description: 'Deployed NSX manager hostname.'
        required: true
        type: str
    username:
        description: 'The username to authenticate with the NSX manager.'
        required: true
        type: str
    password:
        description: 'The password to authenticate with the NSX manager.'
        required: true
        type: str
    vip:
        description: 'virtual ip'
        required: true
        type: str
    state:
        choices:
            - present
            - absent
        description: "State can be either 'present' or 'absent'.
                      'present' is used to create or update resource.
                      'absent' is used to delete resource."
        required: true   
'''

EXAMPLES = '''
- name: Add Virtual IP
  nsxt_controller_vip:
      hostname: "10.192.167.137"
      username: "admin"
      password: "Admin!23Admin"
      validate_certs: False
      vip: "10.192.167.130"
      state: present
'''

RETURN = '''# '''

import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware_nsxt import vmware_argument_spec, request
from ansible.module_utils._text import to_native

def get_vip_params(args=None):
    args_to_remove = ['state', 'username', 'password', 'port', 'hostname', 'validate_certs']
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if value == None:
            args.pop(key, None)
    return args

def check_vip_exist(module, manager_url, mgr_username, mgr_password, validate_certs):
    id = module.params['vip']
    try:
      (rc, resp) = request(manager_url+ '/cluster/api-virtual-ip', headers=dict(Accept='application/json'),
                      url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
      ipaddress_json = json.dumps(resp)
      ipaddress_json = json.loads(ipaddress_json)
      ipaddress = ipaddress_json['ip_address']
      if ipaddress == id:
         return True
      else:
         return False
         #module.fail_json(msg="DEBUG - IP Address [%s]. Request body [%s]. Error[%s]." % (ipaddress, resp, rc))

    except Exception as err:
      return False

def main():
  argument_spec = vmware_argument_spec()
  argument_spec.update(vip=dict(required=True, type='str'),
                    state=dict(required=True, choices=['present', 'absent']))

  module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
  vip_params = get_vip_params(module.params.copy())
  state = module.params['state']
  mgr_hostname = module.params['hostname']
  mgr_username = module.params['username']
  mgr_password = module.params['password']
  validate_certs = module.params['validate_certs']

  manager_url = 'https://{}/api/v1'.format(mgr_hostname)

  headers = dict(Accept="application/json")
  headers['Content-Type'] = 'application/json'
  #request_data = json.dumps(vip_params)
  request_data = ""

  if state == 'present':
    # add the virtual ip
    if check_vip_exist(module, manager_url, mgr_username, mgr_password, validate_certs):
      module.exit_json(changed=False, message="Virtual IP %s already exist."% module.params['vip'])
    #if module.check_mode:
    #  module.exit_json(changed=True, debug_out=str(request_data), id=module.params['vip'])
    try:
      (rc, resp) = request(manager_url+ '/cluster/api-virtual-ip?action=set_virtual_ip&ip_address=%s' % module.params['vip'], data=request_data, headers=headers, method='POST',
                              url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
    except Exception as err:
      module.fail_json(msg="Failed to add virtual ip. Request body [%s]. Error[%s]." % (request_data, to_native(err)))

    module.exit_json(changed=True, result=resp, message="Virtual IP %s created." % module.params['vip'])

  elif state == 'absent':
    # delete the vip
    id = module.params['vip']
    if check_vip_exist(module, manager_url, mgr_username, mgr_password, validate_certs):
      #if module.check_mode:
      #  module.exit_json(changed=True, debug_out=str(request_data), id=id)
      try:
        (rc, resp) = request(manager_url+ '/cluster/api-virtual-ip?action=clear_virtual_ip', method='POST',
                            url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs, ignore_errors=True)
      except Exception as err:
        module.fail_json(msg="Failed to delete Virtual IP %s. Error[%s]." % (id, to_native(err)))

      module.exit_json(changed=True, object_name=id, message="Virtual IP %s deleted." % id)
    else:
      module.exit_json(changed=False, message="Virtual IP is not currently set to %s."% module.params['vip'])


if __name__ == '__main__':
    main()
