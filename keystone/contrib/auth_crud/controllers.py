# Copyright 2013 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from keystone.common import controller
from keystone import exception
from keystone import config
from oslo_log import log
from keystone.contrib.auth_crud.backends.sql import create_auth as create_auth_driver

CONF = config.CONF
LOG = log.getLogger(__name__)


class AuthController(controller.V2Controller):
    @controller.v2_deprecated
    def create_auth(self, context, auth=None):
        """
            Accept auth as a dict that looks like::

            {
                "user":{
                    "name":"test_user",
                    "password":"mypass"
                    },
                "tenant":{
                    "name" : "test_tenant",
                    "description": "description",
                    }
                "role": "SwiftAccountHost"
            }
        """

        if auth is None:
            raise exception.ValidationError(attribute='auth',
                                            target='request body')
        return {'credential': self._auth_local(context, auth)}

    @controller.v2_deprecated
    def update_auth(self, context, auth=None):
        """
            Accept auth as a dict that looks like::

            {
                "user":{
                    "name":"test_user",
                    "password":"mypass"
                    },
                "tenant":{
                    "name" : "test_tenant"
                    }
                "role": "SwiftAccountHost"
            }
        """
        if auth is None:
            raise exception.ValidationError(attribute='auth',
                                            target='request body')
        return {'credential': self._auth_local(context, auth, tenant_update=True)}

    def _auth_local(self, context, auth, tenant_update=False):

        ###user
        if 'user' not in auth:
            raise exception.ValidationError(
                attribute='user', target='auth')

        if "password" not in auth['user']:
            raise exception.ValidationError(
                attribute='password', target='user')

        password = auth['user']['password']
        if password and len(password) > CONF.identity.max_password_length:
            raise exception.ValidationSizeError(
                attribute='user.password', size=CONF.identity.max_password_length)

        if not auth['user'].get("name"):
            raise exception.ValidationError(
                attribute='name',
                target='user')

        username = auth['user']['name']
        if len(username) > CONF.max_param_size:
            raise exception.ValidationSizeError(attribute='user.name',
                                                size=CONF.max_param_size)

        user_extra = auth['user'].get('extra', '{}')

        ### tenant
        if 'tenant' not in auth:
            raise exception.ValidationError(
                attribute='tenant', target='auth')

        if "name" not in auth['tenant']:
            raise exception.ValidationError(
                attribute='name', target='tenant')

        tenant_name = auth['tenant'].get('name')
        if len(tenant_name) > CONF.max_param_size:
            raise exception.ValidationSizeError(attribute='tenantname',
                                                size=CONF.max_param_size)
        description = auth['tenant'].get('description', '')


        ### role
        if 'role' in auth and auth['role']:
            role = auth['role']
        else:
            role = 'SwiftAccountHost'

        ### ec2
        trust_id = self._get_trust_id_for_request(context)

        return create_auth_driver(user_name=username, password=password, user_extra=user_extra, tenant_name=tenant_name,
                           description=description, role=role, trust_id=trust_id, tenant_update=tenant_update)