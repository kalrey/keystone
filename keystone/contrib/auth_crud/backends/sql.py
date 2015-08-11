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

from keystone.common import sql
from keystone.resource.backends.sql import Project
from keystone.assignment.backends.sql import RoleAssignment, AssignmentType
from keystone.assignment.role_backends.sql import Role

from keystone.identity.backends.sql import User
from keystone.credential.backends.sql import CredentialModel
from oslo_serialization import jsonutils
from keystone.common import utils
from keystone import exception

import uuid
from keystone import config

CONF = config.CONF

def create_auth(user_name, password, user_extra, tenant_name, description, role, trust_id, tenant_update=False):
    with sql.transaction() as session:
        user_id = uuid.uuid4().hex

        # get project id
        # if project_id is None, raise exception

        if tenant_update:
            query = session.query(Project)
            query = query.filter_by(name=tenant_name)
            query = query.filter_by(domain_id=CONF.identity.default_domain_id)
            try:
                project_ref = query.one()
            except sql.NotFound:
                raise exception.ProjectNotFound(project_id=tenant_name)

            project_id = project_ref.id
        else:
            project_id = uuid.uuid4().hex

        blob = {'access': uuid.uuid4().hex,
                'secret': uuid.uuid4().hex,
                'trust_id': trust_id}

        credential_id = utils.hash_access_key(blob['access'])

        project = {'id': project_id, 'name': tenant_name, 'domain_id': CONF.identity.default_domain_id,
                   'description': description, 'enabled': True}

        project_ref = Project.from_dict(project)

        user = {'id': user_id,
                'name': user_name,
                'domain_id': CONF.identity.default_domain_id,
                'password': utils.hash_password(password),
                'enabled': True,
                'default_project_id': project_id,
                'extra': user_extra}

        user_ref = User.from_dict(user)

        credential = {'user_id': user_id, 'project_id': project_id,
                      'blob': jsonutils.dumps(blob),
                      'id': credential_id,
                      'type': 'ec2'}

        credential_ref = CredentialModel.from_dict(credential)

        query = session.query(Role)
        query = query.filter_by(name=role)
        ref = query.one()
        role_id = ref.id
        if not tenant_update:
            session.add(project_ref)
        session.add(user_ref)
        session.add(RoleAssignment(type=AssignmentType.USER_PROJECT,
                                   actor_id=user_id,
                                   target_id=project_id,
                                   role_id=role_id,
                                   inherited=False))
        session.add(credential_ref)

        blob.pop('trust_id')
        blob['user_id'] = user_id
        blob['tenant_id'] = project_id
        return blob
