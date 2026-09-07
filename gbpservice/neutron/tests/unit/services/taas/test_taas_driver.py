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

from unittest import mock

from aim.api import resource as aim_res
from gbpservice.neutron.services.taas.aim import taas_driver
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_aim_mapping_driver as test_aim_base)
from oslo_utils import uuidutils


class TestAimTaasDriver(test_aim_base.AIMBaseTestCase):

    def setUp(self):
        super(TestAimTaasDriver, self).setUp()
        self.drv = taas_driver.AimTaasServiceDriver(mock.MagicMock())
        self.drv._aim = self.aim_mgr
        self.drv._aim_mech_driver = mock.MagicMock()

    def test_source_group_name(self):
        name = self.drv._source_group_name('abcdef12-3456')
        self.assertEqual('taas-src-abcdef12', name)

    def test_dest_group_name(self):
        name = self.drv._dest_group_name('abcdef12-3456')
        self.assertEqual('taas-dst-abcdef12', name)

    def test_direction_map(self):
        self.assertEqual('in', self.drv._direction_map('IN'))
        self.assertEqual('out', self.drv._direction_map('OUT'))
        self.assertEqual('both', self.drv._direction_map('BOTH'))
        self.assertEqual('both', self.drv._direction_map('UNKNOWN'))

    @mock.patch.object(taas_driver.AimTaasServiceDriver, '_get_port_ip',
                       return_value='192.168.1.10')
    def test_create_tap_service_creates_span_dest(self, mock_ip):
        tap_service = {
            'id': uuidutils.generate_uuid(),
            'port_id': uuidutils.generate_uuid(),
        }
        context = mock.MagicMock()
        context.tap_service = tap_service
        aim_ctx = mock.MagicMock()
        self.drv._get_aim_context = mock.MagicMock(return_value=aim_ctx)
        aim_ctx = self.drv._get_aim_context(context._plugin_context)

        real_aim_ctx = self._aim_context
        self.drv._get_aim_context = mock.MagicMock(
            return_value=real_aim_ctx)

        self.drv.create_tap_service_postcommit(context)

        dest_group_name = self.drv._dest_group_name(tap_service['id'])
        dest_group = self.aim_mgr.get(
            real_aim_ctx,
            aim_res.SpanVdestGroup(name=dest_group_name))
        self.assertIsNotNone(dest_group)

    @mock.patch.object(taas_driver.AimTaasServiceDriver, '_get_port_ip',
                       return_value='192.168.1.10')
    def test_delete_tap_service_removes_span_dest(self, mock_ip):
        tap_service = {
            'id': uuidutils.generate_uuid(),
            'port_id': uuidutils.generate_uuid(),
        }
        context = mock.MagicMock()
        context.tap_service = tap_service
        real_aim_ctx = self._aim_context
        self.drv._get_aim_context = mock.MagicMock(
            return_value=real_aim_ctx)

        self.drv.create_tap_service_postcommit(context)
        self.drv.delete_tap_service_postcommit(context)

        dest_group_name = self.drv._dest_group_name(tap_service['id'])
        dest_group = self.aim_mgr.get(
            real_aim_ctx,
            aim_res.SpanVdestGroup(name=dest_group_name))
        self.assertIsNone(dest_group)
