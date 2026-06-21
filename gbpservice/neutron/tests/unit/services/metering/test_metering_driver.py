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
from gbpservice.neutron.services.metering.aim import metering_driver
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_aim_mapping_driver as test_aim_base)
from oslo_utils import uuidutils


class TestAciMeteringDriver(test_aim_base.AIMBaseTestCase):

    def setUp(self):
        super(TestAciMeteringDriver, self).setUp()
        self.drv = metering_driver.AciMeteringDriver(
            mock.MagicMock(), mock.MagicMock())
        self.drv._aim = self.aim_mgr
        self.drv._aim_mech_driver = mock.MagicMock()
        self.drv._aim_mech_driver.name_mapper.project.return_value = (
            'prj_test')
        self.drv._aim_mech_driver.get_aim_app_profile_name.return_value = (
            'OpenStack')

    def _make_router_with_label(self, label_id=None, rules=None):
        if not label_id:
            label_id = uuidutils.generate_uuid()
        if rules is None:
            rules = [{'remote_ip_prefix': '10.0.0.0/8',
                       'direction': 'ingress'}]
        return {
            'tenant_id': 'test_project',
            '_metering_labels': [{
                'id': label_id,
                'rules': rules,
            }],
        }

    def test_useg_epg_name(self):
        name = self.drv._useg_epg_name('abcdef12-3456')
        self.assertEqual('meter-abcdef12', name)

    def test_add_metering_label_creates_useg_epg(self):
        label_id = uuidutils.generate_uuid()
        routers = [self._make_router_with_label(label_id)]

        self.drv.add_metering_label(mock.MagicMock(), routers)

        aim_ctx = self.drv._get_aim_context()
        epg_name = 'meter-%s-in' % label_id[:8]

        epg = self.aim_mgr.get(
            aim_ctx,
            aim_res.EndpointGroup(
                tenant_name='prj_test',
                app_profile_name='OpenStack',
                name=epg_name))
        self.assertIsNotNone(epg)

        criteria = self.aim_mgr.get(
            aim_ctx,
            aim_res.EndpointGroupCriteria(
                tenant_name='prj_test',
                app_profile_name='OpenStack',
                epg_name=epg_name))
        self.assertIsNotNone(criteria)

        ip_attr = self.aim_mgr.get(
            aim_ctx,
            aim_res.EndpointGroupIpAttr(
                tenant_name='prj_test',
                app_profile_name='OpenStack',
                epg_name=epg_name,
                name='cidr-match'))
        self.assertIsNotNone(ip_attr)
        self.assertEqual('10.0.0.0/8', ip_attr.ip)

    def test_remove_metering_label_cleans_up(self):
        label_id = uuidutils.generate_uuid()
        routers = [self._make_router_with_label(label_id)]

        self.drv.add_metering_label(mock.MagicMock(), routers)
        self.drv.remove_metering_label(mock.MagicMock(), routers)

        aim_ctx = self.drv._get_aim_context()
        epg_name = 'meter-%s-in' % label_id[:8]

        epg = self.aim_mgr.get(
            aim_ctx,
            aim_res.EndpointGroup(
                tenant_name='prj_test',
                app_profile_name='OpenStack',
                name=epg_name))
        self.assertIsNone(epg)

    def test_add_egress_rule(self):
        label_id = uuidutils.generate_uuid()
        rules = [{'remote_ip_prefix': '172.16.0.0/12',
                   'direction': 'egress'}]
        routers = [self._make_router_with_label(label_id, rules)]

        self.drv.add_metering_label(mock.MagicMock(), routers)

        aim_ctx = self.drv._get_aim_context()
        epg_name = 'meter-%s-out' % label_id[:8]

        epg = self.aim_mgr.get(
            aim_ctx,
            aim_res.EndpointGroup(
                tenant_name='prj_test',
                app_profile_name='OpenStack',
                name=epg_name))
        self.assertIsNotNone(epg)

    def test_get_traffic_counters_returns_dict(self):
        label_id = uuidutils.generate_uuid()
        routers = [self._make_router_with_label(label_id)]
        self.drv.add_metering_label(mock.MagicMock(), routers)

        self.drv._query_epg_stats = mock.MagicMock(
            return_value={'pkts': 100, 'bytes': 50000})

        counters = self.drv.get_traffic_counters(
            mock.MagicMock(), routers)
        self.assertIn(label_id, counters)
        self.assertIn('pkts', counters[label_id])
        self.assertIn('bytes', counters[label_id])
        self.assertIn('time', counters[label_id])
