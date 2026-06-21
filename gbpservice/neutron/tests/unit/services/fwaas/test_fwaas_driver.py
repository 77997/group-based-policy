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
from gbpservice.neutron.services.fwaas.aim import fwaas_driver
from gbpservice.neutron.tests.unit.services.grouppolicy import (
    test_aim_mapping_driver as test_aim_base)
from oslo_utils import uuidutils


class TestAciUsegFwaasDriver(test_aim_base.AIMBaseTestCase):

    def setUp(self):
        super(TestAciUsegFwaasDriver, self).setUp()
        self.drv = fwaas_driver.AciUsegFwaasDriver(mock.MagicMock())
        self.drv._aim_mech_driver = mock.MagicMock()
        self.drv._aim_mech_driver.name_mapper.project.return_value = (
            'prj_test')
        self.drv._aim_mech_driver.get_aim_app_profile_name.return_value = (
            'OpenStack')
        self.drv._aim = self.aim_mgr

    def _make_rule(self, action='allow', protocol='tcp',
                   src_ip='10.0.1.0/24', dst_ip='10.0.2.0/24',
                   src_port=None, dst_port=80):
        return {
            'id': uuidutils.generate_uuid(),
            'action': action,
            'protocol': protocol,
            'source_ip_address': src_ip,
            'destination_ip_address': dst_ip,
            'source_port': src_port,
            'destination_port': dst_port,
            'enabled': True,
        }

    def test_useg_epg_name(self):
        name = self.drv._useg_epg_name('abcdef12-3456', 'src')
        self.assertEqual('fw-src-abcdef12', name)

    def test_contract_name(self):
        name = self.drv._contract_name('abcdef12-3456')
        self.assertEqual('fw-rule-abcdef12', name)

    def test_map_protocol(self):
        self.assertEqual('tcp', self.drv._map_protocol('tcp'))
        self.assertEqual('udp', self.drv._map_protocol('udp'))
        self.assertEqual('tcp', self.drv._map_protocol('6'))
        self.assertIsNone(self.drv._map_protocol(None))

    def test_apply_allow_rule_creates_useg_epgs(self):
        rule = self._make_rule()
        aim_ctx = self.drv._get_aim_context(self._context)

        self.drv._apply_rule(aim_ctx, 'prj_test', 'OpenStack', rule)

        src_epg = self.aim_mgr.get(
            aim_ctx,
            aim_res.EndpointGroup(
                tenant_name='prj_test', app_profile_name='OpenStack',
                name='fw-src-%s' % rule['id'][:8]))
        self.assertIsNotNone(src_epg)

        dst_epg = self.aim_mgr.get(
            aim_ctx,
            aim_res.EndpointGroup(
                tenant_name='prj_test', app_profile_name='OpenStack',
                name='fw-dst-%s' % rule['id'][:8]))
        self.assertIsNotNone(dst_epg)

    def test_apply_deny_rule_skipped(self):
        rule = self._make_rule(action='deny')
        aim_ctx = self.drv._get_aim_context(self._context)

        self.drv._apply_rule(aim_ctx, 'prj_test', 'OpenStack', rule)

        src_epg = self.aim_mgr.get(
            aim_ctx,
            aim_res.EndpointGroup(
                tenant_name='prj_test', app_profile_name='OpenStack',
                name='fw-src-%s' % rule['id'][:8]))
        self.assertIsNone(src_epg)

    def test_apply_reject_treated_as_deny(self):
        rule = self._make_rule(action='reject')
        aim_ctx = self.drv._get_aim_context(self._context)

        self.drv._apply_rule(aim_ctx, 'prj_test', 'OpenStack', rule)

        src_epg = self.aim_mgr.get(
            aim_ctx,
            aim_res.EndpointGroup(
                tenant_name='prj_test', app_profile_name='OpenStack',
                name='fw-src-%s' % rule['id'][:8]))
        self.assertIsNone(src_epg)

    def test_remove_rule_cleans_up(self):
        rule = self._make_rule()
        aim_ctx = self.drv._get_aim_context(self._context)

        self.drv._apply_rule(aim_ctx, 'prj_test', 'OpenStack', rule)
        self.drv._remove_rule(aim_ctx, 'prj_test', 'OpenStack',
                                 rule['id'])

        src_epg = self.aim_mgr.get(
            aim_ctx,
            aim_res.EndpointGroup(
                tenant_name='prj_test', app_profile_name='OpenStack',
                name='fw-src-%s' % rule['id'][:8]))
        self.assertIsNone(src_epg)

        contract = self.aim_mgr.get(
            aim_ctx,
            aim_res.Contract(
                tenant_name='prj_test',
                name='fw-rule-%s' % rule['id'][:8]))
        self.assertIsNone(contract)

    def test_apply_rule_creates_contract(self):
        rule = self._make_rule()
        aim_ctx = self.drv._get_aim_context(self._context)

        self.drv._apply_rule(aim_ctx, 'prj_test', 'OpenStack', rule)

        contract_name = self.drv._contract_name(rule['id'])
        contract = self.aim_mgr.get(
            aim_ctx,
            aim_res.Contract(tenant_name='prj_test', name=contract_name))
        self.assertIsNotNone(contract)

        subject = self.aim_mgr.get(
            aim_ctx,
            aim_res.ContractSubject(
                tenant_name='prj_test',
                contract_name=contract_name,
                name='subject'))
        self.assertIsNotNone(subject)

    def test_apply_rule_creates_ip_criteria(self):
        rule = self._make_rule(src_ip='192.168.1.0/24')
        aim_ctx = self.drv._get_aim_context(self._context)

        self.drv._apply_rule(aim_ctx, 'prj_test', 'OpenStack', rule)

        criteria = self.aim_mgr.get(
            aim_ctx,
            aim_res.EndpointGroupCriteria(
                tenant_name='prj_test', app_profile_name='OpenStack',
                epg_name='fw-src-%s' % rule['id'][:8]))
        self.assertIsNotNone(criteria)

        ip_attr = self.aim_mgr.get(
            aim_ctx,
            aim_res.EndpointGroupIpAttr(
                tenant_name='prj_test', app_profile_name='OpenStack',
                epg_name='fw-src-%s' % rule['id'][:8],
                name='ip-match'))
        self.assertIsNotNone(ip_attr)
        self.assertEqual('192.168.1.0/24', ip_attr.ip)
