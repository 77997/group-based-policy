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

from gbpservice.neutron.services.vpn.aci import aci_vpn_driver
from gbpservice.neutron.services.vpn.aci import aci_ipsec
from oslotest import base as test_base
from oslo_utils import uuidutils


class TestAciVpnServiceDriver(test_base.BaseTestCase):

    def setUp(self):
        super(TestAciVpnServiceDriver, self).setUp()
        self.plugin = mock.MagicMock()
        with mock.patch(
                'neutron_vpnaas.services.vpn.service_drivers.base_ipsec.'
                'BaseIPsecVPNDriver.__init__'):
            self.driver = aci_vpn_driver.AciVpnServiceDriver(self.plugin)
            self.driver.agent_rpc = mock.MagicMock()

    def test_service_type(self):
        self.assertEqual('VPN', self.driver.service_type)

    @mock.patch('neutron_lib.plugins.directory.get_plugin')
    def test_create_ipsec_site_connection_notifies_agent(self, mock_plugin):
        vpn_plugin = mock.MagicMock()
        mock_plugin.return_value = vpn_plugin
        vpn_plugin.get_vpnservice.return_value = {
            'router_id': 'router-123'
        }

        context = mock.MagicMock()
        conn = {
            'id': uuidutils.generate_uuid(),
            'vpnservice_id': 'vpn-svc-1',
        }
        self.driver.create_ipsec_site_connection(context, conn)
        self.driver.agent_rpc.vpnservice_updated.assert_called_once_with(
            context, router_id='router-123')

    @mock.patch('neutron_lib.plugins.directory.get_plugin')
    def test_delete_ipsec_site_connection_notifies_agent(self, mock_plugin):
        vpn_plugin = mock.MagicMock()
        mock_plugin.return_value = vpn_plugin
        vpn_plugin.get_vpnservice.return_value = {
            'router_id': 'router-456'
        }

        context = mock.MagicMock()
        conn = {
            'id': uuidutils.generate_uuid(),
            'vpnservice_id': 'vpn-svc-2',
        }
        self.driver.delete_ipsec_site_connection(context, conn)
        self.driver.agent_rpc.vpnservice_updated.assert_called_once_with(
            context, router_id='router-456')


class TestAciIPsecDriver(test_base.BaseTestCase):

    def test_namespace_prefix(self):
        self.assertEqual('qvpn-', aci_ipsec.NAMESPACE_PREFIX)

    @mock.patch('neutron_vpnaas.services.vpn.device_drivers.ipsec.'
                'IPsecDriver.__init__', return_value=None)
    def test_get_namespace(self, _):
        driver = aci_ipsec.AciIPsecDriver(mock.MagicMock(), 'host1')
        ns = driver._get_namespace('router-123')
        self.assertEqual('qvpn-router-123', ns)
