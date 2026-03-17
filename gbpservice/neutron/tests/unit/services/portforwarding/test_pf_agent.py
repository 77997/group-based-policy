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

from gbpservice.neutron.services.portforwarding.aci import aci_pf_agent
from oslotest import base as test_base


class TestAciPortForwardingAgent(test_base.BaseTestCase):

    def test_namespace_prefix(self):
        self.assertEqual('qpf-', aci_pf_agent.NAMESPACE_PREFIX)

    def test_get_namespace(self):
        agent = aci_pf_agent.AciPortForwardingAgent('host1')
        ns = agent._get_namespace('router-123')
        self.assertEqual('qpf-router-123', ns)

    @mock.patch('neutron.agent.linux.ip_lib.IPWrapper')
    def test_ensure_namespace_creates_if_not_exists(self, mock_ipwrap):
        agent = aci_pf_agent.AciPortForwardingAgent('host1')
        mock_ip = mock.MagicMock()
        mock_ipwrap.return_value = mock_ip
        mock_ip.netns.exists.return_value = False

        agent._ensure_namespace('router-123')
        mock_ip.netns.add.assert_called_once_with('qpf-router-123')

    @mock.patch('neutron.agent.linux.ip_lib.IPWrapper')
    def test_ensure_namespace_no_op_if_exists(self, mock_ipwrap):
        agent = aci_pf_agent.AciPortForwardingAgent('host1')
        mock_ip = mock.MagicMock()
        mock_ipwrap.return_value = mock_ip
        mock_ip.netns.exists.return_value = True

        agent._ensure_namespace('router-123')
        mock_ip.netns.add.assert_not_called()

    @mock.patch('neutron.agent.linux.ip_lib.IPWrapper')
    def test_remove_namespace(self, mock_ipwrap):
        agent = aci_pf_agent.AciPortForwardingAgent('host1')
        mock_ip = mock.MagicMock()
        mock_ipwrap.return_value = mock_ip
        mock_ip.netns.exists.return_value = True

        agent._remove_namespace('router-123')
        mock_ip.netns.delete.assert_called_once_with('qpf-router-123')

    def test_managed_namespaces_tracking(self):
        agent = aci_pf_agent.AciPortForwardingAgent('host1')
        self.assertEqual({}, agent._managed_namespaces)
