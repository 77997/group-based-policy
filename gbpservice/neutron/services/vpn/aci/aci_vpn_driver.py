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

from neutron_lib.plugins import directory
from neutron_vpnaas.services.vpn.service_drivers import base_ipsec
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class AciVpnServiceDriver(base_ipsec.BaseIPsecVPNDriver):
    """Server-side VPN service driver for ACI deployments.

    Adapts the OVN VPN agent pattern: standalone VPN agent runs on
    network nodes, creating qvpn-{router_id} namespaces with ports
    plugged into br-int. The opflex agent sees these as regular
    endpoints and programs OVS flows; ACI fabric routes normally.
    """

    def __init__(self, service_plugin):
        super(AciVpnServiceDriver, self).__init__(service_plugin)

    def create_rpc_conn(self):
        pass

    @property
    def service_type(self):
        return 'VPN'

    def create_vpnservice(self, context, vpnservice):
        pass

    def update_vpnservice(self, context, old_vpnservice, vpnservice):
        pass

    def delete_vpnservice(self, context, vpnservice):
        pass

    def create_ipsec_site_connection(self, context, ipsec_site_connection):
        vpnservice_id = ipsec_site_connection['vpnservice_id']
        vpn_plugin = directory.get_plugin('VPN')
        vpnservice = vpn_plugin.get_vpnservice(context, vpnservice_id)
        self.agent_rpc.vpnservice_updated(
            context, router_id=vpnservice['router_id'])

    def update_ipsec_site_connection(self, context, old_ipsec_site_connection,
                                     ipsec_site_connection):
        vpnservice_id = ipsec_site_connection['vpnservice_id']
        vpn_plugin = directory.get_plugin('VPN')
        vpnservice = vpn_plugin.get_vpnservice(context, vpnservice_id)
        self.agent_rpc.vpnservice_updated(
            context, router_id=vpnservice['router_id'])

    def delete_ipsec_site_connection(self, context, ipsec_site_connection):
        vpnservice_id = ipsec_site_connection['vpnservice_id']
        vpn_plugin = directory.get_plugin('VPN')
        vpnservice = vpn_plugin.get_vpnservice(context, vpnservice_id)
        self.agent_rpc.vpnservice_updated(
            context, router_id=vpnservice['router_id'])
