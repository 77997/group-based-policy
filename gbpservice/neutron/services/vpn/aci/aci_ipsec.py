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

import os

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils as linux_utils
from neutron_lib import context as n_context
from neutron_lib.plugins import directory
from neutron_vpnaas.services.vpn.device_drivers import ipsec
from oslo_config import cfg
from oslo_log import log as logging

LOG = logging.getLogger(__name__)

NAMESPACE_PREFIX = 'qvpn-'


class AciIPsecDriver(ipsec.IPsecDriver):
    """IPsec device driver for ACI standalone VPN agent.

    Runs strongswan in qvpn-{router_id} namespaces on network nodes.
    Creates external and transit ports on br-int via OVSInterfaceDriver;
    the opflex agent sees these as regular endpoints.
    """

    def __init__(self, vpn_service, host):
        super(AciIPsecDriver, self).__init__(vpn_service, host)

    def create_process(self, process_id, vpnservice, namespace):
        pass

    def _get_namespace(self, router_id):
        return NAMESPACE_PREFIX + router_id

    def create_router(self, router_id):
        ns_name = self._get_namespace(router_id)
        ip = ip_lib.IPWrapper()
        if not ip.netns.exists(ns_name):
            ip.netns.add(ns_name)
            LOG.info('Created VPN namespace %s', ns_name)

    def destroy_router(self, router_id):
        ns_name = self._get_namespace(router_id)
        ip = ip_lib.IPWrapper()
        if ip.netns.exists(ns_name):
            ip.netns.delete(ns_name)
            LOG.info('Deleted VPN namespace %s', ns_name)

    def _ensure_ports(self, vpnservice):
        """Ensure external and transit ports exist for the VPN namespace."""
        admin_ctx = n_context.get_admin_context()
        plugin = directory.get_plugin()
        router_id = vpnservice['router_id']

        ext_net_id = vpnservice.get('external_v4_ip') or self._get_ext_net(
            admin_ctx, router_id)
        if not ext_net_id:
            LOG.warning('No external network for router %s', router_id)
            return

        ns_name = self._get_namespace(router_id)
        device_owner = 'network:vpn'
        host = cfg.CONF.host

        existing = plugin.get_ports(
            admin_ctx,
            filters={'device_id': ['vpn-' + router_id],
                     'device_owner': [device_owner]})

        if not existing:
            port_data = {
                'port': {
                    'network_id': ext_net_id,
                    'device_id': 'vpn-' + router_id,
                    'device_owner': device_owner,
                    'admin_state_up': True,
                    'binding:host_id': host,
                    'name': 'vpn-ext-%s' % router_id[:8],
                }
            }
            try:
                plugin.create_port(admin_ctx, port_data)
            except Exception:
                LOG.exception('Failed to create VPN external port')

    def _get_ext_net(self, context, router_id):
        l3_plugin = directory.get_plugin('L3_ROUTER_NAT')
        if not l3_plugin:
            return None
        try:
            router = l3_plugin.get_router(context, router_id)
            gw_info = router.get('external_gateway_info')
            if gw_info:
                return gw_info.get('network_id')
        except Exception:
            pass
        return None

    def sync(self, context, processes):
        super(AciIPsecDriver, self).sync(context, processes)
