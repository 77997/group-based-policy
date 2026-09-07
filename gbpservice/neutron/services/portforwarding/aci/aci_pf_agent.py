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

import sys

from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_manager
from neutron_lib import context as n_context
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import loopingcall
from oslo_service import service

LOG = logging.getLogger(__name__)

NAMESPACE_PREFIX = 'qpf-'
SYNC_INTERVAL = 60


class AciPortForwardingAgent(object):
    """Standalone agent managing iptables DNAT for port forwarding on ACI.

    Runs on network nodes. For each router with port forwarding rules,
    creates a qpf-{router_id} namespace, claims the floating IP via a
    port on the external network, and installs iptables DNAT rules.

    Traffic flow:
    External -> ACI fabric -> network node br-int -> qpf namespace
    -> iptables DNAT -> br-int -> ACI fabric -> target VM compute
    """

    def __init__(self, host):
        self.host = host
        self._managed_namespaces = {}

    def _get_namespace(self, router_id):
        return NAMESPACE_PREFIX + router_id

    def _ensure_namespace(self, router_id):
        ns_name = self._get_namespace(router_id)
        ip = ip_lib.IPWrapper()
        if not ip.netns.exists(ns_name):
            ip.netns.add(ns_name)
            LOG.info('Created port forwarding namespace %s', ns_name)
        return ns_name

    def _remove_namespace(self, router_id):
        ns_name = self._get_namespace(router_id)
        ip = ip_lib.IPWrapper()
        if ip.netns.exists(ns_name):
            ip.netns.delete(ns_name)
            LOG.info('Deleted port forwarding namespace %s', ns_name)

    def _ensure_ext_port(self, context, router_id, ext_net_id, fip_address):
        """Ensure an external port exists claiming the floating IP."""
        plugin = directory.get_plugin()
        device_id = 'pf-' + router_id
        device_owner = 'network:portforwarding'

        existing = plugin.get_ports(
            context,
            filters={'device_id': [device_id],
                     'device_owner': [device_owner]})
        if existing:
            return existing[0]

        port_data = {
            'port': {
                'network_id': ext_net_id,
                'device_id': device_id,
                'device_owner': device_owner,
                'admin_state_up': True,
                'binding:host_id': self.host,
                'fixed_ips': [{'ip_address': fip_address}],
                'name': 'pf-ext-%s' % router_id[:8],
            }
        }
        try:
            return plugin.create_port(context, port_data)
        except Exception:
            LOG.exception('Failed to create port forwarding external port')
            return None

    def _apply_iptables_rules(self, ns_name, rules):
        """Install DNAT rules inside the namespace.

        Each rule: {protocol, external_port, internal_ip, internal_port}
        """
        ns_ip = ip_lib.IPWrapper(namespace=ns_name)
        ipt_mgr = iptables_manager.IptablesManager(
            namespace=ns_name, use_ipv6=False)

        for rule in rules:
            proto = rule.get('protocol', 'tcp')
            ext_port = rule.get('external_port')
            int_ip = rule.get('internal_ip_address')
            int_port = rule.get('internal_port')

            if not all([ext_port, int_ip, int_port]):
                continue

            ipt_rule = (
                '-p %s --dport %s -j DNAT '
                '--to-destination %s:%s' % (
                    proto, ext_port, int_ip, int_port))
            ipt_mgr.ipv4['nat'].add_rule('PREROUTING', ipt_rule)

        ipt_mgr.apply()

    def _sync_port_forwarding(self):
        """Periodic sync of port forwarding rules."""
        context = n_context.get_admin_context()
        try:
            l3_plugin = directory.get_plugin('L3_ROUTER_NAT')
            if not l3_plugin:
                return

            pf_plugin = directory.get_plugin('port_forwarding')
            if not pf_plugin:
                return

            fips = l3_plugin.get_floatingips(context)
            router_rules = {}

            for fip in fips:
                fip_id = fip['id']
                try:
                    pf_rules = pf_plugin.get_floatingip_port_forwardings(
                        context, fip_id)
                except Exception:
                    continue

                if not pf_rules:
                    continue

                router_id = fip.get('router_id')
                if not router_id:
                    continue

                router_rules.setdefault(router_id, {
                    'ext_net_id': fip.get('floating_network_id'),
                    'fip_address': fip.get('floating_ip_address'),
                    'rules': [],
                })
                router_rules[router_id]['rules'].extend(pf_rules)

            active_routers = set()
            for router_id, info in router_rules.items():
                ns_name = self._ensure_namespace(router_id)
                self._ensure_ext_port(
                    context, router_id,
                    info['ext_net_id'], info['fip_address'])
                self._apply_iptables_rules(ns_name, info['rules'])
                active_routers.add(router_id)

            for router_id in list(self._managed_namespaces.keys()):
                if router_id not in active_routers:
                    self._remove_namespace(router_id)
                    del self._managed_namespaces[router_id]

            self._managed_namespaces = {
                r: True for r in active_routers}

        except Exception:
            LOG.exception('Error during port forwarding sync')

    def start(self):
        self._sync_port_forwarding()
        pulse = loopingcall.FixedIntervalLoopingCall(
            self._sync_port_forwarding)
        pulse.start(interval=SYNC_INTERVAL)

    def wait(self):
        pass

    def stop(self):
        pass

    def reset(self):
        pass


def main():
    from neutron.common import config as common_config
    common_config.register_common_config_options()
    common_config.init(sys.argv[1:])
    cfg.CONF(project='neutron')
    common_config.setup_logging()

    agent = AciPortForwardingAgent(cfg.CONF.host)
    launcher = service.launch(cfg.CONF, agent, restart_method='mutate')
    launcher.wait()


if __name__ == '__main__':
    main()
