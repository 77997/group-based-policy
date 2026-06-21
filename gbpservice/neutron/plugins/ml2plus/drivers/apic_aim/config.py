# Copyright (c) 2014 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_config import cfg

from gbpservice._i18n import _


apic_opts = [
    cfg.BoolOpt('enable_optimized_dhcp', default=True),
    cfg.BoolOpt('enable_optimized_metadata', default=False),
    cfg.StrOpt('keystone_notification_exchange',
               default='keystone',
               help=("The exchange used to subscribe to Keystone "
                     "notifications")),
    cfg.StrOpt('keystone_notification_topic',
               default='notifications',
               help=("The topic used to subscribe to Keystone "
                     "notifications")),
    cfg.StrOpt('keystone_notification_pool',
               default=None,
               help=("The pool used to subscribe to Keystone "
                     "notifications. This value should only be configured "
                     "to a value other than 'None' when there are other "
                     "notification listeners subscribed to the same "
                     "keystone exchange and topic, whose pool is set "
                     "to 'None'.")),
    cfg.IntOpt('apic_optimized_dhcp_lease_time', default=0,
               help=("Number of seconds for the optimized DHCP lease time. "
                     "Default is 0 which means using opflex agent's default "
                     "value.")),
    cfg.BoolOpt('enable_keystone_notification_purge',
                default=False,
                help=("This will enable purging all the resources including "
                      "the tenant once a keystone project.deleted "
                      "notification is received.")),
    cfg.BoolOpt('enable_neutronclient_internal_ep_interface',
                default=False,
                help=("Set to True to use the internal endpoint interface "
                      "while initializing the neutron client. By default its "
                      "using the public interface.")),
    cfg.BoolOpt('enable_iptables_firewall',
                default=False,
                help=("This will enable the iptables firewall implementation "
                      "on those compute nodes.")),
    # TODO(kentwu): Need to define the external routed domain
    # AIM object instead.
    cfg.StrOpt('l3_domain_dn', default='',
               help=("The DN of the APIC external routed domain used by the "
                     "auto l3out created for the SVI networks.")),
    cfg.StrOpt('apic_router_id_pool', default='199.199.199.1/24',
               help=("The pool of IPs where we allocate the APIC "
                     "router ID from while creating the SVI interface.")),
    cfg.DictOpt('migrate_ext_net_dns', default={},
                help="DNs for external networks being migrated from other "
                "plugin, formatted as a dictionary mapping Neutron external "
                "network IDs (UUIDs) to ACI external network distinguished "
                "names."),
    cfg.IntOpt('apic_nova_vm_name_cache_update_interval', default=60,
               help=("How many seconds for the polling thread on each "
                     "controller should wait before it updates the nova vm "
                     "name cache again.")),
    cfg.BoolOpt('allow_routed_vrf_subnet_overlap',
                default=False,
                help=("Set to True to turn off checking for overlapping "
                      "subnets within a routed VRF when adding or removing "
                      "router interfaces. Overlapping subnets in a routed VRF "
                      "will result in ACI faults and lost connectivity, so "
                      "this should only be used temporarily to enable "
                      "cleaning up overlapping routed subnets created before "
                      "overlap checking was implemented.")),
    # --- QoS minimum-bandwidth / minimum-packet-rate (Placement) ---
    # These mirror the ML2/OVS agent options but are consumed server-side
    # by the apic_aim Placement reporter (the bandwidth-providing resource
    # in ACI is the fabric leaf uplink the host attaches to, known from
    # AIM HostLink, not a host-local bridge). See qos_rp.py.
    cfg.ListOpt('resource_provider_bandwidths',
                default=[],
                help=("Comma-separated list of "
                      "<physnet>:<egress_kbps>:<ingress_kbps> tuples "
                      "describing the bandwidth each host's fabric uplink "
                      "provides for a physnet. An empty egress/ingress means "
                      "unlimited (no inventory reported for that direction). "
                      "When set, apic_aim reports NET_BW_*_KILOBIT_PER_SEC "
                      "inventories to Placement so Nova can schedule ports "
                      "carrying minimum_bandwidth QoS rules.")),
    cfg.ListOpt('resource_provider_packet_processing',
                default=[],
                help=("Comma-separated list of "
                      "<physnet>:<egress_kpps>:<ingress_kpps> tuples "
                      "describing the packet-rate capacity each host's "
                      "fabric uplink provides for a physnet, used to report "
                      "NET_PACKET_RATE_* inventories for minimum_packet_rate "
                      "QoS rules.")),
    cfg.DictOpt('resource_provider_inventory_defaults',
                default={'allocation_ratio': 1.0,
                         'min_unit': 1,
                         'step_size': 1,
                         'reserved': 0},
                help=("Key:value pairs for the bandwidth resource provider "
                      "inventory, applied to every reported inventory. Valid "
                      "keys: allocation_ratio, min_unit, max_unit, step_size, "
                      "reserved.")),
    cfg.DictOpt('resource_provider_packet_processing_inventory_defaults',
                default={'allocation_ratio': 1.0,
                         'min_unit': 1,
                         'step_size': 1,
                         'reserved': 0},
                help=("As resource_provider_inventory_defaults but for the "
                      "packet-rate inventories.")),
    cfg.DictOpt('resource_provider_hypervisors',
                default={},
                help=("Optional <physnet>:<hypervisor_name> overrides used "
                      "to map a physnet's bandwidth resource provider to the "
                      "Nova compute (hypervisor) resource provider. Defaults "
                      "to the AIM HostLink host_name when not given.")),
]


cfg.CONF.register_opts(apic_opts, "ml2_apic_aim")


# oslo_config limits ${var} expansion to global variables
# That is why apic_system_id as a global variable
global_opts = [
    cfg.StrOpt('apic_system_id',
               default='openstack',
               help=_("Prefix for APIC domain/names/profiles created")),
]


cfg.CONF.register_opts(global_opts)
