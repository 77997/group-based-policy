# Copyright (c) 2020 Cisco Systems Inc.
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

from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from neutron_lib.db import constants as db_consts
from neutron_lib.services.qos import base
from neutron_lib.services.qos import constants as qos_consts
from oslo_config import cfg
from oslo_log import log as logging

from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import qos_rp

LOG = logging.getLogger(__name__)

SUPPORTED_RULES = {
    qos_consts.RULE_TYPE_BANDWIDTH_LIMIT: {
        qos_consts.MAX_KBPS: {
            'type:range': [0, db_consts.DB_INTEGER_MAX_VALUE]},
        qos_consts.MAX_BURST: {
            'type:range': [0, db_consts.DB_INTEGER_MAX_VALUE]},
        qos_consts.DIRECTION: {
            'type:values': constants.VALID_DIRECTIONS},
    },
    qos_consts.RULE_TYPE_DSCP_MARKING: {
        qos_consts.DSCP_MARK: {'type:values': constants.VALID_DSCP_MARKS},
    },
}

# NOTE: packet_rate_limit is deliberately NOT advertised, even though the
# Neutron -> AIM -> APIC half of it works: _handle_qos_policy emits a
# qosDppPol with mode='packet' and the AID converter pushes it unmodified.
#
# It cannot be enforced on an OpFlex host. QoS for these ports is programmed
# by agent-ovs, and the OpFlex policy model has no packet-rate representation
# at all: genie/MODEL/SPECIFIC/GBP/COMMON/qos.mdl declares
# "#Burst and Rate are always in Kbps" and class BandwidthLimit carries only
# burst and rate, while QosRenderer.cpp reads getRate()/getBurst() and writes
# OVSDB ingress_policing_rate / ingress_policing_burst, which are kbps. A
# max_kpps therefore either never reaches the compute or is applied as a
# kilobit-per-second policer - roughly a thousandfold error, in the direction
# of throttling the port far harder than asked, with Neutron reporting success
# and AIM reporting synced throughout.
#
# Advertising a rule the data plane silently mis-applies is worse than not
# offering it: the API now refuses it with "rule type not supported", which is
# the truth. Restore this block if the agent's model gains a packet mode.

# Minimum-bandwidth / minimum-packet-rate are admission-control (Placement)
# rules: they have no ACI data-plane guarantee, only capacity-aware
# scheduling. They are advertised ONLY when the apic_aim Placement reporter
# is configured (resource_provider_bandwidths / _packet_processing); without
# reported resource providers Nova cannot schedule the request, so claiming
# support unconditionally would break port binding.
MINIMUM_BANDWIDTH_RULES = {
    qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH: {
        qos_consts.MIN_KBPS: {
            'type:range': [0, db_consts.DB_INTEGER_MAX_VALUE]},
        qos_consts.DIRECTION: {
            'type:values': constants.VALID_DIRECTIONS},
    },
}
MINIMUM_PACKET_RATE_RULES = {
    qos_consts.RULE_TYPE_MINIMUM_PACKET_RATE: {
        qos_consts.MIN_KPPS: {
            'type:range': [0, db_consts.DB_INTEGER_MAX_VALUE]},
        qos_consts.DIRECTION: {
            'type:values': [constants.EGRESS_DIRECTION,
                            constants.INGRESS_DIRECTION,
                            constants.ANY_DIRECTION]},
    },
}

# VIF_TYPE_FABRIC ports are router interfaces and other ports whose
# binding:host_id starts with FABRIC_HOST_ID: the ACI fabric implements them
# itself as an anycast gateway, so they are bound by mechanism_driver.bind_port
# without ever landing on a compute host. They carry no OVS interface and no
# policer, which is correct - ACI applies a network's QoS at the EPG via
# fvRsQosRequirement, and the fabric SVI is not an endpoint of that EPG.
#
# They must still be listed here. Neutron validates a network-level QoS policy
# against EVERY port on the network (QoSPlugin._validate_update_network_callback
# -> validate_rule_for_port), and a port whose vif_type no driver claims fails
# with "Rule bandwidth_limit is not supported by port <uuid>". Omitting the type
# therefore does not scope QoS away from fabric ports - it makes network-level
# QoS impossible on any network that has a router attached.
VIF_TYPES = [portbindings.VIF_TYPE_OVS, portbindings.VIF_TYPE_VHOST_USER]
VNIC_TYPES = [portbindings.VNIC_NORMAL]

DRIVER = None


class ACIQosDriver(base.DriverBase):

    @classmethod
    def create(cls, plugin_driver):
        # Imported here rather than at module scope: mechanism_driver imports
        # this module, and defines VIF_TYPE_FABRIC after that import runs, so a
        # top-level import would be circular and the name would be undefined.
        from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import (
            mechanism_driver as md)
        vif_types = VIF_TYPES + [md.VIF_TYPE_FABRIC]
        supported_rules = dict(SUPPORTED_RULES)
        # Only advertise the Placement-backed minimum rules when the
        # corresponding resource providers are configured to be reported.
        if qos_rp.parse_rp_bandwidths(cfg.CONF):
            supported_rules.update(MINIMUM_BANDWIDTH_RULES)
        if qos_rp.parse_rp_packet_rates(cfg.CONF):
            supported_rules.update(MINIMUM_PACKET_RATE_RULES)
        obj = ACIQosDriver(name='ACIQosDriver',
                           vif_types=vif_types,
                           vnic_types=VNIC_TYPES,
                           supported_rules=supported_rules,
                           requires_rpc_notifications=False)
        obj._driver = plugin_driver
        return obj

    @property
    def is_loaded(self):
        return 'qos' in cfg.CONF.ml2.extension_drivers

    def create_policy_precommit(self, context, policy):
        self._driver.create_qos_policy_precommit(context, policy)

    def update_policy_precommit(self, context, policy):
        self._driver.update_qos_policy_precommit(context, policy)

    def delete_policy_precommit(self, context, policy):
        self._driver.delete_qos_policy_precommit(context, policy)


def register(plugin_driver):
    """Register the driver."""
    global DRIVER
    if not DRIVER:
        DRIVER = ACIQosDriver.create(plugin_driver)
    LOG.debug('ACI QoS driver registered')
    return DRIVER
