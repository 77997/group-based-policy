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
    # NOTE: ACI enforces packet-rate limiting through a qosDppPol in
    # packet mode (APIC 6.1(2)+). It shares the per-direction DPP slot of
    # a qosRequirement with the bandwidth_limit rule, so the two are
    # mutually exclusive per direction (enforced in the mechanism driver).
    qos_consts.RULE_TYPE_PACKET_RATE_LIMIT: {
        qos_consts.MAX_KPPS: {
            'type:range': [0, db_consts.DB_INTEGER_MAX_VALUE]},
        qos_consts.MAX_BURST_KPPS: {
            'type:range': [0, db_consts.DB_INTEGER_MAX_VALUE]},
        qos_consts.DIRECTION: {
            'type:values': constants.VALID_DIRECTIONS},
    },
}

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

VIF_TYPES = [portbindings.VIF_TYPE_OVS, portbindings.VIF_TYPE_VHOST_USER]
VNIC_TYPES = [portbindings.VNIC_NORMAL]

DRIVER = None


class ACIQosDriver(base.DriverBase):

    @classmethod
    def create(cls, plugin_driver):
        supported_rules = dict(SUPPORTED_RULES)
        # Only advertise the Placement-backed minimum rules when the
        # corresponding resource providers are configured to be reported.
        if qos_rp.parse_rp_bandwidths(cfg.CONF):
            supported_rules.update(MINIMUM_BANDWIDTH_RULES)
        if qos_rp.parse_rp_packet_rates(cfg.CONF):
            supported_rules.update(MINIMUM_PACKET_RATE_RULES)
        obj = ACIQosDriver(name='ACIQosDriver',
                           vif_types=VIF_TYPES,
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
