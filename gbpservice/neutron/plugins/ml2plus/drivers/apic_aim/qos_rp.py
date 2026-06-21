# Copyright (c) 2026 Cisco Systems Inc.
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

"""Placement resource-provider reporting for apic_aim QoS minimum-bandwidth
and minimum-packet-rate scheduling.

Unlike ML2/OVS or SR-IOV, the bandwidth-providing resource in an ACI fabric
is the leaf-switch uplink a compute host attaches to, not a host-local
bridge/NIC the L2 agent owns. That topology is known server-side from AIM
``HostLink`` records (host_name -> switch/module/port), so apic_aim reports
the resource providers to Placement directly rather than relying on the
agent-based ``placement_report`` service plugin.

This module is split into:

* pure, unit-testable helpers (config parsing + RP-descriptor building) that
  do not touch Placement or the database, and
* :class:`ApicRpReporter`, which performs the actual Placement I/O.

NOTE (best-effort, 2026): the Placement I/O path has NOT been validated
against a live APIC + Nova + Placement deployment. The descriptor model and
config parsing are unit-tested; the ``report()`` sync must be exercised in a
lab before relying on it. See STATUS_qos_min_bandwidth.md.
"""

import re
import uuid

from oslo_log import log as logging

LOG = logging.getLogger(__name__)

# os-resource-classes string values (avoid a hard import dependency).
RC_NET_BW_EGR = 'NET_BW_EGR_KILOBIT_PER_SEC'
RC_NET_BW_IGR = 'NET_BW_IGR_KILOBIT_PER_SEC'
RC_NET_PACKET_RATE = 'NET_PACKET_RATE_KILOPACKET_PER_SEC'
RC_NET_PACKET_RATE_EGR = 'NET_PACKET_RATE_EGR_KILOPACKET_PER_SEC'
RC_NET_PACKET_RATE_IGR = 'NET_PACKET_RATE_IGR_KILOPACKET_PER_SEC'

TRAIT_VNIC_NORMAL = 'CUSTOM_VNIC_TYPE_NORMAL'

# uuid5 namespace identifying apic_aim-owned resource providers. Must be
# stable across restarts so RPs are not duplicated. Also assigned to the
# mechanism driver's resource_provider_uuid5_namespace attribute.
APIC_AIM_RP_NAMESPACE = uuid.UUID('0b1e7a5c-9d3f-5e8a-b4c6-7f2a1d9e3c50')


def physnet_trait(physnet):
    """Return the CUSTOM_PHYSNET_* trait name for a physnet.

    Mirrors neutron's normalisation: upper-case and replace any character
    that is not a letter, digit or underscore with '_'.
    """
    normalized = re.sub(r'[^A-Z0-9_]', '_', physnet.upper())
    return 'CUSTOM_PHYSNET_%s' % normalized


def _parse_triples(values):
    """Parse ['physnet:egr:igr', ...] into {physnet: (egr, igr)}.

    Empty egress/ingress fields become ``None`` (meaning "do not report an
    inventory for that direction" = unlimited). Raises ValueError on a
    malformed entry so misconfiguration is caught early.
    """
    result = {}
    for entry in values or []:
        entry = entry.strip()
        if not entry:
            continue
        parts = entry.split(':')
        if len(parts) != 3:
            raise ValueError(
                "Malformed resource provider entry %r: expected "
                "<physnet>:<egress>:<ingress>" % entry)
        physnet, egr, igr = (p.strip() for p in parts)
        if not physnet:
            raise ValueError("Empty physnet in entry %r" % entry)
        result[physnet] = (
            int(egr) if egr != '' else None,
            int(igr) if igr != '' else None)
    return result


def parse_rp_bandwidths(conf):
    """{physnet: (egress_kbps, ingress_kbps)} from config."""
    return _parse_triples(conf.ml2_apic_aim.resource_provider_bandwidths)


def parse_rp_packet_rates(conf):
    """{physnet: (egress_kpps, ingress_kpps)} from config."""
    return _parse_triples(
        conf.ml2_apic_aim.resource_provider_packet_processing)


def is_enabled(conf):
    """True if any RP reporting is configured."""
    return bool(conf.ml2_apic_aim.resource_provider_bandwidths or
                conf.ml2_apic_aim.resource_provider_packet_processing)


def rp_uuid(host, physnet):
    """Deterministic RP uuid for a (host, physnet) bandwidth provider."""
    return str(uuid.uuid5(APIC_AIM_RP_NAMESPACE, '%s:%s' % (host, physnet)))


def _inventory(rc, total, defaults):
    inv = {'total': total}
    for key in ('allocation_ratio', 'min_unit', 'max_unit',
                'step_size', 'reserved'):
        if key in defaults:
            inv[key] = defaults[key]
    inv.setdefault('max_unit', total)
    return {rc: inv}


def build_rp_descriptors(hosts, bw_map, pps_map, hypervisors,
                         inv_defaults, pps_inv_defaults):
    """Build the desired Placement resource-provider state.

    :param hosts: iterable of compute host names (from AIM HostLink).
    :param bw_map: {physnet: (egr_kbps, igr_kbps)}.
    :param pps_map: {physnet: (egr_kpps, igr_kpps)}.
    :param hypervisors: {physnet: hypervisor_name} overrides.
    :param inv_defaults: dict of bandwidth inventory defaults.
    :param pps_inv_defaults: dict of packet-rate inventory defaults.
    :returns: list of descriptor dicts, each::

        {'uuid', 'name', 'hypervisor', 'physnet',
         'inventories': {rc: {...}}, 'traits': [...]}

    This is a pure function (no I/O), so it is fully unit-tested.
    """
    descriptors = []
    physnets = set(bw_map) | set(pps_map)
    for host in sorted(hosts):
        for physnet in sorted(physnets):
            inventories = {}
            egr_bw, igr_bw = bw_map.get(physnet, (None, None))
            if egr_bw:
                inventories.update(
                    _inventory(RC_NET_BW_EGR, egr_bw, inv_defaults))
            if igr_bw:
                inventories.update(
                    _inventory(RC_NET_BW_IGR, igr_bw, inv_defaults))
            egr_pps, igr_pps = pps_map.get(physnet, (None, None))
            if egr_pps:
                inventories.update(
                    _inventory(RC_NET_PACKET_RATE_EGR, egr_pps,
                               pps_inv_defaults))
            if igr_pps:
                inventories.update(
                    _inventory(RC_NET_PACKET_RATE_IGR, igr_pps,
                               pps_inv_defaults))
            if not inventories:
                continue
            descriptors.append({
                'uuid': rp_uuid(host, physnet),
                'name': '%s:apic_aim:%s' % (host, physnet),
                'hypervisor': hypervisors.get(physnet, host),
                'physnet': physnet,
                'inventories': inventories,
                'traits': [physnet_trait(physnet), TRAIT_VNIC_NORMAL],
            })
    return descriptors


class ApicRpReporter(object):
    """Sync apic_aim bandwidth resource providers into Placement.

    The reporter is driven server-side (e.g. from a periodic task or on
    HostLink changes). It is intentionally best-effort and idempotent: it
    ensures each (host, physnet) child RP exists under the host's hypervisor
    RP, with the configured inventories and traits.
    """

    def __init__(self, aim, aim_context_factory, placement_client, conf):
        self._aim = aim
        self._aim_context_factory = aim_context_factory
        self._placement = placement_client
        self._conf = conf

    def _hosts(self):
        """Compute hosts known to the ACI fabric, from AIM HostLink."""
        from aim.api import infra as aim_infra
        aim_ctx = self._aim_context_factory()
        links = self._aim.find(aim_ctx, aim_infra.HostLink)
        return sorted({link.host_name for link in links if link.host_name})

    def desired_state(self):
        return build_rp_descriptors(
            self._hosts(),
            parse_rp_bandwidths(self._conf),
            parse_rp_packet_rates(self._conf),
            self._conf.ml2_apic_aim.resource_provider_hypervisors,
            self._conf.ml2_apic_aim.resource_provider_inventory_defaults,
            (self._conf.ml2_apic_aim.
             resource_provider_packet_processing_inventory_defaults))

    def report(self):
        """Push the desired RP state to Placement (best-effort).

        NOTE: unvalidated against a live deployment. The exact
        PlacementAPIClient method names/signatures must be confirmed in a
        lab; failures are logged and swallowed so a reporting problem never
        breaks the mechanism driver.
        """
        if not is_enabled(self._conf):
            return
        for desc in self.desired_state():
            try:
                parent = self._placement.list_resource_providers(
                    name=desc['hypervisor'])
                parent_rps = parent.get('resource_providers', [])
                if not parent_rps:
                    LOG.warning("apic_aim QoS RP: hypervisor RP %s not found "
                                "in Placement; skipping %s",
                                desc['hypervisor'], desc['name'])
                    continue
                parent_uuid = parent_rps[0]['uuid']
                self._placement.ensure_resource_provider(
                    {'uuid': desc['uuid'],
                     'name': desc['name'],
                     'parent_provider_uuid': parent_uuid})
                self._placement.update_resource_provider_inventories(
                    desc['uuid'], desc['inventories'])
                self._placement.update_resource_provider_traits(
                    desc['uuid'], desc['traits'])
                LOG.debug("apic_aim QoS RP reported: %s", desc['name'])
            except Exception as e:
                LOG.warning("apic_aim QoS RP reporting failed for %s: %s",
                            desc['name'], e)
