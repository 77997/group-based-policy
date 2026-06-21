# apic_aim QoS minimum-bandwidth / minimum-packet-rate (Placement)

Status: **best-effort, NOT lab-validated.** Driver-side code is in place and the
pure logic is unit-tested; the Placement sync, binding interaction, and the
end-to-end Nova scheduling flow MUST be validated against a live
APIC + opflex + Nova + Placement deployment before relying on this.

## What this delivers

Capacity-aware scheduling (admission control) for ports carrying
`minimum_bandwidth` / `minimum_packet_rate` QoS rules. There is **no ACI
data-plane guarantee** — ACI DPP polices a maximum, it cannot reserve a
floor (deliberate, per design discussion). The value is that Nova will not
over-subscribe a host's fabric uplink.

## Architecture (why it differs from ML2/OVS)

In ML2/OVS the L2 agent reports `resource_provider_bandwidths` for a local
bridge, and neutron's `placement_report` service plugin syncs it to
Placement. In ACI the bandwidth-providing resource is the **leaf-switch
uplink** the host attaches to — known **server-side** from AIM `HostLink`
(`host_name -> switch/module/port`), and the dataplane agent
(`python-opflex-agent`) does not know fabric port speeds. So apic_aim
reports resource providers to Placement **directly**, server-side, instead
of via the agent path.

Resource-provider model (per `qos_rp.build_rp_descriptors`):

```
<nova compute RP "hypervisor">
  └── <host>:apic_aim:<physnet>           (uuid5 of APIC_AIM_RP_NAMESPACE)
        inventories: NET_BW_EGR/IGR_KILOBIT_PER_SEC,
                     NET_PACKET_RATE_EGR/IGR_KILOPACKET_PER_SEC
        traits:      CUSTOM_PHYSNET_<physnet>, CUSTOM_VNIC_TYPE_NORMAL
```

## Implemented (this branch, in group-based-policy)

- `config.py`: `resource_provider_bandwidths`,
  `resource_provider_packet_processing`,
  `resource_provider_inventory_defaults`,
  `resource_provider_packet_processing_inventory_defaults`,
  `resource_provider_hypervisors` (group `ml2_apic_aim`).
- `qos_rp.py`: config parsing + RP-descriptor building (pure, unit-tested) +
  `ApicRpReporter` Placement sync (best-effort, unvalidated).
- `mechanism_driver.py`: declares `resource_provider_uuid5_namespace`; sets
  up `qos_rp_reporter` when configured (does **not** auto-report at init).
- `qos_driver.py`: advertises `minimum_bandwidth` / `minimum_packet_rate` in
  `SUPPORTED_RULES` **only when** the matching RP config is set (so we never
  claim support that cannot schedule).
- `tests/unit/services/qos/test_aim_qos_rp.py`: unit tests for the pure logic.

## NOT done / needs validation

1. **Periodic reporting trigger.** The reporter object is created but
   `report()` is not yet wired to a periodic task. Add a periodic task (or a
   HostLink-change hook) that calls `self.qos_rp_reporter.report()`.
2. **Placement client calls.** `ApicRpReporter.report()` uses
   `PlacementAPIClient` method names that must be confirmed against the
   deployed neutron version (`list_resource_providers`,
   `ensure_resource_provider`, `update_resource_provider_inventories`,
   `update_resource_provider_traits`).
3. **Bind-time allocation.** apic_aim binds by host (HPB), and the RP is
   per-host-per-physnet, so binding should already be consistent with Nova's
   allocation — but confirm the port binds on the physnet matching the
   allocated RP. No binding code was changed (to avoid risk to HPB).
4. **`resource_request` flow.** Confirm the QoS plugin emits
   `port.resource_request` for min-bw/min-packet-rate ports once the rules
   are advertised, and that Nova schedules against the apic_aim RPs.

## Other-repo touch-points (NOT modified here)

- **kolla-ansible** (gated — needs your go-ahead): set
  `[ml2_apic_aim] resource_provider_bandwidths` (and friends) in the
  neutron-server config for ACI deployments. Nothing else.
- **python-opflex-agent**: NOT required by this design (reporting is
  server-side). Not in our tree.
- Runtime: APIC ≥ 6.1(2) is only needed for `packet_rate_limit`
  enforcement, not for these scheduling-only rules.

## Validation checklist (lab)

1. Set `resource_provider_bandwidths = physnet1:10000000:10000000` in
   neutron-server `[ml2_apic_aim]`; restart neutron-server.
2. Confirm `openstack network qos rule type list` shows `minimum_bandwidth`.
3. Trigger `qos_rp_reporter.report()`; verify RPs/inventories/traits appear
   under the compute RP in `openstack resource provider list`.
4. Create a QoS policy with a `minimum_bandwidth` rule, attach to a port,
   boot an instance; confirm Nova schedules and Placement shows an
   allocation against the apic_aim RP.
