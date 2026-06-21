# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit tests for the pure (I/O-free) parts of the apic_aim QoS Placement
resource-provider reporter. The Placement sync itself needs a live
deployment and is not covered here."""

from neutron.tests import base

from gbpservice.neutron.plugins.ml2plus.drivers.apic_aim import qos_rp


class TestQosRpHelpers(base.BaseTestCase):

    def test_physnet_trait(self):
        self.assertEqual('CUSTOM_PHYSNET_PHYSNET1',
                         qos_rp.physnet_trait('physnet1'))
        # Non-alnum characters are normalised to underscores.
        self.assertEqual('CUSTOM_PHYSNET_PHYS_NET_1',
                         qos_rp.physnet_trait('phys-net.1'))

    def test_parse_triples_ok(self):
        self.assertEqual(
            {'physnet1': (1000, 2000), 'physnet2': (500, None)},
            qos_rp._parse_triples(
                ['physnet1:1000:2000', 'physnet2:500:']))

    def test_parse_triples_empty(self):
        self.assertEqual({}, qos_rp._parse_triples([]))
        self.assertEqual({}, qos_rp._parse_triples(['  ']))

    def test_parse_triples_malformed(self):
        self.assertRaises(ValueError,
                          qos_rp._parse_triples, ['physnet1:1000'])
        self.assertRaises(ValueError,
                          qos_rp._parse_triples, [':1000:2000'])

    def test_rp_uuid_stable_and_unique(self):
        u1 = qos_rp.rp_uuid('host1', 'physnet1')
        # Deterministic.
        self.assertEqual(u1, qos_rp.rp_uuid('host1', 'physnet1'))
        # Distinct per host and per physnet.
        self.assertNotEqual(u1, qos_rp.rp_uuid('host2', 'physnet1'))
        self.assertNotEqual(u1, qos_rp.rp_uuid('host1', 'physnet2'))

    def test_build_rp_descriptors_bandwidth(self):
        inv_defaults = {'allocation_ratio': 1.0, 'min_unit': 1,
                        'step_size': 1, 'reserved': 0}
        descs = qos_rp.build_rp_descriptors(
            hosts=['host1'],
            bw_map={'physnet1': (1000, 2000)},
            pps_map={},
            hypervisors={},
            inv_defaults=inv_defaults,
            pps_inv_defaults={})
        self.assertEqual(1, len(descs))
        d = descs[0]
        self.assertEqual('host1', d['hypervisor'])
        self.assertEqual(qos_rp.rp_uuid('host1', 'physnet1'), d['uuid'])
        self.assertIn(qos_rp.RC_NET_BW_EGR, d['inventories'])
        self.assertIn(qos_rp.RC_NET_BW_IGR, d['inventories'])
        self.assertEqual(1000, d['inventories'][qos_rp.RC_NET_BW_EGR]['total'])
        self.assertEqual(2000, d['inventories'][qos_rp.RC_NET_BW_IGR]['total'])
        self.assertIn('CUSTOM_PHYSNET_PHYSNET1', d['traits'])
        self.assertIn(qos_rp.TRAIT_VNIC_NORMAL, d['traits'])

    def test_build_rp_descriptors_skips_empty_direction(self):
        # Only ingress configured -> no egress inventory.
        descs = qos_rp.build_rp_descriptors(
            hosts=['host1'],
            bw_map={'physnet1': (None, 2000)},
            pps_map={},
            hypervisors={},
            inv_defaults={},
            pps_inv_defaults={})
        self.assertEqual(1, len(descs))
        self.assertNotIn(qos_rp.RC_NET_BW_EGR, descs[0]['inventories'])
        self.assertIn(qos_rp.RC_NET_BW_IGR, descs[0]['inventories'])

    def test_build_rp_descriptors_packet_rate_and_hypervisor_override(self):
        descs = qos_rp.build_rp_descriptors(
            hosts=['host1'],
            bw_map={},
            pps_map={'physnet1': (300, 400)},
            hypervisors={'physnet1': 'cmp-1.example.com'},
            inv_defaults={},
            pps_inv_defaults={'allocation_ratio': 1.0})
        self.assertEqual(1, len(descs))
        d = descs[0]
        self.assertEqual('cmp-1.example.com', d['hypervisor'])
        self.assertIn(qos_rp.RC_NET_PACKET_RATE_EGR, d['inventories'])
        self.assertIn(qos_rp.RC_NET_PACKET_RATE_IGR, d['inventories'])

    def test_build_rp_descriptors_no_inventory_no_rp(self):
        # A physnet with no bandwidth and no packet rate produces nothing.
        descs = qos_rp.build_rp_descriptors(
            hosts=['host1'],
            bw_map={'physnet1': (None, None)},
            pps_map={},
            hypervisors={},
            inv_defaults={},
            pps_inv_defaults={})
        self.assertEqual([], descs)
