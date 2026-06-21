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

import json
import os
import tempfile
from unittest import mock

from gbpservice.neutron.services.logapi.aim import log_driver
from oslotest import base as test_base
from oslo_utils import uuidutils


class TestAciPacketLogDriver(test_base.BaseTestCase):

    def setUp(self):
        super(TestAciPacketLogDriver, self).setUp()
        self.driver = log_driver.AciPacketLogDriver()
        self.tmpdir = tempfile.mkdtemp()
        self.driver._log_dir = self.tmpdir

    def test_get_sg_uri(self):
        uri = self.driver._get_sg_uri('tenant0', 'sg-abc123')
        self.assertEqual(
            '/PolicyUniverse/PolicySpace/tenant0/GbpSecGroup/sg-abc123/',
            uri)

    def test_write_droplog_config_creates_file(self):
        sg_uris = {'/PolicyUniverse/PolicySpace/t0/GbpSecGroup/sg1/'}
        self.driver._write_droplog_config('host1', sg_uris)

        config_file = os.path.join(
            self.tmpdir, 'host1', 'openstack.droplogcfg')
        self.assertTrue(os.path.exists(config_file))

        with open(config_file, 'r') as f:
            config = json.load(f)
        self.assertTrue(config.get('drop-log-enable'))
        self.assertIn(
            '/PolicyUniverse/PolicySpace/t0/GbpSecGroup/sg1/',
            config.get('log-sgs', []))

    def test_write_droplog_config_preserves_existing(self):
        host_dir = os.path.join(self.tmpdir, 'host1')
        os.makedirs(host_dir, exist_ok=True)
        config_file = os.path.join(host_dir, 'openstack.droplogcfg')
        with open(config_file, 'w') as f:
            json.dump({
                'drop-log-enable': True,
                'drop-log-mode': 'unfiltered',
                'extra-field': 'preserved',
            }, f)

        sg_uris = {'/PolicyUniverse/PolicySpace/t0/GbpSecGroup/sg1/'}
        self.driver._write_droplog_config('host1', sg_uris)

        with open(config_file, 'r') as f:
            config = json.load(f)
        self.assertEqual('unfiltered', config.get('drop-log-mode'))
        self.assertEqual('preserved', config.get('extra-field'))
        self.assertIn(
            '/PolicyUniverse/PolicySpace/t0/GbpSecGroup/sg1/',
            config.get('log-sgs', []))

    def test_write_droplog_config_multiple_sgs(self):
        sg_uris = {
            '/PolicyUniverse/PolicySpace/t0/GbpSecGroup/sg1/',
            '/PolicyUniverse/PolicySpace/t0/GbpSecGroup/sg2/',
        }
        self.driver._write_droplog_config('host1', sg_uris)

        config_file = os.path.join(
            self.tmpdir, 'host1', 'openstack.droplogcfg')
        with open(config_file, 'r') as f:
            config = json.load(f)
        self.assertEqual(2, len(config.get('log-sgs', [])))

    def test_write_droplog_config_empty_disables(self):
        sg_uris = set()
        self.driver._write_droplog_config('host1', sg_uris)

        config_file = os.path.join(
            self.tmpdir, 'host1', 'openstack.droplogcfg')
        with open(config_file, 'r') as f:
            config = json.load(f)
        self.assertFalse(config.get('drop-log-enable'))

    def test_write_droplog_config_event_type_accept(self):
        sg_uris = {'/PolicyUniverse/PolicySpace/t0/GbpSecGroup/sg1/'}
        self.driver._write_droplog_config(
            'host1', sg_uris, log_permits=True, log_drops=False)

        config_file = os.path.join(
            self.tmpdir, 'host1', 'openstack.droplogcfg')
        with open(config_file, 'r') as f:
            config = json.load(f)
        self.assertTrue(config.get('log-permits'))
        self.assertFalse(config.get('log-drops'))

    def test_write_droplog_config_event_type_drop(self):
        sg_uris = {'/PolicyUniverse/PolicySpace/t0/GbpSecGroup/sg1/'}
        self.driver._write_droplog_config(
            'host1', sg_uris, log_permits=False, log_drops=True)

        config_file = os.path.join(
            self.tmpdir, 'host1', 'openstack.droplogcfg')
        with open(config_file, 'r') as f:
            config = json.load(f)
        self.assertFalse(config.get('log-permits'))
        self.assertTrue(config.get('log-drops'))

    def test_write_droplog_config_rate_limit(self):
        sg_uris = {'/PolicyUniverse/PolicySpace/t0/GbpSecGroup/sg1/'}
        self.driver._write_droplog_config(
            'host1', sg_uris, rate_limit=100, burst_limit=50)

        config_file = os.path.join(
            self.tmpdir, 'host1', 'openstack.droplogcfg')
        with open(config_file, 'r') as f:
            config = json.load(f)
        self.assertEqual(100, config.get('rate-limit'))
        self.assertEqual(50, config.get('burst-limit'))

    def test_map_event_type_all(self):
        log_res = {'event': 'ALL'}
        permits, drops = self.driver._map_event_type(log_res)
        self.assertTrue(permits)
        self.assertTrue(drops)

    def test_map_event_type_accept(self):
        log_res = {'event': 'ACCEPT'}
        permits, drops = self.driver._map_event_type(log_res)
        self.assertTrue(permits)
        self.assertFalse(drops)

    def test_map_event_type_drop(self):
        log_res = {'event': 'DROP'}
        permits, drops = self.driver._map_event_type(log_res)
        self.assertFalse(permits)
        self.assertTrue(drops)

    def test_map_event_type_default(self):
        log_res = {}
        permits, drops = self.driver._map_event_type(log_res)
        self.assertTrue(permits)
        self.assertTrue(drops)

    def test_is_loaded(self):
        self.assertTrue(self.driver.is_loaded)

    def test_is_vif_type_compatible(self):
        self.assertTrue(self.driver.is_vif_type_compatible('ovs'))
        self.assertTrue(self.driver.is_vif_type_compatible('vhostuser'))

    def test_supported_logging_types(self):
        self.assertIn('security_group',
                       self.driver.SUPPORTED_LOGGING_TYPES)
