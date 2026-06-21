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

from neutron.services.logapi.drivers import base as log_base
from neutron_lib import context as n_context
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_log import log as logging

LOG = logging.getLogger(__name__)

OPFLEX_DROP_LOG_DIR = '/var/lib/opflex-agent-ovs/droplog'

EVENT_ACCEPT = 'ACCEPT'
EVENT_DROP = 'DROP'
EVENT_ALL = 'ALL'


class AciPacketLogDriver(log_base.DriverBase):
    """Packet logging driver for ACI using opflex-agent-ovs per-SG logging.

    Extends the opflex agent's existing .droplogcfg config files to include
    a 'log-sgs' list of SG URIs. The C++ opflex agent watches these files
    via inotify and enables per-rule permit/deny logging for listed SGs
    without requiring a restart.

    Event type filtering:
      - ALL:    log both PERMIT and DENY actions (default)
      - ACCEPT: log only PERMIT actions
      - DROP:   log only DENY actions (uses existing drop-log infra)

    Rate limiting is mapped to the 'rate-limit' field in the .droplogcfg
    file. The C++ agent's PacketLogHandler uses a KeyedRateLimiter to
    throttle log output per SG.

    Log output: syslog or file via the opflex agent's PacketLogHandler,
    format: {bridge}-{table} {MISS|DENY|PERMIT} {rule-URI}
            MAC=... IPv4 SRC=... DST=... PROTO=... SPORT=... DPORT=...
    """

    SUPPORTED_LOGGING_TYPES = ['security_group']

    def __init__(self):
        super(AciPacketLogDriver, self).__init__(
            name='aci',
            vif_types=[],
            vnic_types=[],
            supported_logging_types=self.SUPPORTED_LOGGING_TYPES)
        self._log_dir = getattr(cfg.CONF, 'opflex_drop_log_dir',
                                OPFLEX_DROP_LOG_DIR)

    @staticmethod
    def create():
        return AciPacketLogDriver()

    @property
    def is_loaded(self):
        return True

    def is_vif_type_compatible(self, vif_type):
        return True

    def _get_sg_uri(self, tenant_name, sg_id):
        return ('/PolicyUniverse/PolicySpace/%s/'
                'GbpSecGroup/%s/' % (tenant_name, sg_id))

    def _get_tenant_name(self, project_id):
        plugin = directory.get_plugin()
        mech_driver = (
            plugin.mechanism_manager.mech_drivers['apic_aim'].obj)
        return mech_driver.name_mapper.project(None, project_id)

    def _get_compute_hosts_for_sg(self, context, sg_id):
        """Find all compute hosts that have ports using this SG."""
        plugin = directory.get_plugin()
        ports = plugin.get_ports(
            context,
            filters={'security_groups': [sg_id]})
        hosts = set()
        for port in ports:
            host = port.get('binding:host_id')
            if host:
                hosts.add(host)
        return hosts

    def _map_event_type(self, log_res):
        """Map Neutron log resource event type to opflex log mode.

        Returns a tuple (log_permits, log_drops) controlling which actions
        the C++ agent should capture.
        """
        event = log_res.get('event', EVENT_ALL).upper()
        if event == EVENT_ACCEPT:
            return True, False
        elif event == EVENT_DROP:
            return False, True
        return True, True

    def _write_droplog_config(self, host, sg_uris, log_permits=True,
                              log_drops=True, rate_limit=None,
                              burst_limit=None):
        """Write .droplogcfg file with log-sgs list for a compute host.

        The opflex agent watches this directory and hot-reloads via inotify.
        """
        config_dir = os.path.join(self._log_dir, host)
        os.makedirs(config_dir, exist_ok=True)
        config_file = os.path.join(config_dir, 'openstack.droplogcfg')

        config = {'drop-log-enable': True}
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
            except Exception:
                pass

        config['log-sgs'] = list(sg_uris)
        config['log-permits'] = log_permits
        config['log-drops'] = log_drops

        if rate_limit is not None:
            config['rate-limit'] = rate_limit
        if burst_limit is not None:
            config['burst-limit'] = burst_limit

        if not sg_uris:
            config['drop-log-enable'] = False

        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)

    def _collect_active_sg_uris(self, context):
        """Collect all SG URIs that should be logged across all hosts.

        Returns dict: {host: {'sg_uris': set, 'log_permits': bool,
                               'log_drops': bool, 'rate_limit': int|None,
                               'burst_limit': int|None}}
        """
        log_plugin = directory.get_plugin('log')
        if not log_plugin:
            return {}

        host_config = {}
        logs = log_plugin.get_logs(context)
        for log_res in logs:
            if not log_res.get('enabled', True):
                continue
            sg_id = log_res.get('resource_id')
            if not sg_id:
                continue
            project_id = log_res.get('project_id')
            tenant_name = self._get_tenant_name(project_id)
            sg_uri = self._get_sg_uri(tenant_name, sg_id)
            log_permits, log_drops = self._map_event_type(log_res)

            hosts = self._get_compute_hosts_for_sg(context, sg_id)
            for host in hosts:
                if host not in host_config:
                    host_config[host] = {
                        'sg_uris': set(),
                        'log_permits': False,
                        'log_drops': False,
                        'rate_limit': None,
                        'burst_limit': None,
                    }
                hc = host_config[host]
                hc['sg_uris'].add(sg_uri)
                hc['log_permits'] = hc['log_permits'] or log_permits
                hc['log_drops'] = hc['log_drops'] or log_drops

                rl = log_res.get('rate_limit')
                bl = log_res.get('burst_limit')
                if rl is not None:
                    if hc['rate_limit'] is None:
                        hc['rate_limit'] = rl
                    else:
                        hc['rate_limit'] = max(hc['rate_limit'], rl)
                if bl is not None:
                    if hc['burst_limit'] is None:
                        hc['burst_limit'] = bl
                    else:
                        hc['burst_limit'] = max(hc['burst_limit'], bl)

        return host_config

    def _sync_all_hosts(self, context):
        host_config = self._collect_active_sg_uris(context)
        for host, hc in host_config.items():
            self._write_droplog_config(
                host, hc['sg_uris'],
                log_permits=hc['log_permits'],
                log_drops=hc['log_drops'],
                rate_limit=hc['rate_limit'],
                burst_limit=hc['burst_limit'])

    def create_log(self, context, log_obj):
        admin_ctx = n_context.get_admin_context()
        self._sync_all_hosts(admin_ctx)

    def create_log_precommit(self, context, log_obj):
        pass

    def update_log(self, context, log_obj):
        self.create_log(context, log_obj)

    def update_log_precommit(self, context, log_obj):
        pass

    def delete_log(self, context, log_obj):
        admin_ctx = n_context.get_admin_context()
        self._sync_all_hosts(admin_ctx)

    def delete_log_precommit(self, context, log_obj):
        pass
