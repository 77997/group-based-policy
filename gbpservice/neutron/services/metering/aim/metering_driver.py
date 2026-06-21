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

import time

from aim import aim_manager
from aim.api import resource as aim_resource
from aim import context as aim_context
from neutron.services.metering.drivers import abstract_driver
from neutron_lib import context as n_context
from neutron_lib.plugins import directory
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class AciMeteringDriver(abstract_driver.MeteringAbstractDriver):
    """Metering driver using ACI uSeg EPGs and APIC hardware counters.

    Creates uSeg EPGs per metering label CIDR, then reads per-EPG
    hardware counters from APIC REST API. APIC maintains byte/packet
    counters on leaf switches at line-rate.
    """

    def __init__(self, plugin, conf):
        super(AciMeteringDriver, self).__init__(plugin, conf)
        self._aim = None
        self._aim_mech_driver = None

    @property
    def aim(self):
        if not self._aim:
            self._aim = aim_manager.AimManager()
        return self._aim

    @property
    def aim_mech(self):
        if not self._aim_mech_driver:
            plugin = directory.get_plugin()
            self._aim_mech_driver = (
                plugin.mechanism_manager.mech_drivers['apic_aim'].obj)
        return self._aim_mech_driver

    def _get_aim_context(self):
        ctx = n_context.get_admin_context()
        return aim_context.AimContext(db_session=ctx.session)

    def _useg_epg_name(self, label_id):
        return 'meter-%s' % label_id[:8]

    def _get_tenant_name(self, project_id):
        return self.aim_mech.name_mapper.project(None, project_id)

    def _get_app_profile_name(self, project_id):
        return self.aim_mech.get_aim_app_profile_name(project_id)

    def _create_useg_epg_for_rule(self, aim_ctx, tenant_name,
                                  app_profile_name, label_id, cidr,
                                  direction):
        """Create uSeg EPG with IP criteria for a metering label rule."""
        suffix = 'in' if direction == 'ingress' else 'out'
        epg_name = '%s-%s' % (self._useg_epg_name(label_id), suffix)

        epg = aim_resource.EndpointGroup(
            tenant_name=tenant_name,
            app_profile_name=app_profile_name,
            name=epg_name,
            policy_enforcement_pref='unenforced')
        if not self.aim.get(aim_ctx, epg):
            self.aim.create(aim_ctx, epg)

        criteria = aim_resource.EndpointGroupCriteria(
            tenant_name=tenant_name,
            app_profile_name=app_profile_name,
            epg_name=epg_name)
        if not self.aim.get(aim_ctx, criteria):
            self.aim.create(aim_ctx, criteria)

        ip_attr = aim_resource.EndpointGroupIpAttr(
            tenant_name=tenant_name,
            app_profile_name=app_profile_name,
            epg_name=epg_name,
            name='cidr-match',
            ip=cidr)
        if not self.aim.get(aim_ctx, ip_attr):
            self.aim.create(aim_ctx, ip_attr)

        return epg_name

    def _delete_useg_epg_for_rule(self, aim_ctx, tenant_name,
                                  app_profile_name, label_id, direction):
        suffix = 'in' if direction == 'ingress' else 'out'
        epg_name = '%s-%s' % (self._useg_epg_name(label_id), suffix)

        ip_attrs = self.aim.find(
            aim_ctx, aim_resource.EndpointGroupIpAttr,
            tenant_name=tenant_name,
            app_profile_name=app_profile_name,
            epg_name=epg_name)
        for attr in ip_attrs:
            self.aim.delete(aim_ctx, attr)

        criteria = aim_resource.EndpointGroupCriteria(
            tenant_name=tenant_name,
            app_profile_name=app_profile_name,
            epg_name=epg_name)
        if self.aim.get(aim_ctx, criteria):
            self.aim.delete(aim_ctx, criteria)

        epg = aim_resource.EndpointGroup(
            tenant_name=tenant_name,
            app_profile_name=app_profile_name,
            name=epg_name)
        if self.aim.get(aim_ctx, epg):
            self.aim.delete(aim_ctx, epg)

    def add_metering_label(self, context, routers):
        aim_ctx = self._get_aim_context()
        for router in routers:
            project_id = router['tenant_id']
            tenant_name = self._get_tenant_name(project_id)
            app_profile_name = self._get_app_profile_name(project_id)
            for label in router.get('_metering_labels', []):
                for rule in label.get('rules', []):
                    cidr = rule.get('remote_ip_prefix')
                    if cidr:
                        self._create_useg_epg_for_rule(
                            aim_ctx, tenant_name, app_profile_name,
                            label['id'], cidr,
                            rule.get('direction', 'ingress'))

    def remove_metering_label(self, context, routers):
        aim_ctx = self._get_aim_context()
        for router in routers:
            project_id = router['tenant_id']
            tenant_name = self._get_tenant_name(project_id)
            app_profile_name = self._get_app_profile_name(project_id)
            for label in router.get('_metering_labels', []):
                for rule in label.get('rules', []):
                    self._delete_useg_epg_for_rule(
                        aim_ctx, tenant_name, app_profile_name,
                        label['id'],
                        rule.get('direction', 'ingress'))

    def update_metering_label_rules(self, context, routers):
        self.remove_metering_label(context, routers)
        self.add_metering_label(context, routers)

    def add_metering_label_rule(self, context, routers):
        self.update_metering_label_rules(context, routers)

    def remove_metering_label_rule(self, context, routers):
        self.update_metering_label_rules(context, routers)

    def get_traffic_counters(self, context, routers):
        """Read traffic counters from APIC hardware stats.

        Returns counters in the standard Neutron metering format:
        {label_id: {'pkts': N, 'bytes': N}}
        """
        counters = {}
        aim_ctx = self._get_aim_context()
        for router in routers:
            project_id = router['tenant_id']
            tenant_name = self._get_tenant_name(project_id)
            app_profile_name = self._get_app_profile_name(project_id)
            for label in router.get('_metering_labels', []):
                label_id = label['id']
                pkts = 0
                bytes_ = 0
                for suffix in ('in', 'out'):
                    epg_name = '%s-%s' % (
                        self._useg_epg_name(label_id), suffix)
                    epg = aim_resource.EndpointGroup(
                        tenant_name=tenant_name,
                        app_profile_name=app_profile_name,
                        name=epg_name)
                    if self.aim.get(aim_ctx, epg):
                        stats = self._query_epg_stats(
                            tenant_name, app_profile_name, epg_name)
                        pkts += stats.get('pkts', 0)
                        bytes_ += stats.get('bytes', 0)
                counters[label_id] = {
                    'pkts': pkts,
                    'bytes': bytes_,
                    'time': int(time.time()),
                }
        return counters

    def _query_epg_stats(self, tenant_name, app_profile_name, epg_name):
        """Query APIC REST API for per-EPG traffic statistics.

        APIC path: /api/mo/uni/tn-{tn}/ap-{ap}/epg-{epg}.json?
                    rsp-subtree-include=stats&rsp-subtree-class=
                    fvCEp,l2IngrBytesAgCum,l2EgrBytesAgCum
        """
        try:
            apic_client = self.aim_mech.aim.get_apic_client()
            dn = 'uni/tn-%s/ap-%s/epg-%s' % (
                tenant_name, app_profile_name, epg_name)
            stats = apic_client.get_mo(
                dn, rsp_subtree_include='stats',
                rsp_subtree_class='l2IngrBytesAgCum,l2EgrBytesAgCum')
            pkts = 0
            bytes_ = 0
            if stats:
                for child in stats.get('imdata', []):
                    for cls_data in child.values():
                        attrs = cls_data.get('attributes', {})
                        bytes_ += int(attrs.get('bytesRate', 0))
                        pkts += int(attrs.get('pktsRate', 0))
            return {'pkts': pkts, 'bytes': bytes_}
        except Exception:
            LOG.debug('Failed to query APIC stats for EPG %s/%s/%s',
                      tenant_name, app_profile_name, epg_name)
            return {'pkts': 0, 'bytes': 0}

    def remove_router(self, context, router_id):
        pass

    def sync_router_namespaces(self, context, routers):
        pass

    def update_routers(self, context, routers):
        pass
