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

from aim import aim_manager
from aim.api import resource as aim_resource
from aim import context as aim_context
from neutron_lib import context as n_context
from neutron_lib.plugins import directory
from neutron_taas.services.taas import service_drivers as taas_base
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class AimTaasServiceDriver(taas_base.TaasBaseDriver):
    """TaaS driver using ERSPAN via AIM SpanRenderer.

    tap_service -> SpanVdestGroup with ERSPAN destination IP
    tap_flow -> SpanVsource with source port + direction

    Full pipeline: AIM -> APIC -> OpFlex -> SpanRenderer -> OVS OVSDB mirror.
    Analyzer VM receives GRE-encapsulated (ERSPAN) packets.
    """

    def __init__(self, service_plugin):
        super(AimTaasServiceDriver, self).__init__(service_plugin)
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

    def _get_aim_context(self, context):
        if hasattr(context, 'session'):
            return aim_context.AimContext(db_session=context.session)
        admin_ctx = n_context.get_admin_context()
        return aim_context.AimContext(db_session=admin_ctx.session)

    def _source_group_name(self, tap_flow_id):
        return 'taas-src-%s' % tap_flow_id[:8]

    def _dest_group_name(self, tap_service_id):
        return 'taas-dst-%s' % tap_service_id[:8]

    def _get_port_ip(self, context, port_id):
        plugin = directory.get_plugin()
        port = plugin.get_port(n_context.get_admin_context(), port_id)
        for fixed_ip in port.get('fixed_ips', []):
            return fixed_ip.get('ip_address')
        return None

    def _get_port_cep_dn(self, context, port_id):
        """Get the concrete endpoint DN for a port from opflex binding."""
        try:
            return self.aim_mech._get_cep_dn_for_port(
                n_context.get_admin_context(), port_id)
        except Exception:
            LOG.warning('Could not resolve CEP DN for port %s', port_id)
            return None

    def _direction_map(self, direction):
        mapping = {'IN': 'in', 'OUT': 'out', 'BOTH': 'both'}
        return mapping.get(direction, 'both')

    def create_tap_service_precommit(self, context):
        pass

    def create_tap_service_postcommit(self, context):
        tap_service = context.tap_service
        aim_ctx = self._get_aim_context(context._plugin_context)
        dest_ip = self._get_port_ip(
            context._plugin_context, tap_service['port_id'])
        if not dest_ip:
            LOG.error('Cannot create TaaS: tap_service port %s has no IP',
                      tap_service['port_id'])
            return

        dest_group_name = self._dest_group_name(tap_service['id'])

        dest_group = aim_resource.SpanVdestGroup(name=dest_group_name)
        if not self.aim.get(aim_ctx, dest_group):
            self.aim.create(aim_ctx, dest_group)

        dest = aim_resource.SpanVdest(
            vdg_name=dest_group_name, name=dest_group_name)
        if not self.aim.get(aim_ctx, dest):
            self.aim.create(aim_ctx, dest)

        summary = aim_resource.SpanVepgSummary(
            vdg_name=dest_group_name,
            vd_name=dest_group_name,
            dst_ip=dest_ip,
            flow_id=1)
        if not self.aim.get(aim_ctx, summary):
            self.aim.create(aim_ctx, summary)

    def delete_tap_service_precommit(self, context):
        pass

    def delete_tap_service_postcommit(self, context):
        tap_service = context.tap_service
        aim_ctx = self._get_aim_context(context._plugin_context)
        dest_group_name = self._dest_group_name(tap_service['id'])

        summary = aim_resource.SpanVepgSummary(
            vdg_name=dest_group_name, vd_name=dest_group_name)
        if self.aim.get(aim_ctx, summary):
            self.aim.delete(aim_ctx, summary)

        dest = aim_resource.SpanVdest(
            vdg_name=dest_group_name, name=dest_group_name)
        if self.aim.get(aim_ctx, dest):
            self.aim.delete(aim_ctx, dest)

        dest_group = aim_resource.SpanVdestGroup(name=dest_group_name)
        if self.aim.get(aim_ctx, dest_group):
            self.aim.delete(aim_ctx, dest_group)

    def create_tap_flow_precommit(self, context):
        pass

    def create_tap_flow_postcommit(self, context):
        tap_flow = context.tap_flow
        aim_ctx = self._get_aim_context(context._plugin_context)

        source_port_id = tap_flow['source_port']
        tap_service_id = tap_flow['tap_service_id']
        direction = self._direction_map(tap_flow.get('direction', 'BOTH'))

        cep_dn = self._get_port_cep_dn(
            context._plugin_context, source_port_id)
        src_paths = [cep_dn] if cep_dn else []

        source_group_name = self._source_group_name(tap_flow['id'])
        dest_group_name = self._dest_group_name(tap_service_id)

        source_group = aim_resource.SpanVsourceGroup(
            name=source_group_name, admin_st='start')
        if not self.aim.get(aim_ctx, source_group):
            self.aim.create(aim_ctx, source_group)

        source = aim_resource.SpanVsource(
            vsg_name=source_group_name,
            name=source_group_name,
            dir=direction,
            src_paths=src_paths)
        if not self.aim.get(aim_ctx, source):
            self.aim.create(aim_ctx, source)

        label = aim_resource.SpanSpanlbl(
            vsg_name=source_group_name,
            name=dest_group_name,
            tag='yellow-green')
        if not self.aim.get(aim_ctx, label):
            self.aim.create(aim_ctx, label)

        acc_name = self.aim_mech._get_acc_bundle_for_host(
            aim_ctx,
            self._get_port_host(context._plugin_context, source_port_id))
        if acc_name:
            curr_bundle = self.aim.get(
                aim_ctx,
                aim_resource.InfraAccBundleGroup(name=acc_name))
            if curr_bundle:
                src_groups = list(
                    set(curr_bundle.span_vsource_group_names or []) |
                    {source_group_name})
                dst_groups = list(
                    set(curr_bundle.span_vdest_group_names or []) |
                    {dest_group_name})
                self.aim.update(
                    aim_ctx, curr_bundle,
                    span_vsource_group_names=src_groups,
                    span_vdest_group_names=dst_groups)

    def delete_tap_flow_precommit(self, context):
        pass

    def delete_tap_flow_postcommit(self, context):
        tap_flow = context.tap_flow
        aim_ctx = self._get_aim_context(context._plugin_context)

        source_group_name = self._source_group_name(tap_flow['id'])
        dest_group_name = self._dest_group_name(tap_flow['tap_service_id'])

        label = aim_resource.SpanSpanlbl(
            vsg_name=source_group_name, name=dest_group_name)
        if self.aim.get(aim_ctx, label):
            self.aim.delete(aim_ctx, label)

        source = aim_resource.SpanVsource(
            vsg_name=source_group_name, name=source_group_name)
        if self.aim.get(aim_ctx, source):
            self.aim.delete(aim_ctx, source)

        source_group = aim_resource.SpanVsourceGroup(
            name=source_group_name)
        if self.aim.get(aim_ctx, source_group):
            self.aim.delete(aim_ctx, source_group)

    def _get_port_host(self, context, port_id):
        plugin = directory.get_plugin()
        port = plugin.get_port(n_context.get_admin_context(), port_id)
        return port.get('binding:host_id', '')

    def create_tap_mirror_precommit(self, context):
        pass

    def create_tap_mirror_postcommit(self, context):
        pass

    def delete_tap_mirror_precommit(self, context):
        pass

    def delete_tap_mirror_postcommit(self, context):
        pass
