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
from neutron_fwaas.services.firewall.service_drivers import driver_api
from neutron_lib import context as n_context
from neutron_lib.plugins import directory
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class AciUsegFwaasDriver(driver_api.FirewallDriverDBMixin):
    """FWaaS v2 driver enforcing rules in ACI fabric via uSeg EPGs.

    Firewall rules with IP address fields are mapped to uSeg EPGs
    (microsegmentation) so that traffic classification happens at
    the ACI leaf hardware. Protocol/port filtering uses standard
    ACI Contracts with FilterEntry objects.

    Rules without IP fields use standard Contracts between existing
    network EPGs.

    Limitation: REJECT action is silently downgraded to DENY since
    ACI contracts only support allow/deny.
    """

    def __init__(self, service_plugin=None):
        super(AciUsegFwaasDriver, self).__init__(service_plugin)
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
        return aim_context.AimContext(db_session=context.session)

    def _useg_epg_name(self, rule_id, direction):
        return 'fw-%s-%s' % (direction, rule_id[:8])

    def _contract_name(self, rule_id):
        return 'fw-rule-%s' % rule_id[:8]

    def _filter_name(self, rule_id):
        return 'fw-flt-%s' % rule_id[:8]

    def _get_tenant_name(self, project_id):
        return self.aim_mech.name_mapper.project(None, project_id)

    def _get_app_profile_name(self, project_id):
        return self.aim_mech.get_aim_app_profile_name(project_id)

    def _map_protocol(self, protocol):
        if protocol is None:
            return None
        proto_map = {
            'tcp': 'tcp', 'udp': 'udp', 'icmp': 'icmp',
            'icmpv6': 'icmpv6', '6': 'tcp', '17': 'udp',
            '1': 'icmp', '58': 'icmpv6',
        }
        return proto_map.get(str(protocol).lower(), str(protocol))

    def _create_useg_epg(self, aim_ctx, tenant_name, app_profile_name,
                         epg_name, ip_cidr):
        """Create a uSeg EPG with IP criteria for traffic classification."""
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
            name='ip-match',
            ip=ip_cidr)
        if not self.aim.get(aim_ctx, ip_attr):
            self.aim.create(aim_ctx, ip_attr)

        return epg

    def _delete_useg_epg(self, aim_ctx, tenant_name, app_profile_name,
                         epg_name):
        """Delete a uSeg EPG and its criteria."""
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

    def _create_contract(self, aim_ctx, tenant_name, contract_name,
                         filter_name, rule):
        """Create Contract + Filter + FilterEntry for a firewall rule."""
        filt = aim_resource.Filter(
            tenant_name=tenant_name, name=filter_name)
        if not self.aim.get(aim_ctx, filt):
            self.aim.create(aim_ctx, filt)

        entry_kwargs = {
            'tenant_name': tenant_name,
            'filter_name': filter_name,
            'name': 'entry',
        }
        proto = self._map_protocol(rule.get('protocol'))
        if proto:
            entry_kwargs['ip_protocol'] = proto
        src_port = rule.get('source_port')
        if src_port:
            entry_kwargs['s_from_port'] = str(src_port)
            entry_kwargs['s_to_port'] = str(src_port)
        dst_port = rule.get('destination_port')
        if dst_port:
            entry_kwargs['d_from_port'] = str(dst_port)
            entry_kwargs['d_to_port'] = str(dst_port)

        entry = aim_resource.FilterEntry(**entry_kwargs)
        if not self.aim.get(aim_ctx, entry):
            self.aim.create(aim_ctx, entry)

        contract = aim_resource.Contract(
            tenant_name=tenant_name, name=contract_name)
        if not self.aim.get(aim_ctx, contract):
            self.aim.create(aim_ctx, contract)

        subject = aim_resource.ContractSubject(
            tenant_name=tenant_name,
            contract_name=contract_name,
            name='subject',
            bi_filters=[filter_name])
        if not self.aim.get(aim_ctx, subject):
            self.aim.create(aim_ctx, subject)

        return contract

    def _delete_contract(self, aim_ctx, tenant_name, contract_name,
                         filter_name):
        """Delete Contract, Subject, Filter, and FilterEntry."""
        subject = aim_resource.ContractSubject(
            tenant_name=tenant_name,
            contract_name=contract_name,
            name='subject')
        if self.aim.get(aim_ctx, subject):
            self.aim.delete(aim_ctx, subject)

        contract = aim_resource.Contract(
            tenant_name=tenant_name, name=contract_name)
        if self.aim.get(aim_ctx, contract):
            self.aim.delete(aim_ctx, contract)

        entries = self.aim.find(
            aim_ctx, aim_resource.FilterEntry,
            tenant_name=tenant_name, filter_name=filter_name)
        for entry in entries:
            self.aim.delete(aim_ctx, entry)

        filt = aim_resource.Filter(
            tenant_name=tenant_name, name=filter_name)
        if self.aim.get(aim_ctx, filt):
            self.aim.delete(aim_ctx, filt)

    def _apply_rule(self, aim_ctx, tenant_name, app_profile_name, rule):
        """Map a single FWaaS rule to ACI uSeg EPGs + Contract."""
        rule_id = rule['id']
        action = rule.get('action', 'deny')
        src_ip = rule.get('source_ip_address')
        dst_ip = rule.get('destination_ip_address')

        if action == 'reject':
            action = 'deny'

        if action == 'deny':
            return

        contract_name = self._contract_name(rule_id)
        filter_name = self._filter_name(rule_id)
        self._create_contract(aim_ctx, tenant_name, contract_name,
                              filter_name, rule)

        if src_ip:
            src_epg_name = self._useg_epg_name(rule_id, 'src')
            src_epg = self._create_useg_epg(
                aim_ctx, tenant_name, app_profile_name, src_epg_name, src_ip)
            self.aim.update(
                aim_ctx, src_epg,
                provided_contract_names=(
                    list(set(src_epg.provided_contract_names or []) |
                         {contract_name})))

        if dst_ip:
            dst_epg_name = self._useg_epg_name(rule_id, 'dst')
            dst_epg = self._create_useg_epg(
                aim_ctx, tenant_name, app_profile_name, dst_epg_name, dst_ip)
            self.aim.update(
                aim_ctx, dst_epg,
                consumed_contract_names=(
                    list(set(dst_epg.consumed_contract_names or []) |
                         {contract_name})))

    def _remove_rule(self, aim_ctx, tenant_name, app_profile_name, rule_id):
        """Remove ACI objects for a firewall rule."""
        contract_name = self._contract_name(rule_id)
        filter_name = self._filter_name(rule_id)
        self._delete_contract(aim_ctx, tenant_name, contract_name,
                              filter_name)

        for direction in ('src', 'dst'):
            epg_name = self._useg_epg_name(rule_id, direction)
            self._delete_useg_epg(aim_ctx, tenant_name, app_profile_name,
                                  epg_name)

    def create_firewall_group_precommit(self, context, firewall_group):
        pass

    def create_firewall_group_postcommit(self, context, firewall_group):
        project_id = firewall_group['tenant_id']
        tenant_name = self._get_tenant_name(project_id)
        app_profile_name = self._get_app_profile_name(project_id)
        aim_ctx = self._get_aim_context(context)

        for policy_id in (firewall_group.get('ingress_firewall_policy_id'),
                          firewall_group.get('egress_firewall_policy_id')):
            if not policy_id:
                continue
            policy = self._get_firewall_policy(context, policy_id)
            if not policy:
                continue
            for rule_id in (policy.get('firewall_rules') or []):
                rule = self._get_firewall_rule(context, rule_id)
                if rule and rule.get('enabled', True):
                    self._apply_rule(aim_ctx, tenant_name,
                                     app_profile_name, rule)

    def update_firewall_group_precommit(self, context, old_firewall_group,
                                        new_firewall_group):
        pass

    def update_firewall_group_postcommit(self, context, old_firewall_group,
                                         new_firewall_group):
        self.delete_firewall_group_postcommit(context, old_firewall_group)
        self.create_firewall_group_postcommit(context, new_firewall_group)

    def delete_firewall_group_precommit(self, context, firewall_group):
        pass

    def delete_firewall_group_postcommit(self, context, firewall_group):
        project_id = firewall_group['tenant_id']
        tenant_name = self._get_tenant_name(project_id)
        app_profile_name = self._get_app_profile_name(project_id)
        aim_ctx = self._get_aim_context(context)

        for policy_id in (firewall_group.get('ingress_firewall_policy_id'),
                          firewall_group.get('egress_firewall_policy_id')):
            if not policy_id:
                continue
            policy = self._get_firewall_policy(context, policy_id)
            if not policy:
                continue
            for rule_id in (policy.get('firewall_rules') or []):
                self._remove_rule(aim_ctx, tenant_name,
                                  app_profile_name, rule_id)

    def update_firewall_policy_postcommit(self, context, old_firewall_policy,
                                          new_firewall_policy):
        admin_ctx = n_context.get_admin_context()
        groups = self._get_firewall_groups_for_policy(
            admin_ctx, new_firewall_policy['id'])
        for group in groups:
            self.delete_firewall_group_postcommit(context, group)
            self.create_firewall_group_postcommit(context, group)

    def update_firewall_rule_postcommit(self, context, old_firewall_rule,
                                        new_firewall_rule):
        admin_ctx = n_context.get_admin_context()
        policies = self._get_policies_with_rule(
            admin_ctx, new_firewall_rule['id'])
        for policy in policies:
            groups = self._get_firewall_groups_for_policy(
                admin_ctx, policy['id'])
            for group in groups:
                self.delete_firewall_group_postcommit(context, group)
                self.create_firewall_group_postcommit(context, group)

    def _get_firewall_policy(self, context, policy_id):
        try:
            fw_plugin = directory.get_plugin('FIREWALL_V2')
            return fw_plugin.get_firewall_policy(
                n_context.get_admin_context(), policy_id)
        except Exception:
            LOG.warning('Failed to get firewall policy %s', policy_id)
            return None

    def _get_firewall_rule(self, context, rule_id):
        try:
            fw_plugin = directory.get_plugin('FIREWALL_V2')
            return fw_plugin.get_firewall_rule(
                n_context.get_admin_context(), rule_id)
        except Exception:
            LOG.warning('Failed to get firewall rule %s', rule_id)
            return None

    def _get_firewall_groups_for_policy(self, context, policy_id):
        try:
            fw_plugin = directory.get_plugin('FIREWALL_V2')
            return fw_plugin.get_firewall_groups(
                context,
                filters={'ingress_firewall_policy_id': [policy_id],
                         'egress_firewall_policy_id': [policy_id]})
        except Exception:
            return []

    def _get_policies_with_rule(self, context, rule_id):
        try:
            fw_plugin = directory.get_plugin('FIREWALL_V2')
            policies = fw_plugin.get_firewall_policies(context)
            return [p for p in policies
                    if rule_id in (p.get('firewall_rules') or [])]
        except Exception:
            return []

    def is_supported_l2_firewall_group(self, context, firewall_group):
        return False

    def create_firewall_policy_precommit(self, context, firewall_policy):
        pass

    def create_firewall_policy_postcommit(self, context, firewall_policy):
        pass

    def create_firewall_rule_precommit(self, context, firewall_rule):
        pass

    def create_firewall_rule_postcommit(self, context, firewall_rule):
        pass

    def delete_firewall_policy_precommit(self, context, firewall_policy):
        pass

    def delete_firewall_policy_postcommit(self, context, firewall_policy):
        pass

    def delete_firewall_rule_precommit(self, context, firewall_rule):
        pass

    def delete_firewall_rule_postcommit(self, context, firewall_rule):
        pass

    def insert_rule_precommit(self, context, policy_id, rule_info):
        pass

    def insert_rule_postcommit(self, context, policy_id, rule_info):
        pass

    def remove_rule_precommit(self, context, policy_id, rule_info):
        pass

    def remove_rule_postcommit(self, context, policy_id, rule_info):
        pass

    def update_firewall_policy_precommit(self, context, old_firewall_policy,
                                         new_firewall_policy):
        pass

    def update_firewall_rule_precommit(self, context, old_firewall_rule,
                                       new_firewall_rule):
        pass
