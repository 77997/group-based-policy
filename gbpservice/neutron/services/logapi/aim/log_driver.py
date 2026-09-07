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

from neutron.services.logapi.common import exceptions as log_exc
from neutron.services.logapi.drivers import base as log_base
from neutron_lib.plugins import directory
from oslo_log import log as logging
from oslo_utils import importutils

from aim import aim_manager
from aim import context as aim_context
from aim.api import resource as aim_resource

LOG = logging.getLogger(__name__)

DRIVER = None

SUPPORTED_LOGGING_TYPES = ('security_group',)

EVENT_ACCEPT = 'ACCEPT'
EVENT_DROP = 'DROP'
EVENT_ALL = 'ALL'

# hostprotRule.action is a bitmask over log/permit/deny (APIC MIM 5.0(1)).
# A Neutron security group is an allow-list: every rule it renders is a
# permit, so "log this rule" is the two-bit value below, not a bare "log".
# Leaving a rule at plain 'permit' is what the fabric defaults to, which is
# why clearing logging restores that exact string rather than an empty value.
ACTION_LOG = 'log,permit'
ACTION_PLAIN = 'permit'

SG_SUBJECT = 'default'


class AciPacketLogDriver(log_base.DriverBase):
    """Packet logging driver for ACI security groups.

    Sets hostprotRule.action on the AIM SecurityGroupRule objects backing a
    Neutron security group. APIC renders that into a gbp:LogAction on the
    rule, the OpFlex agent resolves it into PolicyRule::log, and
    AccessFlowManager turns it into permitLog on the compute. Nothing is
    written to disk and nothing is pushed to the agent out of band: the flag
    travels the same path as the security group itself.

    Event mapping. Neutron offers ACCEPT, DROP and ALL. Only the permit bit
    has a per-rule representation here, because every rule of an allow-list
    is a permit and the drops are the group's implicit default-deny, which
    the fabric expresses globally rather than per rule. ACCEPT and ALL are
    therefore accepted; DROP alone is refused rather than silently recorded
    and never rendered.
    """

    SUPPORTED_LOGGING_TYPES = SUPPORTED_LOGGING_TYPES

    def __init__(self):
        super(AciPacketLogDriver, self).__init__(
            name='aci',
            vif_types=[],
            vnic_types=[],
            supported_logging_types=SUPPORTED_LOGGING_TYPES,
            requires_rpc=False)
        self.aim = aim_manager.AimManager()

    @staticmethod
    def create():
        return AciPacketLogDriver()

    @property
    def is_loaded(self):
        return True

    def is_vif_type_compatible(self, vif_type):
        return True

    # -- helpers ---------------------------------------------------------

    @property
    def _md(self):
        plugin = directory.get_plugin()
        return plugin.mechanism_manager.mech_drivers['apic_aim'].obj

    def _tenant_aname(self, session, sg_id):
        """Map a security group to its AIM tenant name.

        Uses the mechanism driver's own helper so the answer matches what
        created the AIM objects: the tenant_id carried on a rule dict is
        not reliable, which is why apic_aim looks it up from the group.
        """
        md = self._md
        tenant_id = md._get_sg_rule_tenant_id(session, {'security_group_id':
                                                        sg_id})
        return md.name_mapper.project(session, tenant_id)

    def _sg_rule_ids(self, context, sg_id):
        plugin = directory.get_plugin()
        sg = plugin.get_security_group(context, sg_id)
        return [r['id'] for r in sg.get('security_group_rules', [])]

    def _set_action(self, context, sg_id, action):
        """Stamp every AIM rule of this security group with `action`."""
        session = context.session
        aim_ctx = aim_context.AimContext(session)
        tenant_aname = self._tenant_aname(session, sg_id)
        for rule_id in self._sg_rule_ids(context, sg_id):
            sg_rule_aim = aim_resource.SecurityGroupRule(
                tenant_name=tenant_aname,
                security_group_name=sg_id,
                security_group_subject_name=SG_SUBJECT,
                name=rule_id)
            self.aim.update(aim_ctx, sg_rule_aim, action=action)
        LOG.info("Set hostprotRule action=%(action)s on security group "
                 "%(sg)s", {'action': action, 'sg': sg_id})

    @staticmethod
    def _validate_event(log_obj):
        event = (log_obj.get('event', EVENT_ALL) or EVENT_ALL).upper()
        if event == EVENT_DROP:
            raise log_exc.LogapiDriverException(
                exception_msg=(
                    "event=DROP is not supported for ACI security group "
                    "logging. hostprotRule.action carries the log bit on a "
                    "permit rule, and a security group's drops are its "
                    "implicit default-deny, which the fabric does not "
                    "express per rule. Use ACCEPT or ALL."))
        return event

    def _is_logged(self, context, sg_id, skip_log_id=None):
        """Is any other enabled log resource still covering this group?"""
        log_plugin = directory.get_plugin('log')
        if not log_plugin:
            return False
        for log_res in log_plugin.get_logs(context):
            if skip_log_id and log_res.get('id', None) == skip_log_id:
                continue
            if not log_res.get('enabled', True):
                continue
            if log_res.get('resource_id', None) == sg_id:
                return True
        return False

    # -- precommit hooks -------------------------------------------------
    #
    # NOTE: the AIM writes happen here, not in the postcommit hooks. The
    # logging plugin calls the precommit hooks inside
    # db_api.CONTEXT_WRITER.using(context) and the postcommit hooks after it
    # has closed, so an aim.update() issued from a postcommit hook runs on a
    # session with no enclosing writer transaction and is discarded - the API
    # returns 201 and the fabric never changes. Every apic_aim hook writes AIM
    # from _precommit for the same reason. Failing here also aborts the log
    # resource itself, which is the behaviour we want: no record of logging
    # that was never applied.

    def create_log_precommit(self, context, log_obj):
        self._validate_event(log_obj)
        sg_id = log_obj.get('resource_id', None)
        if not sg_id:
            # A log with no resource_id covers every group the project owns.
            # There is no bounded set of AIM rules to stamp for that, so
            # refuse it rather than accept it and change nothing.
            raise log_exc.ResourceIdNotSpecified(
                resource_type='security_group')
        action = (ACTION_LOG if log_obj.get('enabled', True)
                  else ACTION_PLAIN)
        self._set_action(context, sg_id, action)

    def update_log_precommit(self, context, log_obj):
        self._validate_event(log_obj)
        sg_id = log_obj.get('resource_id', None)
        if not sg_id:
            return
        if log_obj.get('enabled', True):
            action = ACTION_LOG
        else:
            # Only clear if nothing else still logs this group.
            action = (ACTION_LOG
                      if self._is_logged(context, sg_id,
                                         skip_log_id=log_obj.get('id', None))
                      else ACTION_PLAIN)
        self._set_action(context, sg_id, action)

    def delete_log_precommit(self, context, log_obj):
        sg_id = log_obj.get('resource_id', None)
        if not sg_id:
            return
        if self._is_logged(context, sg_id,
                           skip_log_id=log_obj.get('id', None)):
            return
        self._set_action(context, sg_id, ACTION_PLAIN)

    # -- postcommit hooks ------------------------------------------------
    #
    # Nothing to do: the flag reaches the compute over OpFlex with the policy
    # itself, so there is no agent to notify once the transaction lands.

    def create_log(self, context, log_obj):
        pass

    def update_log(self, context, log_obj):
        pass

    def delete_log(self, context, log_obj):
        pass


def action_for_security_group(context, sg_id):
    """The hostprotRule action a rule of this group should be created with.

    Called by the apic_aim mechanism driver when it materialises a
    SecurityGroupRule, so a rule added to an already-logged group renders
    logged instead of silently staying at the fabric default while its
    siblings are logged. Returns None when the logging service plugin is
    not loaded at all, so callers can omit the attribute entirely and leave
    AIM's own default in place.
    """
    log_plugin = directory.get_plugin('log')
    if not log_plugin:
        return None
    try:
        logs = log_plugin.get_logs(context)
    except Exception:
        # Never let a logging lookup break security group creation.
        LOG.exception("Failed to read log resources while creating a "
                      "security group rule for %s", sg_id)
        return None
    for log_res in logs:
        if not log_res.get('enabled', True):
            continue
        if log_res.get('resource_id', None) == sg_id:
            return ACTION_LOG
    return ACTION_PLAIN


def register():
    """Register the ACI packet logging driver.

    Neutron's logging plugin discovers drivers by publishing
    LOGGING_PLUGIN/AFTER_INIT and letting existing DriverBase instances
    self-register, so a driver nobody constructs never joins the manager and
    every security_group log request is refused for lack of a supported type.
    Upstream constructs its OVS equivalent from mech_openvswitch for the same
    reason.

    Importing sg_validate is what registers the security_group request
    validator: validators.ResourceValidateRequest.register is applied as a
    decorator at module scope, so without the import the logging plugin raises
    KeyError('security_group') out of validate_request and every create
    returns a 500.

    Deliberately NOT registered: sg_callback.SecurityGroupRuleCallBack, which
    upstream wires up here. Its handle_event calls resource_push_api, which
    routes through LoggingServiceDriverManager.call to a driver method named
    resource_update. This driver is requires_rpc=False and has no such method,
    so registering it would raise DriverCallError on every security group rule
    change. Nothing is lost: the flag reaches the compute over OpFlex with the
    policy itself, and apic_aim stamps late-added rules via
    action_for_security_group.
    """
    global DRIVER
    if not DRIVER:
        DRIVER = AciPacketLogDriver.create()
    importutils.import_module(
        'neutron.services.logapi.common.sg_validate')
    LOG.debug('ACI packet logging driver registered')
