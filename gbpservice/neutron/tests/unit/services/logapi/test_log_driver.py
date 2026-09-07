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

from unittest import mock

from neutron.services.logapi.common import exceptions as log_exc
from oslotest import base as test_base

from gbpservice.neutron.services.logapi.aim import log_driver


class FakeLog(dict):
    """Stands in for a Log versioned object.

    The real object is a NeutronDbObject, which mixes in
    VersionedObjectDictCompat and so answers .get() - but only returns the
    supplied default when the field is unset. A plain dict has the same
    surface for what the driver reads.
    """


class TestAciPacketLogDriver(test_base.BaseTestCase):

    def setUp(self):
        super(TestAciPacketLogDriver, self).setUp()
        with mock.patch.object(log_driver.aim_manager, 'AimManager'):
            self.driver = log_driver.AciPacketLogDriver()
        self.driver.aim = mock.Mock()
        # AimContext registers a SQLAlchemy before_flush listener on the
        # session it is handed, which a mock session cannot accept.
        patcher = mock.patch.object(log_driver.aim_context, 'AimContext')
        self.addCleanup(patcher.stop)
        patcher.start()
        self.context = mock.Mock()

    # -- event validation ------------------------------------------------

    def test_accept_event_is_allowed(self):
        self.assertEqual(
            log_driver.EVENT_ACCEPT,
            self.driver._validate_event(FakeLog(event='ACCEPT')))

    def test_all_event_is_allowed(self):
        self.assertEqual(
            log_driver.EVENT_ALL,
            self.driver._validate_event(FakeLog(event='ALL')))

    def test_missing_event_defaults_to_all(self):
        self.assertEqual(
            log_driver.EVENT_ALL,
            self.driver._validate_event(FakeLog()))

    def test_drop_event_is_refused(self):
        # A security group's drops are its implicit default-deny, which the
        # fabric does not express per rule. Refusing is the point: accepting
        # would record a log resource that could never render.
        self.assertRaises(
            log_exc.LogapiDriverException,
            self.driver._validate_event, FakeLog(event='DROP'))

    def test_create_log_precommit_refuses_drop(self):
        self.assertRaises(
            log_exc.LogapiDriverException,
            self.driver.create_log_precommit,
            self.context, FakeLog(event='DROP'))

    # -- action stamping -------------------------------------------------

    def _stub_group(self, rule_ids):
        self.driver._tenant_aname = mock.Mock(return_value='prj_t0')
        self.driver._sg_rule_ids = mock.Mock(return_value=rule_ids)

    def test_set_action_stamps_every_rule(self):
        self._stub_group(['r1', 'r2', 'r3'])
        self.driver._set_action(self.context, 'sg1', log_driver.ACTION_LOG)

        self.assertEqual(3, self.driver.aim.update.call_count)
        for call in self.driver.aim.update.call_args_list:
            self.assertEqual(log_driver.ACTION_LOG, call.kwargs['action'])
        names = [c.args[1].name for c in self.driver.aim.update.call_args_list]
        self.assertEqual(['r1', 'r2', 'r3'], names)

    def test_set_action_addresses_the_right_aim_object(self):
        self._stub_group(['r1'])
        self.driver._set_action(self.context, 'sg1', log_driver.ACTION_LOG)
        aim_obj = self.driver.aim.update.call_args.args[1]
        self.assertEqual('prj_t0', aim_obj.tenant_name)
        self.assertEqual('sg1', aim_obj.security_group_name)
        self.assertEqual('default', aim_obj.security_group_subject_name)
        self.assertEqual('r1', aim_obj.name)

    def test_log_action_carries_the_permit_bit(self):
        # hostprotRule.action is a bitmask; a security group rule is a
        # permit, so logging it is "log,permit" and never a bare "log".
        self.assertEqual('log,permit', log_driver.ACTION_LOG)
        self.assertEqual('permit', log_driver.ACTION_PLAIN)

    # -- lifecycle -------------------------------------------------------

    def test_create_log_sets_log_action(self):
        self._stub_group(['r1'])
        self.driver.create_log_precommit(
            self.context, FakeLog(resource_id='sg1'))
        self.assertEqual(log_driver.ACTION_LOG,
                         self.driver.aim.update.call_args.kwargs['action'])

    def test_create_log_without_resource_id_is_refused(self):
        self.assertRaises(
            log_exc.ResourceIdNotSpecified,
            self.driver.create_log_precommit, self.context, FakeLog())

    def test_disabled_log_does_not_set_the_log_bit(self):
        self._stub_group(['r1'])
        self.driver.create_log_precommit(
            self.context, FakeLog(resource_id='sg1', enabled=False))
        self.assertEqual(log_driver.ACTION_PLAIN,
                         self.driver.aim.update.call_args.kwargs['action'])

    def test_delete_log_clears_the_log_bit(self):
        self._stub_group(['r1'])
        self.driver._is_logged = mock.Mock(return_value=False)
        self.driver.delete_log_precommit(
            self.context, FakeLog(resource_id='sg1', id='log1'))
        self.assertEqual(log_driver.ACTION_PLAIN,
                         self.driver.aim.update.call_args.kwargs['action'])

    def test_delete_log_keeps_logging_when_another_log_covers_the_group(self):
        # Two log resources on one group: deleting one must not silently
        # stop logging for the other.
        self._stub_group(['r1'])
        self.driver._is_logged = mock.Mock(return_value=True)
        self.driver.delete_log_precommit(
            self.context, FakeLog(resource_id='sg1', id='log1'))
        self.driver.aim.update.assert_not_called()

    def test_update_log_disable_keeps_logging_if_another_log_remains(self):
        self._stub_group(['r1'])
        self.driver._is_logged = mock.Mock(return_value=True)
        self.driver.update_log_precommit(
            self.context,
            FakeLog(resource_id='sg1', id='log1', enabled=False))
        self.assertEqual(log_driver.ACTION_LOG,
                         self.driver.aim.update.call_args.kwargs['action'])


class TestActionForSecurityGroup(test_base.BaseTestCase):
    """The helper apic_aim calls so late-added rules inherit the flag."""

    def setUp(self):
        super(TestActionForSecurityGroup, self).setUp()
        self.context = mock.Mock()

    def _with_log_plugin(self, logs):
        plugin = mock.Mock()
        plugin.get_logs.return_value = logs
        return mock.patch.object(log_driver.directory, 'get_plugin',
                                 return_value=plugin)

    def test_returns_none_without_the_logging_plugin(self):
        # Nothing should be passed to AIM at all in that case, so AIM's own
        # default stands rather than this path asserting a fabric default.
        with mock.patch.object(log_driver.directory, 'get_plugin',
                               return_value=None):
            self.assertIsNone(
                log_driver.action_for_security_group(self.context, 'sg1'))

    def test_logged_group_yields_the_log_action(self):
        with self._with_log_plugin([FakeLog(resource_id='sg1')]):
            self.assertEqual(
                log_driver.ACTION_LOG,
                log_driver.action_for_security_group(self.context, 'sg1'))

    def test_unlogged_group_yields_plain_permit(self):
        with self._with_log_plugin([FakeLog(resource_id='other')]):
            self.assertEqual(
                log_driver.ACTION_PLAIN,
                log_driver.action_for_security_group(self.context, 'sg1'))

    def test_disabled_log_does_not_count(self):
        with self._with_log_plugin(
                [FakeLog(resource_id='sg1', enabled=False)]):
            self.assertEqual(
                log_driver.ACTION_PLAIN,
                log_driver.action_for_security_group(self.context, 'sg1'))

    def test_lookup_failure_never_breaks_rule_creation(self):
        plugin = mock.Mock()
        plugin.get_logs.side_effect = RuntimeError('boom')
        with mock.patch.object(log_driver.directory, 'get_plugin',
                               return_value=plugin):
            self.assertIsNone(
                log_driver.action_for_security_group(self.context, 'sg1'))


class TestHooksRunInPrecommit(test_base.BaseTestCase):
    """The AIM writes must happen in the precommit hooks.

    The logging plugin runs precommit hooks inside
    db_api.CONTEXT_WRITER.using(context) and postcommit hooks after it has
    closed, so an aim.update() issued from a postcommit hook is discarded and
    the API reports success while the fabric never changes. Pin that here.
    """

    def setUp(self):
        super(TestHooksRunInPrecommit, self).setUp()
        with mock.patch.object(log_driver.aim_manager, 'AimManager'):
            self.driver = log_driver.AciPacketLogDriver()
        self.driver.aim = mock.Mock()
        patcher = mock.patch.object(log_driver.aim_context, 'AimContext')
        self.addCleanup(patcher.stop)
        patcher.start()
        self.driver._tenant_aname = mock.Mock(return_value='prj_t0')
        self.driver._sg_rule_ids = mock.Mock(return_value=['r1'])
        self.context = mock.Mock()

    def test_postcommit_hooks_write_nothing(self):
        for hook in (self.driver.create_log, self.driver.update_log,
                     self.driver.delete_log):
            hook(self.context, FakeLog(resource_id='sg1', id='log1'))
        self.driver.aim.update.assert_not_called()

    def test_precommit_hooks_do_the_write(self):
        self.driver.create_log_precommit(
            self.context, FakeLog(resource_id='sg1'))
        self.driver.aim.update.assert_called()
