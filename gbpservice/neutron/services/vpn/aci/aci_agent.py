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

import sys

from neutron.common import config as common_config
from neutron_vpnaas.services.vpn import agent as vpn_agent
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import service

LOG = logging.getLogger(__name__)


def main():
    """Entry point for the ACI standalone VPN agent.

    Adapted from neutron-ovn-vpn-agent. Runs on network nodes,
    manages qvpn-{router_id} namespaces with strongswan.
    """
    common_config.register_common_config_options()
    common_config.init(sys.argv[1:])
    cfg.CONF(project='neutron')
    common_config.setup_logging()

    agent = vpn_agent.VPNAgent(cfg.CONF.host)
    launcher = service.launch(cfg.CONF, agent, restart_method='mutate')
    launcher.wait()


if __name__ == '__main__':
    main()
