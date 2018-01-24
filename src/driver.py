import datetime
import json

from cloudshell.networking.apply_connectivity.apply_connectivity_operation import apply_connectivity_changes
from cloudshell.networking.apply_connectivity.models.connectivity_result import ConnectivitySuccessResponse
from cloudshell.shell.core.interfaces.save_restore import OrchestrationSaveResult, OrchestrationSavedArtifact, \
    OrchestrationSavedArtifactInfo, OrchestrationRestoreRules
from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface
from cloudshell.shell.core.driver_context import InitCommandContext, ResourceCommandContext, AutoLoadResource, \
    AutoLoadAttribute, AutoLoadDetails, CancellationContext
from cloudshell.devices.standards.networking.configuration_attributes_structure import create_networking_resource_from_context
from cloudshell.cli.cli import CLI
from cloudshell.cli.session.ssh_session import SSHSession
from cloudshell.cli.command_mode import CommandMode
from cloudshell.api.cloudshell_api import CloudShellAPISession
import re
from data_model import *
from cloudshell.core.logger.qs_logger import get_qs_logger

class VyosDriver (ResourceDriverInterface):

    def __init__(self):
        """
        ctor must be without arguments, it is created with reflection at run time
        """
        pass

    def initialize(self, context):
        """
        Initialize the driver session, this function is called everytime a new instance of the driver is created
        This is a good place to load and cache the driver configuration, initiate sessions etc.
        :param InitCommandContext context: the context the command runs on
        """
        resource = Vyos.create_from_context(context)

        logger = get_qs_logger(log_category="Test",log_group=context.resource.name)
        logger.info("Opening SSH to " +  context.resource.address)
        logger.info(resource.user + " " +  resource.password + " ")
        self.cli = CLI()
        self.cliMode = CommandMode(r'.*$')
        self.verbose = "False"
        
        self.port = int(resource.cli_tcp_port)
        if self.port == 0:
            self.port = 22
        
        pass

    def enable_verbose_output(self, context, cancellation_context):
        """
        Enables verbose console output and logging.
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :return: the command result text
        :rtype: str
        """
        logger = get_qs_logger(log_category="Test",log_group=context.resource.name)

        self.verbose = "True"
        logger.info("Verbose mode enabled")

        api = CloudShellAPISession(host=context.connectivity.server_address,
                                   token_id=context.connectivity.admin_auth_token,
                                   domain=context.reservation.domain)
        resource = Vyos.create_from_context(context)
        ctpw = api.DecryptPassword(resource.password).Value

        session_types = [SSHSession(host=context.resource.address, username=resource.user, password=ctpw, port=self.port)]

        out = "Verbose mode enabled"

        print out
        return out

    def disable_verbose_output(self, context, cancellation_context):
        """
        Disables verbose console output and logging.
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :return: the command result text
        :rtype: str
        """
        logger = get_qs_logger(log_category="Test",log_group=context.resource.name)

        self.verbose = "False"
        logger.info("Verbose mode disabled")

        api = CloudShellAPISession(host=context.connectivity.server_address,
                                   token_id=context.connectivity.admin_auth_token,
                                   domain=context.reservation.domain)
        resource = Vyos.create_from_context(context)
        ctpw = api.DecryptPassword(resource.password).Value

        session_types = [SSHSession(host=context.resource.address, username=resource.user, password=ctpw, port=self.port)]

        out = "Verbose mode disabled"

        print out
        return out

    def run_custom_command(self, context, cancellation_context, custom_command, enable_config, enable_commit):
        """
        Executes a custom command on the device
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :param str custom_command: The command to run. Note that commands that require a response are not supported.
        :param str enable_config: Flag to determine whether to enter config mode before running command.
        :param str enable_commit: Flag to determine whether to issue commit and save.
        :return: the command result text
        :rtype: str
        """
        logger = get_qs_logger(log_category="Test",log_group=context.resource.name)

        if enable_config == "True":
            logger.info("Running custom config command " + custom_command)
        else:
            logger.info("Running custom command " + custom_command)

        api = CloudShellAPISession(host=context.connectivity.server_address,
                                   token_id=context.connectivity.admin_auth_token,
                                   domain=context.reservation.domain)
        resource = Vyos.create_from_context(context)
        ctpw = api.DecryptPassword(resource.password).Value

        session_types = [SSHSession(host=context.resource.address, username=resource.user, password=ctpw, port=self.port)]

        with self.cli.get_session(session_types, self.cliMode) as default_session:
            default_session.send_command("set terminal length 0")
            if enable_config == "True":
                default_session.send_command("configure")
                out = default_session.send_command(custom_command)
                if enable_commit == "True":
                    default_session.send_command("commit")
                    default_session.send_command("save")
                default_session.send_command("exit")
            else:
                out = default_session.send_command(custom_command)

        out = "Custom command complete" + '\n' + out

        print out
        return out

    def set_hostname(self, context, cancellation_context, hostname):
        """
        Set the hostname of the device
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :param str hostname: The hostname to set on the device.
        :return: the command result text
        :rtype: str
        """
        logger = get_qs_logger(log_category="Test",log_group=context.resource.name)
        logger.info("Setting hostname...")

        api = CloudShellAPISession(host=context.connectivity.server_address,
                                   token_id=context.connectivity.admin_auth_token,
                                   domain=context.reservation.domain)
        resource = Vyos.create_from_context(context)
        ctpw = api.DecryptPassword(resource.password).Value

        session_types = [SSHSession(host=context.resource.address, username=resource.user, password=ctpw, port=self.port)]

        with self.cli.get_session(session_types, self.cliMode) as default_session:
            out = default_session.send_command("configure") + '\n'
            out = out + default_session.send_command("set system host-name " + hostname) + '\n'
            out = out + default_session.send_command("commit") + '\n'
            out = out + default_session.send_command("save") + '\n'
            out = out + default_session.send_command("exit")

        if self.verbose == "False":
            out = "Hostname set to " + hostname

        logger.info(out)

        print out
        return out

    def set_domain_name(self, context, cancellation_context, domain_name):
        """
        Set the domain name of the device
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :param str domain_name: The domain name to set on the device.
        :return: the command result text
        :rtype: str
        """
        logger = get_qs_logger(log_category="Test",log_group=context.resource.name)
        logger.info("Setting domain name...")

        api = CloudShellAPISession(host=context.connectivity.server_address,
                                   token_id=context.connectivity.admin_auth_token,
                                   domain=context.reservation.domain)
        resource = Vyos.create_from_context(context)
        ctpw = api.DecryptPassword(resource.password).Value

        session_types = [SSHSession(host=context.resource.address, username=resource.user, password=ctpw, port=self.port)]

        with self.cli.get_session(session_types, self.cliMode) as default_session:
            out = default_session.send_command("configure") + '\n'
            out = out + default_session.send_command("set system domain-name " + domain_name) + '\n'
            out = out + default_session.send_command("commit") + '\n'
            out = out + default_session.send_command("save") + '\n'
            out = out + default_session.send_command("exit")

        if self.verbose == "False":
            out = "Domain name set to " + domain_name

        logger.info(out)

        print out
        return out

    def set_static_ip(self, context, cancellation_context, eth_adpt, ip_address, subnet_mask):
        """
        Set the static IP of the selected ethernet adapter on the device
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :param str eth_adpt: The ethernet adapter to set the IP on.
        :param str ip_address: The IP address to be set.
        :param str subnet_mask: The subnet mask to be set.
        :return: the command result text
        :rtype: str
        """
        logger = get_qs_logger(log_category="Test",log_group=context.resource.name)
        logger.info("Setting IP address...")

        api = CloudShellAPISession(host=context.connectivity.server_address,
                                   token_id=context.connectivity.admin_auth_token,
                                   domain=context.reservation.domain)
        resource = Vyos.create_from_context(context)
        ctpw = api.DecryptPassword(resource.password).Value

        session_types = [SSHSession(host=context.resource.address, username=resource.user, password=ctpw, port=self.port)]

        with self.cli.get_session(session_types, self.cliMode) as default_session:
            out = default_session.send_command("configure") + '\n'
            out = out + default_session.send_command("set interfaces ethernet " + eth_adpt + " address '" + ip_address + subnet_mask + "'") + '\n'
            out = out + default_session.send_command("commit") + '\n'
            out = out + default_session.send_command("save") + '\n'
            out = out + default_session.send_command("exit")

        if self.verbose == "False":
            out = "Set " + eth_adpt + " to " + ip_address + subnet_mask

        logger.info(out)

        print out
        return out

    def set_ntp_server(self, context, cancellation_context, ntp_server):
        """
        Set the NTP server for the device
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :param str ntp_server: The IP address of the NTP server to set on the device.
        :return: the command result text
        :rtype: str
        """
        logger = get_qs_logger(log_category="Test",log_group=context.resource.name)
        logger.info("Setting NTP server...")

        api = CloudShellAPISession(host=context.connectivity.server_address,
                                   token_id=context.connectivity.admin_auth_token,
                                   domain=context.reservation.domain)
        resource = Vyos.create_from_context(context)
        ctpw = api.DecryptPassword(resource.password).Value

        session_types = [SSHSession(host=context.resource.address, username=resource.user, password=ctpw, port=self.port)]

        with self.cli.get_session(session_types, self.cliMode) as default_session:
            out = default_session.send_command("configure") + '\n'
            out = out + default_session.send_command("set system ntp server " + ntp_server) + '\n'
            out = out + default_session.send_command("commit") + '\n'
            out = out + default_session.send_command("save") + '\n'
            out = out + default_session.send_command("exit")

        if self.verbose == "False":
            out = "NTP server set to " + ntp_server

        logger.info(out)

        print out
        return out

    def set_timezone(self, context, cancellation_context, timezone):
        """
        Set the timezone for the device
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :param str timezoner: The timezone to set on the device.
        :return: the command result text
        :rtype: str
        """
        logger = get_qs_logger(log_category="Test",log_group=context.resource.name)
        logger.info("Setting timezone...")

        api = CloudShellAPISession(host=context.connectivity.server_address,
                                   token_id=context.connectivity.admin_auth_token,
                                   domain=context.reservation.domain)
        resource = Vyos.create_from_context(context)
        ctpw = api.DecryptPassword(resource.password).Value

        session_types = [SSHSession(host=context.resource.address, username=resource.user, password=ctpw, port=self.port)]

        with self.cli.get_session(session_types, self.cliMode) as default_session:
            out = default_session.send_command("configure") + '\n'
            out = out + default_session.send_command("set system time-zone " + timezone) + '\n'
            out = out + default_session.send_command("commit") + '\n'
            out = out + default_session.send_command("save") + '\n'
            out = out + default_session.send_command("exit")

        if self.verbose == "False":
            out = "Timezone set to " + timezone

        logger.info(out)

        print out
        return out

    def set_bgp_multihop(self, context, cancellation_context, local_asn, neighbor_ip, max_hops):
        """
        Allow eBGP neighbors not on directly connected networks.
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :param str local_asn: The ASN of the network that the local router is located in. (Range is 1 - 65535)
        :param str neighbor_ip: The IP address of the neighboring router to establish a route to.
        :param str max_hops: The maximum number of hops (TTL) allowed.  (Range is 1 - 255, Default is 10)
        :return: the command result text
        :rtype: str
        """
        logger = get_qs_logger(log_category="Test",log_group=context.resource.name)
        logger.info("Setting eBGP max hops...")

        api = CloudShellAPISession(host=context.connectivity.server_address,
                                   token_id=context.connectivity.admin_auth_token,
                                   domain=context.reservation.domain)
        resource = Vyos.create_from_context(context)
        ctpw = api.DecryptPassword(resource.password).Value

        session_types = [SSHSession(host=context.resource.address, username=resource.user, password=ctpw, port=self.port)]

        with self.cli.get_session(session_types, self.cliMode) as default_session:
            out = default_session.send_command("configure") + '\n'
            out = out + default_session.send_command("set protocols bgp " + local_asn + " neighbor " + neighbor_ip + " ebgp-multihop '" + max_hops + "'") + '\n'
            out = out + default_session.send_command("commit") + '\n'
            out = out + default_session.send_command("save") + '\n'
            out = out + default_session.send_command("exit")

        if self.verbose == "False":
            out = "eBGP max hops for " + neighbor_ip + " set to " + max_hops

        logger.info(out)

        print out
        return out

    def set_bgp_remote(self, context, cancellation_context, local_asn, neighbor_asn, neighbor_ip):
        """
        Specify the ASN of the neighbor
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :param str local_asn: The ASN of the network that the local router is located in. (Range is 1 - 65535)
        :param str neighbor_asn: The ASN of the network that the neighboring router is located in. (Range is 1 - 65535)
        :param str neighbor_ip: The IP address of the neighboring router to establish a route to.
        :return: the command result text
        :rtype: str
        """
        logger = get_qs_logger(log_category="Test",log_group=context.resource.name)
        logger.info("Setting neighbor ASN...")

        api = CloudShellAPISession(host=context.connectivity.server_address,
                                   token_id=context.connectivity.admin_auth_token,
                                   domain=context.reservation.domain)
        resource = Vyos.create_from_context(context)
        ctpw = api.DecryptPassword(resource.password).Value

        session_types = [SSHSession(host=context.resource.address, username=resource.user, password=ctpw, port=self.port)]

        with self.cli.get_session(session_types, self.cliMode) as default_session:
            out = default_session.send_command("configure") + '\n'
            out = out + default_session.send_command("set protocols bgp " + local_asn + " neighbor " + neighbor_ip + " remote-as '" + neighbor_asn + "'") + '\n'
            out = out + default_session.send_command("commit") + '\n'
            out = out + default_session.send_command("save") + '\n'
            out = out + default_session.send_command("exit")

        if self.verbose == "False":
            out = "Neighbor ASN for " + neighbor_ip + " set to " + neighbor_asn

        logger.info(out)

        print out
        return out

    def set_bgp_interface(self, context, cancellation_context, local_asn, neighbor_ip, eth_adpt):
        """
        Allows the router to use a specific interface for TCP connections.
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :param str local_asn: The ASN of the network that the local router is located in. (Range is 1 - 65535)
        :param str neighbor_ip: The IP address of the neighboring router to establish a route to.
        :param str eth_adpt: The ethernet adapter to use on the local router.
        :return: the command result text
        :rtype: str
        """
        logger = get_qs_logger(log_category="Test",log_group=context.resource.name)
        logger.info("Setting BGP router interface...")

        api = CloudShellAPISession(host=context.connectivity.server_address,
                                   token_id=context.connectivity.admin_auth_token,
                                   domain=context.reservation.domain)
        resource = Vyos.create_from_context(context)
        ctpw = api.DecryptPassword(resource.password).Value

        session_types = [SSHSession(host=context.resource.address, username=resource.user, password=ctpw, port=self.port)]

        with self.cli.get_session(session_types, self.cliMode) as default_session:
            out = default_session.send_command("configure") + '\n'
            out = out + default_session.send_command("set protocols bgp " + local_asn + " neighbor " + neighbor_ip + " update-source '" + eth_adpt + "'") + '\n'
            out = out + default_session.send_command("commit") + '\n'
            out = out + default_session.send_command("save") + '\n'
            out = out + default_session.send_command("exit")

        if self.verbose == "False":
            out = "BGP router interface set to " + neighbor_ip + " for " + eth_adpt

        logger.info(out)

        print out
        return out

    def set_bgp_network(self, context, cancellation_context, local_asn, local_network):
        """
        Specifies a network to be advertised by the BGP routing process.
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :param str local_asn: The ASN of the network that the local router is located in. (Range is 1 - 65535)
        :param str local_network: The IP address and mask of the network that the local router is in. (Ex. 1.0.0.0/16)
        :return: the command result text
        :rtype: str
        """
        logger = get_qs_logger(log_category="Test", log_group=context.resource.name)
        logger.info("Setting BGP network...")

        api = CloudShellAPISession(host=context.connectivity.server_address,
                                   token_id=context.connectivity.admin_auth_token,
                                   domain=context.reservation.domain)
        resource = Vyos.create_from_context(context)
        ctpw = api.DecryptPassword(resource.password).Value

        session_types = [
            SSHSession(host=context.resource.address, username=resource.user, password=ctpw, port=self.port)]

        with self.cli.get_session(session_types, self.cliMode) as default_session:
            out = default_session.send_command("configure") + '\n'
            out = out + default_session.send_command("set protocols bgp " + local_asn + " network '" + local_network + "'") + '\n'
            out = out + default_session.send_command("commit") + '\n'
            out = out + default_session.send_command("save") + '\n'
            out = out + default_session.send_command("exit")

        if self.verbose == "False":
            out = "BGP network for " + local_asn + " set to " + local_network

        logger.info(out)

        print out
        return out

    def set_bgp_router_id(self, context, cancellation_context, local_asn, router_id):
        """
        Sets a fixed BGP router ID for the router, overriding the automatic ID selection process.
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :param str local_asn: The ASN of the network that the local router is located in. (Range is 1 - 65535)
        :param str router_id: The ID to assign to the local router.
        :return: the command result text
        :rtype: str
        """
        logger = get_qs_logger(log_category="Test",log_group=context.resource.name)
        logger.info("Setting BGP router ID...")

        api = CloudShellAPISession(host=context.connectivity.server_address,
                                   token_id=context.connectivity.admin_auth_token,
                                   domain=context.reservation.domain)
        resource = Vyos.create_from_context(context)
        ctpw = api.DecryptPassword(resource.password).Value

        session_types = [SSHSession(host=context.resource.address, username=resource.user, password=ctpw, port=self.port)]

        with self.cli.get_session(session_types, self.cliMode) as default_session:
            out = default_session.send_command("configure") + '\n'
            out = out + default_session.send_command("set protocols bgp " + local_asn + " parameters router-id '" + router_id + "'") + '\n'
            out = out + default_session.send_command("commit") + '\n'
            out = out + default_session.send_command("save") + '\n'
            out = out + default_session.send_command("exit")

        if self.verbose == "False":
            out = "BGP router ID set to " + router_id + " in ASN " + local_asn

        logger.info(out)

        print out
        return out

    def set_bgp_redistribute_ospf(self, context, cancellation_context, route_map):
        """
        Redistributes routes learned from BGP OSPF routes.
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :param str route_map: Route map to redistribute
        :return: the command result text
        :rtype: str
        """
        logger = get_qs_logger(log_category="Test",log_group=context.resource.name)
        logger.info("Redistributing BGP OSPF routes...")

        api = CloudShellAPISession(host=context.connectivity.server_address,
                                   token_id=context.connectivity.admin_auth_token,
                                   domain=context.reservation.domain)
        resource = Vyos.create_from_context(context)
        ctpw = api.DecryptPassword(resource.password).Value

        session_types = [SSHSession(host=context.resource.address, username=resource.user, password=ctpw, port=self.port)]

        with self.cli.get_session(session_types, self.cliMode) as default_session:
            out = default_session.send_command("configure") + '\n'
            out = out + default_session.send_command("set protocols bgp redistribute ospf '" + route_map + "'") + '\n'
            out = out + default_session.send_command("commit") + '\n'
            out = out + default_session.send_command("save") + '\n'
            out = out + default_session.send_command("exit")

        if self.verbose == "False":
            out = "Redistributed BGP OSPF routes to " + route_map

        logger.info(out)

        print out
        return out

    def set_ospf_enable(self, context, cancellation_context):
        """
        Enables the Open Shortest Path First (OSPF) routing protocol on the router.
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :return: the command result text
        :rtype: str
        """
        logger = get_qs_logger(log_category="Test",log_group=context.resource.name)
        logger.info("Enabling OSPF protocol...")

        api = CloudShellAPISession(host=context.connectivity.server_address,
                                   token_id=context.connectivity.admin_auth_token,
                                   domain=context.reservation.domain)
        resource = Vyos.create_from_context(context)
        ctpw = api.DecryptPassword(resource.password).Value

        session_types = [SSHSession(host=context.resource.address, username=resource.user, password=ctpw, port=self.port)]

        with self.cli.get_session(session_types, self.cliMode) as default_session:
            out = default_session.send_command("configure") + '\n'
            out = out + default_session.send_command("set protocols ospf") + '\n'
            out = out + default_session.send_command("commit") + '\n'
            out = out + default_session.send_command("save") + '\n'
            out = out + default_session.send_command("exit")

        if self.verbose == "False":
            out = "OSPF Protocol enabled"

        logger.info(out)

        print out
        return out

    def set_ospf_network_address(self, context, cancellation_context, ospf_id, ip_address):
        """
        Specifies a network address for an OSPF area.
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :param str ospf_id: The ID of the OSPF being configured.
        :param str ip_address: The network to be used for the OSPF area.
        :return: the command result text
        :rtype: str
        """
        logger = get_qs_logger(log_category="Test",log_group=context.resource.name)
        logger.info("Setting OSPF network address...")

        api = CloudShellAPISession(host=context.connectivity.server_address,
                                   token_id=context.connectivity.admin_auth_token,
                                   domain=context.reservation.domain)
        resource = Vyos.create_from_context(context)
        ctpw = api.DecryptPassword(resource.password).Value

        session_types = [SSHSession(host=context.resource.address, username=resource.user, password=ctpw, port=self.port)]

        with self.cli.get_session(session_types, self.cliMode) as default_session:
            out = default_session.send_command("configure") + '\n'
            out = out + default_session.send_command("set protocols ospf area " + ospf_id + " network '" + ip_address + "'") + '\n'
            out = out + default_session.send_command("commit") + '\n'
            out = out + default_session.send_command("save") + '\n'
            out = out + default_session.send_command("exit")

        if self.verbose == "False":
            out = "OSPF network address set to " + ip_address + " for area " + ospf_id

        logger.info(out)

        print out
        return out

    def set_ospf_redistribute_bgp(self, context, cancellation_context, route_map):
        """
        Sets the parameters for redistribution of BGP routes into OSPF.
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :param str route_map: Route map to redistribute
        :return: the command result text
        :rtype: str
        """
        logger = get_qs_logger(log_category="Test",log_group=context.resource.name)
        logger.info("Redistributing OSPF BGP routes...")

        api = CloudShellAPISession(host=context.connectivity.server_address,
                                   token_id=context.connectivity.admin_auth_token,
                                   domain=context.reservation.domain)
        resource = Vyos.create_from_context(context)
        ctpw = api.DecryptPassword(resource.password).Value

        session_types = [SSHSession(host=context.resource.address, username=resource.user, password=ctpw, port=self.port)]

        with self.cli.get_session(session_types, self.cliMode) as default_session:
            out = default_session.send_command("configure") + '\n'
            out = out + default_session.send_command("set protocols ospf redistribute bgp '" + route_map + "'") + '\n'
            out = out + default_session.send_command("commit") + '\n'
            out = out + default_session.send_command("save") + '\n'
            out = out + default_session.send_command("exit")

        if self.verbose == "False":
            out = "Redistributed OSPF BGP routes to " + route_map

        logger.info(out)

        print out
        return out

    def create_vlan(self, context, cancellation_context, eth_adpt, vlan_id, ip_address):
        """
        Configure a VLAN
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :param str eth_adpt: The ethernet adapter to create the VLAN on.
        :param str vlan_id: The ID of the VLAN.
        :param str ip_address: The IP address and network prefix for this VIF.
        :return: the command result text
        :rtype: str
        """
        logger = get_qs_logger(log_category="Test",log_group=context.resource.name)
        logger.info("Creating VLAN...")

        api = CloudShellAPISession(host=context.connectivity.server_address,
                                   token_id=context.connectivity.admin_auth_token,
                                   domain=context.reservation.domain)
        resource = Vyos.create_from_context(context)
        ctpw = api.DecryptPassword(resource.password).Value

        session_types = [SSHSession(host=context.resource.address, username=resource.user, password=ctpw, port=self.port)]

        with self.cli.get_session(session_types, self.cliMode) as default_session:
            out = default_session.send_command("configure") + '\n'
            out = out + default_session.send_command("set interfaces ethernet " + eth_adpt + " vif " + vlan_id + " address '" + ip_address + "'") + '\n'
            out = out + default_session.send_command("commit") + '\n'
            out = out + default_session.send_command("save") + '\n'
            out = out + default_session.send_command("exit")

        if self.verbose == "False":
            out = "VLAN created on VIF " + vlan_id + " at " + ip_address

        logger.info(out)

        print out
        return out

    def show_system_info(self, context, cancellation_context):
        """
        Get the system info
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :return: the command result text
        :rtype: str
        """
        logger = get_qs_logger(log_category="Test",log_group=context.resource.name)
        logger.info("Getting system info...")

        api = CloudShellAPISession(host=context.connectivity.server_address,
                                   token_id=context.connectivity.admin_auth_token,
                                   domain=context.reservation.domain)
        resource = Vyos.create_from_context(context)
        ctpw = api.DecryptPassword(resource.password).Value

        session_types = [SSHSession(host=context.resource.address, username=resource.user, password=ctpw, port=self.port)]

        with self.cli.get_session(session_types, self.cliMode) as default_session:
            default_session.send_command("set terminal length 0")
            default_session.send_command("configure")
            out = default_session.send_command("show system")
            default_session.send_command("exit")

        out = "Begin system info:" + '\n' + out + '\n' + "End system info"
        logger.info(out)

        print out
        return out

    def show_interfaces_basic(self, context, cancellation_context):
        """
        Get the ethernet interfaces (basic mode)
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :return: the command result text
        :rtype: str
        """
        logger = get_qs_logger(log_category="Test",log_group=context.resource.name)
        logger.info("Getting interfaces...")

        api = CloudShellAPISession(host=context.connectivity.server_address,
                                   token_id=context.connectivity.admin_auth_token,
                                   domain=context.reservation.domain)
        resource = Vyos.create_from_context(context)
        ctpw = api.DecryptPassword(resource.password).Value

        session_types = [SSHSession(host=context.resource.address, username=resource.user, password=ctpw, port=self.port)]

        with self.cli.get_session(session_types, self.cliMode) as default_session:
            default_session.send_command("set terminal length 0")
            out = default_session.send_command("show interfaces")

        out = "Begin interface info:" + '\n' + out + '\n' + "End interface info"
        logger.info(out)

        print out
        return out


    def show_interfaces_config(self, context, cancellation_context):
        """
        Get the ethernet interfaces (config mode)
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :return: the command result text
        :rtype: str
        """
        logger = get_qs_logger(log_category="Test",log_group=context.resource.name)
        logger.info("Getting interfaces...")

        api = CloudShellAPISession(host=context.connectivity.server_address,
                                   token_id=context.connectivity.admin_auth_token,
                                   domain=context.reservation.domain)
        resource = Vyos.create_from_context(context)
        ctpw = api.DecryptPassword(resource.password).Value

        session_types = [SSHSession(host=context.resource.address, username=resource.user, password=ctpw, port=self.port)]

        with self.cli.get_session(session_types, self.cliMode) as default_session:
            default_session.send_command("set terminal length 0")
            default_session.send_command("configure")
            out = default_session.send_command("show interfaces")
            default_session.send_command("exit")

        out = "Begin interface info:" + '\n' + out + '\n' + "End interface info"
        logger.info(out)

        print out
        return out


    def show_ntp_server(self, context, cancellation_context):
        """
        Get the NTP server
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :return: the command result text
        :rtype: str
        """
        logger = get_qs_logger(log_category="Test",log_group=context.resource.name)
        logger.info("Getting NTP server...")

        api = CloudShellAPISession(host=context.connectivity.server_address,
                                   token_id=context.connectivity.admin_auth_token,
                                   domain=context.reservation.domain)
        resource = Vyos.create_from_context(context)
        ctpw = api.DecryptPassword(resource.password).Value

        session_types = [SSHSession(host=context.resource.address, username=resource.user, password=ctpw, port=self.port)]

        with self.cli.get_session(session_types, self.cliMode) as default_session:
            default_session.send_command("set terminal length 0")
            default_session.send_command("configure")
            out = default_session.send_command("show system ntp server")
            default_session.send_command("exit")

        out = "Begin NTP server info:" + '\n' + out + '\n' + "End NTP server info"
        logger.info(out)

        print out
        return out

    def show_timezone(self, context, cancellation_context):
        """
        Get the timezone
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :return: the command result text
        :rtype: str
        """
        logger = get_qs_logger(log_category="Test",log_group=context.resource.name)
        logger.info("Getting timezone...")

        api = CloudShellAPISession(host=context.connectivity.server_address,
                                   token_id=context.connectivity.admin_auth_token,
                                   domain=context.reservation.domain)
        resource = Vyos.create_from_context(context)
        ctpw = api.DecryptPassword(resource.password).Value

        session_types = [SSHSession(host=context.resource.address, username=resource.user, password=ctpw, port=self.port)]

        with self.cli.get_session(session_types, self.cliMode) as default_session:
            default_session.send_command("set terminal length 0")
            default_session.send_command("configure")
            out = default_session.send_command("show system time-zone")
            default_session.send_command("exit")

        logger.info(out)

        print out
        return out

    def show_system_uptime(self, context, cancellation_context):
        """
        Get the system uptime
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :return: the command result text
        :rtype: str
        """
        logger = get_qs_logger(log_category="Test",log_group=context.resource.name)
        logger.info("Getting system uptime...")

        api = CloudShellAPISession(host=context.connectivity.server_address,
                                   token_id=context.connectivity.admin_auth_token,
                                   domain=context.reservation.domain)
        resource = Vyos.create_from_context(context)
        ctpw = api.DecryptPassword(resource.password).Value

        session_types = [SSHSession(host=context.resource.address, username=resource.user, password=ctpw, port=self.port)]

        with self.cli.get_session(session_types, self.cliMode) as default_session:
            default_session.send_command("set terminal length 0")
            out = default_session.send_command("show system uptime")

        logger.info(out)

        print out
        return out

    def show_bgp_routes(self, context, cancellation_context):
        """
        Get the BGP routes
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :return: the command result text
        :rtype: str
        """
        logger = get_qs_logger(log_category="Test",log_group=context.resource.name)
        logger.info("Getting BGP routes...")

        api = CloudShellAPISession(host=context.connectivity.server_address,
                                   token_id=context.connectivity.admin_auth_token,
                                   domain=context.reservation.domain)
        resource = Vyos.create_from_context(context)
        ctpw = api.DecryptPassword(resource.password).Value

        session_types = [SSHSession(host=context.resource.address, username=resource.user, password=ctpw, port=self.port)]

        with self.cli.get_session(session_types, self.cliMode) as default_session:
            default_session.send_command("set terminal length 0")
            out = default_session.send_command("show ip bgp")

        out = "Begin BGP routing info:" + '\n' + out + '\n' + "End BGP routing info"
        logger.info(out)

        print out
        return out

    def show_vlan(self, context, cancellation_context, eth_adpt, vlan_id):
        """
        Get the VLAN info
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :param str eth_adpt: The ethernet adapter to create the VLAN on.
        :param str vlan_id: The ID of the VLAN.
        :return: the command result text
        :rtype: str
        """
        logger = get_qs_logger(log_category="Test",log_group=context.resource.name)
        logger.info("Getting VLAN info...")

        api = CloudShellAPISession(host=context.connectivity.server_address,
                                   token_id=context.connectivity.admin_auth_token,
                                   domain=context.reservation.domain)
        resource = Vyos.create_from_context(context)
        ctpw = api.DecryptPassword(resource.password).Value

        session_types = [SSHSession(host=context.resource.address, username=resource.user, password=ctpw, port=self.port)]

        with self.cli.get_session(session_types, self.cliMode) as default_session:
            default_session.send_command("set terminal length 0")
            out = default_session.send_command("show interfaces ethernet " + eth_adpt + " vif " + vlan_id)

        out = "Begin VLAN info:" + '\n' + out + '\n' + "End VLAN info"
        logger.info(out)

        print out
        return out

    def shutdown(self, context, cancellation_context):
        """
        Sends a graceful shutdown to the device
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        """
        pass

    def get_inventory(self, context):
        """
        Discovers the resource structure and attributes.
        :param AutoLoadCommandContext context: the context the command runs on
        :return Attribute and sub-resource information for the Shell resource you can return an AutoLoadDetails object
        :rtype: AutoLoadDetails
        """

        # See below some example code demonstrating how to return the resource structure and attributes
        # In real life, this code will be preceded by SNMP/other calls to the resource details and will not be static
        # run 'shellfoundry generate' in order to create classes that represent your data model

        logger = get_qs_logger(log_category="Test", log_group=context.resource.name)
        logger.info("Starting autoload")

        api = CloudShellAPISession(host=context.connectivity.server_address,
                                   token_id=context.connectivity.admin_auth_token,
                                   domain="Global")
        resource = Vyos.create_from_context(context)
        ctpw = api.DecryptPassword(resource.password).Value

        session_types = [SSHSession(host=context.resource.address, username=resource.user, password=ctpw, port=self.port)]

        with self.cli.get_session(session_types, self.cliMode) as default_session:
            default_session.send_command("set terminal length 0")
            default_session.send_command("configure")
            out = default_session.send_command("show interfaces")
            default_session.send_command("exit")

        # Example output from show interfaces command in config mode
        """
        [edit]
        vyos@MyVyos# show interfaces
        ethernet eth0 {
            address 192.168.1.91/24
            duplex auto
            hw-id 52:54:00:9b:f4:0c
            smp_affinity auto
            speed auto
        }
        ethernet eth1 {
            duplex auto
            hw-id 52:54:00:40:16:13
            smp_affinity auto
            speed auto
        }
        ethernet eth2 {
            duplex auto
            hw-id 52:54:00:25:51:58
            smp_affinity auto
            speed auto
        }
        ethernet eth3 {
            duplex auto
            hw-id 52:54:00:3a:16:63
            smp_affinity auto
            speed auto
        }
        loopback lo {
        }
       [edit]
       vyos@MyVyos#
       """

        logger.info("CLI Output:")
        logger.info(out)

        logger.info("Beginning parse")
        print("Beginning parse")
        intTable = out
        intTable = intTable.split("[edit]")
        intTable = intTable[1]
        intTable = intTable.split("}")
        logger.info("Parsing complete")
        print("Parsing complete")

        resource.vendor = 'Vyatta'
        resource.model = 'VyOS'
        chassis1 = GenericChassis('Chassis 1')
        resource.add_sub_resource('1', chassis1)
        module1 = GenericModule('Module 1')
        module1.model = 'Generic Module'
        chassis1.add_sub_resource('1', module1)

        logger.info("CLI Parsed:")
        logger.info(intTable)

        logger.info("Begin interface loop")
        print("Begin interface loop")

        for section in intTable:
            portName = ""
            portAddr = ""
            portMAC = ""
            for line in section.split("\n"):
                line = line.strip()
                if line.startswith('ethernet'):
                    column = line.split(" ")
                    portName = column[1].strip()
                elif line.startswith('loopback'):
                    portName = "lo"
                    portAddr = "127.0.0.1"
                elif line.startswith('address'):
                    column = line.split(" ")
                    portAddr = column[1].strip().split("/")[0]
                elif line.startswith('hw-id'):
                    column = line.split(" ")
                    portMAC = column[1].strip()

            logger.info("\tNAME: " + portName)
            print("\tNAME: " + portName)
            logger.info("\tADDR: " + portAddr)
            print("\tADDR: " + portAddr)
            logger.info("\tMAC: " + portMAC)
            print("\tMAC: " + portMAC)

            if (len(portName) > 1):
                port = GenericPort(portName)
                if (portAddr) == "":
                    port.ipv4_address = portName + " - No Address"
                    logger.info("\tNEW ADDR: " + port.ipv4_address)
                    print("\tNEW ADDR: " + port.ipv4_address)
                else:
                    port.ipv4_address = portAddr
                port.mac_address = portMAC
                module1.add_sub_resource(port.ipv4_address, port)
                logger.info("\tAdded to inventory")
                print("\tAdded to inventory")
            else:
                logger.info("\tSkipping previous line")
                print("\tSkipping previous line")

        logger.info("End interface loop")
        print("End interface loop")
        logger.info("Ending autoload")
        print("Ending autoload")

        return resource.create_autoload_details()

    # def get_inventory(self, context):
    #     """
    #     Discovers the resource structure and attributes.
    #     :param AutoLoadCommandContext context: the context the command runs on
    #     :return Attribute and sub-resource information for the Shell resource you can return an AutoLoadDetails object
    #     :rtype: AutoLoadDetails
    #     """
    #
    #     # See below some example code demonstrating how to return the resource structure and attributes
    #     # In real life, this code will be preceded by SNMP/other calls to the resource details and will not be static
    #     # run 'shellfoundry generate' in order to create classes that represent your data model
    #
    #     logger = get_qs_logger(log_category="Test",log_group=context.resource.name)
    #     logger.info("Starting autoload")
    #
    #     api = CloudShellAPISession(host=context.connectivity.server_address,
    #                                token_id=context.connectivity.admin_auth_token,
    #                                domain="Global")
    #     resource = Vyos.create_from_context(context)
    #     ctpw = api.DecryptPassword(resource.password).Value
    #
    #     session_types = [SSHSession(host=context.resource.address, username=resource.user, password=ctpw, port=self.port)]
    #
    #     with self.cli.get_session(session_types, self.cliMode) as default_session:
    #         default_session.send_command("set terminal length 0")
    #         out = default_session.send_command("show interfaces")
    #
    #     """
    #     vyos@MrVyos:~$ show interfaces
    #     Codes: S - State, L - Link, u - Up, D - Down, A - Admin Down
    #     Interface        IP Address                        S/L  Description
    #     ---------        ----------                        ---  -----------
    #     eth0             192.168.2.161/24                  u/u
    #     eth1             -                                 u/u
    #     eth2             -                                 u/u
    #     eth3             -                                 u/u
    #     lo               127.0.0.1/8                       u/u
    #                      ::1/128
    #     """
    #     intTable = re.compile("\n-.*-").split(out)
    #     intTable = intTable[1].split(resource.user +"@")
    #     intTable = intTable[0]
    #     intTable = re.sub(r" +", ' ', intTable)
    #
    #     resource.vendor = 'Vayatta'
    #     resource.model = 'VyOS'
    #     chassis1 = GenericChassis('Chassis 1')
    #     resource.add_sub_resource('1', chassis1)
    #     module1 = GenericModule('Module 1')
    #     module1.model = 'Generic Module'
    #     chassis1.add_sub_resource('1', module1)
    #
    #     logger.info("CLI Output:")
    #     logger.info(out)
    #
    #     logger.info("CLI Parsed:")
    #     logger.info(intTable)
    #
    #     logger.info("Begin interface loop")
    #
    #     for line in intTable.split("\n"):
    #         line = line.strip()
    #         logger.info("LINE: " + line)
    #         try:
    #             row = line.split(" ")
    #             portName = row[0].strip()
    #             portAddr = row[1].strip().split("/")[0]
    #             logger.info("\tNAME: " + portName)
    #             logger.info("\tADDR: " + portAddr)
    #             if(len(portName)> 1):
    #                 port = GenericPort(portName)
    #                 if (portAddr) == "-":
    #                     port.ipv4_address = portName + " - No Address"
    #                     logger.info("\tNEW ADDR: " + port.ipv4_address)
    #                 else:
    #                     port.ipv4_address = portAddr
    #                 module1.add_sub_resource(port.ipv4_address, port)
    #                 logger.info("\tAdded to inventory")
    #             else:
    #                 logger.info("\tSkipping previous line")
    #         except:
    #             logger.warning("\tSkipping previous line")
    #             pass
    #
    #     logger.info("End interface loop")
    #     logger.info("Ending autoload")
    #
    #     return resource.create_autoload_details()

    def health_check(self,cancellation_context):
        """
        Checks if the device is up and connectable
        :return: str: Success or fail message
        """
        pass

    def cleanup(self):
        """
        Destroy the driver session, this function is called everytime a driver instance is destroyed
        This is a good place to close any open sessions, finish writing to log files
        """
        pass