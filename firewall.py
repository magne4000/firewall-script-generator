#!/usr/bin/env python
# -*- coding: utf-8 -*-

from argparse import ArgumentParser
from difflib import unified_diff
from os.path import isfile
import ConfigParser
import re
import sys
import os

config = ConfigParser.RawConfigParser()
if isfile('./firewall.conf'):
    config.read('./firewall.conf')
elif isfile(os.getenv('HOME') + '/.config/firewall.conf'):
    config.read(os.getenv('HOME') + '/.config/firewall.conf')
elif isfile('/etc/conf.d/firewall.conf'):
    config.read('/etc/conf.d/firewall.conf')
else:
    print 'firewall.conf not found.'
    os._exit(1)
# base script filepath
BASE_SCRIPT_PATH=config.get('path', 'script.base')

# script filepath (generated file)
SCRIPT_FILE=config.get('path', 'script.gen')

class Service:
    
    services = []
    
    def __init__(self, name, protocol, ports=[], external=True, restricted=False):
        self.name = name
        self.protocol = protocol
        if isinstance(ports, str):
            self.s_ports = ports
        else:
            self.a_ports = ports
        self.external = external
        self.restricted = restricted
        Service.add(self)
    
    def __setattr__(self, name, value):
        if name == 'a_ports':
            if not self._check_ports_len(value):
                raise ValueError('A service can\'t contain more than 15 ports. Aborting.')
            self.__dict__['s_ports'] = ','.join(value)
        elif name == 's_ports':
            if not self._check_ports_len(value):
                raise ValueError('A service can\'t contain more than 15 ports. Aborting.')
            self.__dict__['a_ports'] = value.split(',')
        self.__dict__[name] = value
    
    def _check_ports_len(self, ports):
        if isinstance(ports, str):
            return ports.count(',') + ports.count(':') + 1 <= 15
        else:
            cpt = 0
            for port in ports:
                if str(port).count(':'):
                    cpt +=2
                else:
                    cpt += 1
            return cpt <= 15
    
    @staticmethod
    def get(protocol, external=True, restricted=False, all=False, name=None):
        services = None
        if protocol == 'both':
            if all:
                services = Service.services
            elif external:
                services = [service for service in Service.services if service.external]
            elif not external and not restricted:
                services = [service for service in Service.services if not service.external and not service.restricted]
            elif not external and restricted:
                services = [service for service in Service.services if not service.external and service.restricted]
            if name is not None:
                for service in services:
                    if service.name.lower() == name.lower():
                        return service
                return None
        else:
            if all:
                services = [service for service in Service.services if service.protocol == protocol]
            elif external:
                services = [service for service in Service.services if service.protocol == protocol and service.external]
            elif not external and not restricted:
                services = [service for service in Service.services if service.protocol == protocol and not service.external and not service.restricted]
            elif not external and restricted:
                services = [service for service in Service.services if service.protocol == protocol and not service.external and service.restricted]
            if name is not None:
                for service in services:
                    if service.name.lower() == name.lower():
                        return service
                return None
        return services
    
    @staticmethod
    def remove(name, protocol, external=True, restricted=False):
        if protocol == 'both':
            if Service.exists(name, 'tcp', external=external, restricted=restricted):
                Service.services.remove(Service.get('tcp', external=external, restricted=restricted, name=name))
            if Service.exists(name, 'udp', external=external, restricted=restricted):
                Service.services.remove(Service.get('udp', external=external, restricted=restricted, name=name))
        else:
            Service.services.remove(Service.get(protocol, external=external, restricted=restricted, name=name))
    
    @staticmethod
    def exists(name, protocol, external=True, restricted=False):
        return Service.get(protocol, external=external, restricted=restricted, name=name) is not None
    
    @staticmethod
    def add(service):
        Service.services.append(service)
    
    def __str__(self):
        return 'Service "%s" (%s) - %s' % (self.name, 'External' if self.external else 'Internal restricted' if self.restricted else 'Internal', '%s : %s' % ('TCP' if self.protocol == 'tcp' else 'UDP', self.s_ports))

class Client:
    
    def __init__(self, macs=[], identifier=None, enabled=True, open_all_ports=False):
        self.macs = macs
        self.identifier = self._clean(identifier)
        self.enabled = enabled
        self.open_all_ports = open_all_ports
    
    @staticmethod
    def check_mac(mac):
        re_mac = re.compile(Script.S_RE_MAC)
        return re_mac.match(mac) is not None

    def _check_mac(self, mac):
        return Client.check_mac(mac)
    
    def _check_identifier(self, identifier):
        if identifier is None:
            return True
        re_identifier = re.compile('\w+')
        return re_identifier.match(identifier) is not None
    
    def __setattr__(self, name, value):
        if name == 'macs':
            for mac in value:
                if not self._check_mac(mac):
                    raise ValueError('MAC address "%s" is not valid.' % mac)
        elif name == 'identifier':
            if not self._check_identifier(value):
                raise ValueError('Identifier "%s" is not valid.' % value)
        self.__dict__[name] = value
    
    def _clean(self, identifier):
        if identifier is None:
            return None
        return re.sub('\s+', '_', identifier)
    
    def to_string(self):
        return '%s  %s # %s' % ('' if self.enabled else '#', ','.join(self.macs), self.identifier)
    
    def __str__(self):
        return 'Identifier : %s\nMACS : %s' % (self.identifier, ', '.join(self.macs))

class BaseScript:
    
    def __init__(self):
        self._init_file_handler()
        self.script_content = self.fh.read()
    
    def _init_file_handler(self, mode='r'):
        global BASE_SCRIPT_PATH
        self.fh = open(BASE_SCRIPT_PATH, mode)
    
    def _close_file_handler(self):
        self.fh.close()
        self.fh = None

class Script:
    
    #Sections delimiters
    BEGIN_SECTION='# BEGIN %s'
    END_SECTION='# END %s'
    
    #Sections
    SECTION_CLIENTS='CLIENTS'
    SECTION_CLIENTS_PORTS='CLIENTS PORTS'
    SECTION_WAN='WAN'
    SECTION_LAN='LAN'
    SECTION_SERVICES_PORTS='SERVICES PORTS'
    SECTION_RESTRICTED_SERVICES_PORTS='RESTRICTED SERVICES PORTS'
    SECTION_PORT_FORWARDING='PORT FORWARDING'
    SECTION_START='START'
    SECTION_STOP='STOP'
    
    #Var names
    CLIENTS_TCP_PORTS_NAME='CLIENTS_TCP_PORTS'
    
    #Var regex
    S_RE_IP_WITHOUT_MASK='\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    
    RE_WAN=re.compile('WAN=(\w+)$')
    RE_WAN_IP=re.compile('WAN_IP=(%s)$' % S_RE_IP_WITHOUT_MASK)
    
    RE_LAN=re.compile('LAN=(\w+)$')
    RE_LAN_IP=re.compile('LAN_IP=(%s)$' % S_RE_IP_WITHOUT_MASK)
    RE_LAN_R=re.compile('LAN_R=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})$')
    
    RE_SERVICE_TCP_EXTERNAL=re.compile('E_(\w+)_TCP_PORTS="([0-9,:]*)"')
    RE_SERVICE_UDP_EXTERNAL=re.compile('E_(\w+)_UDP_PORTS="([0-9,:]*)"')
    RE_SERVICE_TCP_INTERNAL=re.compile('I_(\w+)_TCP_PORTS="([0-9,:]*)"')
    RE_SERVICE_UDP_INTERNAL=re.compile('I_(\w+)_UDP_PORTS="([0-9,:]*)"')
    RE_SERVICE_TCP_INTERNAL_RESTRICTED=re.compile('IR_(\w+)_TCP_PORTS="([0-9,:]*)"')
    RE_SERVICE_UDP_INTERNAL_RESTRICTED=re.compile('IR_(\w+)_UDP_PORTS="([0-9,:]*)"')
    
    S_RE_IP='\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?'
    S_RE_MAC='(?:[0-9a-fA-F]){2}(?::(?:[0-9a-fA-F]){2}){5}'
    RE_CLIENTS=re.compile('^CLIENTS=\($\n(.*?)\n^\)$', re.M|re.S)
    RE_CLIENTS_U=re.compile('^CLIENTS_U=\($\n(.*?)\n^\)$', re.M|re.S)
    RE_CLIENT=re.compile('\s*(#\s*)?(?:%s!)?((?:%s)(?:,(?:%s))*)\s+#\s+(\w+)' % (S_RE_IP, S_RE_MAC, S_RE_MAC))
    RE_FORWARD_RULES=re.compile('^FORWARD_RULES=\($\n(.*)\n^\)$', re.M|re.S)
    RE_FORWARD_RULE=re.compile('\s*(\d+)!(%s):(\d+)' % S_RE_IP_WITHOUT_MASK)
    
    def __init__(self):
        self.fh = None
        self.clients = []
        self.script_content = ''
        self.services = Service
        self.forward_rules = {}
        self.wan = '#EDIT-WAN'
        self.wan_ip = '#EDIT-WAN_IP'
        self.lan = '#EDIT-LAN'
        self.lan_ip = '#EDIT-LAN_IP'
        self.lan_r = '#EDIT-LAN_R'
    
    def _fetch_content(self, force=False):
        if (force or self.script_content == ''):
            if self.fh is None:
                if self._init_file_handler():
                    self.script_content = self.fh.read()
                    return True
        return False
    
    def _init_file_handler(self, mode='r', suffix=''):
        global SCRIPT_FILE
        if mode != 'r' or (mode == 'r' and isfile(SCRIPT_FILE)):
            self.fh = open('%s%s' % (SCRIPT_FILE, suffix), mode)
            return True
        return False
    
    def _close_file_handler(self):
        self.fh.close()
        self.fh = None
    
    def _get_section(self, section):
        ifrom = self.script_content.find(self.BEGIN_SECTION % section)
        ito = self.script_content.find(self.END_SECTION % section, ifrom)
        return self.script_content[ifrom:ito]
    
    def _parse_wan(self):
        for line in self._get_section(self.SECTION_WAN).split('\n'):
            match = self.RE_WAN.match(line)
            if match is not None:
                self.wan = match.group(1)
            match = self.RE_WAN_IP.match(line)
            if match is not None:
                self.wan_ip = match.group(1)
    
    def _parse_lan(self):
        for line in self._get_section(self.SECTION_LAN).split('\n'):
            match = self.RE_LAN.match(line)
            if match is not None:
                self.lan = match.group(1)
            match = self.RE_LAN_IP.match(line)
            if match is not None:
                self.lan_ip = match.group(1)
            match = self.RE_LAN_R.match(line)
            if match is not None:
                self.lan_r = match.group(1)
    
    def _parse_clients(self):
        clients = self.RE_CLIENTS.findall(self._get_section(self.SECTION_CLIENTS))
        clients_u = self.RE_CLIENTS_U.findall(self._get_section(self.SECTION_CLIENTS))
        self.clients = []
        if clients is not None and len(clients) > 0:
            for client in clients[0].split('\n'):
                new_client = Client()
                match = self.RE_CLIENT.match(client.strip())
                if match is not None:
                    comment, macs, identifier = match.groups()
                    new_client.macs = macs.split(',')
                    new_client.identifier = identifier
                    new_client.enabled = (comment is None or len(comment.strip()) == 0)
                    new_client.open_all_ports = False
                    self.clients.append(new_client)
        if clients_u is not None and len(clients_u) > 0:
            for client in clients_u[0].split('\n'):
                new_client = Client()
                match = self.RE_CLIENT.match(client.strip())
                if match is not None:
                    comment, macs, identifier = match.groups()
                    new_client.macs = macs.split(',')
                    new_client.identifier = identifier
                    new_client.enabled = (comment is None or len(comment.strip()) == 0)
                    new_client.open_all_ports = True
                    self.clients.append(new_client)

    def _parse_services(self, external=True, restricted=False):
        tokenizer = self.SECTION_CLIENTS_PORTS
        if external is False:
            if restricted:
                tokenizer = self.SECTION_RESTRICTED_SERVICES_PORTS
            else:
                tokenizer = self.SECTION_SERVICES_PORTS
        for line in self._get_section(tokenizer).split('\n'):
            match = None
            if external:
                match = self.RE_SERVICE_TCP_EXTERNAL.match(line)
            elif restricted:
                match = self.RE_SERVICE_TCP_INTERNAL_RESTRICTED.match(line)
            else:
                match = self.RE_SERVICE_TCP_INTERNAL.match(line)
            if match is not None:
                Service(match.group(1), 'tcp', match.group(2).split(','), external=external, restricted=restricted)
            match = None
            if external:
                match = self.RE_SERVICE_UDP_EXTERNAL.match(line)
            elif restricted:
                match = self.RE_SERVICE_UDP_INTERNAL_RESTRICTED.match(line)
            else:
                match = self.RE_SERVICE_UDP_INTERNAL.match(line)
            if match is not None:
                Service(match.group(1), 'udp', match.group(2).split(','), external=external, restricted=restricted)
    
    def _parse_forward_rules(self):
        rules = self.RE_FORWARD_RULES.findall(self._get_section(self.SECTION_PORT_FORWARDING))
        if rules is not None:
            self.forward_rules = {}
            for rule in rules[0].split():
                port_from, ip_to, port_to = self.RE_FORWARD_RULE.match(rule.strip()).groups()
                self.forward_rules[port_from] = (ip_to, port_to)
    
    def _service_to_sh_var(self, service):
        if service.external:
            return 'E_%s_%s_PORTS' % (service.name.upper(), service.protocol.upper())
        elif service.restricted:
            return 'IR_%s_%s_PORTS' % (service.name.upper(), service.protocol.upper())
        else:
            return 'I_%s_%s_PORTS' % (service.name.upper(), service.protocol.upper())
    
    def _get_tcp_ports_lines(self, services):
        return '\n'.join(['$%s' % (self._service_to_sh_var(service)) for service in services])
    
    def _get_udp_ports_lines(self, services):
        return '\n'.join(['$%s' % (self._service_to_sh_var(service)) for service in services])
    
    def _clients_to_string(self):
        return '\n'.join([client.to_string() for client in self.clients if not client.open_all_ports])
    
    def _clients_u_to_string(self):
        return '\n'.join([client.to_string() for client in self.clients if client.open_all_ports])
    
    def _forward_rules_to_string(self):
        return '\n'.join(['  %s!%s:%s' % (port_from, to[0], to[1]) for port_from, to in self.forward_rules.iteritems()])
    
    def _services_to_string(self, services_tcp, services_udp):
        l_services = []
        for service in services_tcp:
            l_services.append('%s="%s"' % (self._service_to_sh_var(service), service.s_ports))
        for service in services_udp:
            l_services.append('%s="%s"' % (self._service_to_sh_var(service), service.s_ports))
        return '\n'.join(l_services)
    
    def _raw_input(self, prompt, regex, myformat, cpt=3):
        s = ''
        while cpt > 0:
            s = raw_input('%s : ' % prompt)
            if regex.match(myformat % s) is not None:
                break
            print 'Incorrect value.'
            cpt -= 1
        if cpt == 0:
            raise ValueError('Invalid value for "%s"' % prompt)
        return s
    
    def _create_file(self):
        global SCRIPT_FILE
        try:
            self._init_file_handler(mode='w')
        except IOError as e:
            print 'File "%s" cannot be open for writing. Aborting.' % SCRIPT_FILE
            sys.exit(1)
        try:
            self.wan = self._raw_input('WAN interface (ex: eth0)', self.RE_WAN, 'WAN=%s')
            self.wan_ip = self._raw_input('WAN IP (ex: 192.168.1.254)', self.RE_WAN_IP, 'WAN_IP=%s')
            self.lan = self._raw_input('LAN interface (ex: eth1)', self.RE_LAN, 'LAN=%s')
            self.lan_ip = self._raw_input('LAN IP (ex: 10.90.34.1)', self.RE_LAN_IP, 'LAN_IP=%s')
            self.lan_r = self._raw_input('LAN mask (ex: 10.0.0.0/8)', self.RE_LAN_R, 'LAN_R=%s')
        except ValueError as e:
            print e
            sys.exit(1)
        script.save(diff=False)
    
    def parse(self):
        # File exists
        if self._fetch_content():            
            self._parse_wan()
            self._parse_lan()
            self._parse_clients()
            self._parse_services(external=True)
            self._parse_services(external=False, restricted=False)
            self._parse_services(external=False, restricted=True)
            self._parse_forward_rules()
            self._close_file_handler()
            return True
        # File does not exists, create it !
        self._create_file()
        return False
    
    def save(self, diff=True):
        base_script = BaseScript()
        new_content = base_script.script_content.format(
            wan=self.wan,
            wan_ip=self.wan_ip,
            lan=self.lan,
            lan_ip=self.lan_ip,
            lan_r=self.lan_r,
            clients=self._clients_to_string(),
            clients_u=self._clients_u_to_string(),
            clients_ports=self._services_to_string(self.services.get('tcp', external=True), self.services.get('udp', external=True)),
            clients_tcp_ports=self._get_tcp_ports_lines(self.services.get('tcp', external=True)),
            clients_udp_ports=self._get_udp_ports_lines(self.services.get('udp', external=True)),
            services_ports=self._services_to_string(self.services.get('tcp', external=False, restricted=False), self.services.get('udp', external=False, restricted=False)),
            services_tcp_ports=self._get_tcp_ports_lines(self.services.get('tcp', external=False, restricted=False)),
            services_udp_ports=self._get_udp_ports_lines(self.services.get('udp', external=False, restricted=False)),
            restricted_services_ports=self._services_to_string(self.services.get('tcp', external=False, restricted=True), self.services.get('udp', external=False, restricted=True)),
            restricted_services_tcp_ports=self._get_tcp_ports_lines(self.services.get('tcp', external=False, restricted=True)),
            restricted_services_udp_ports=self._get_udp_ports_lines(self.services.get('udp', external=False, restricted=True)),
            forward_rules=self._forward_rules_to_string()
        )
        if diff:
            sdiff = unified_diff(self.script_content.splitlines(1), new_content.splitlines(1))
            bdiff = False
            for a in sdiff:
                bdiff = True
                break
            if not bdiff:
                print 'Nothing to do.'
            else:
                print
                sys.stdout.writelines(sdiff)
                print
                for _ in xrange(3):
                    s = raw_input('Apply this changes ? [Y/N] : ')
                    if s.upper() == 'N':
                        print 'Script file NOT saved.'
                        return 0
                    elif s.upper() == 'Y':
                        self._init_file_handler(mode='w')
                        self.fh.write(new_content)
                        self._close_file_handler()
                        print 'Script file saved.'
                        return 0
        else:
            self.fh.write(new_content)
            self._close_file_handler()
            print 'Script file saved.'
            return 0
        print 'Script file NOT saved. Aborting.'
    
    def get_clients(self):
        return self.clients

def port_range_to_list(port_range):
    if str(port_range).count(':') > 0:
        x, y = port_range.split(':')
        return range(int(x), int(y)+1)
    return [int(port_range)]

def clean_port(port, ports):
    _port = port_range_to_list(port)
    ports = set(ports)
    for _single_port in set(_port):
        if int(_single_port) in ports:
            _port.remove(_single_port)
    if len(_port) == 0:
        return []
    if len(_port) == 1:
        return _port
    return ports_list_to_range(_port)

def ports_list_to_range(ports):
    ports = sorted(set(ports))
    new_ports = []
    old_port = None
    range_from = None
    alt_port = None
    if len(ports) >= 2:
        if ports[1] - ports[0] == 1:
            range_from = ports[0]
        else:
            new_ports.append(ports[0])
        old_port = ports[0]
        del ports[0]
    for port in ports:
        if port-1 == old_port:
            if alt_port is not None:
                if range_from is None:
                    range_from = old_port
                else:
                    new_ports.append(str(alt_port))
                alt_port = None
            if range_from is None:
                range_from = port
        else:
            if range_from is not None:
                new_ports.append('%s:%s' % (range_from,old_port))
            if alt_port is not None:
                new_ports.append(str(alt_port))
            alt_port = port
            range_from = None
        old_port = port
    if range_from is not None:
        new_ports.append('%s:%s' % (range_from,old_port))
    elif alt_port is not None:
        new_ports.append(str(alt_port))
    return new_ports

def simplify_ports(str_ports):
    ports = str_ports.split(',')
    new_ports = []
    for port in ports:
        new_ports.extend(port_range_to_list(port))
    return ports_list_to_range(new_ports)

def clean_ports(str_ports, services):
    ports = simplify_ports(str_ports)
    all_ports = []
    _all_ports = []
    for service in services:
        all_ports.extend(service.a_ports)
    for port in all_ports : _all_ports.extend(port_range_to_list(port))
    for port in ports:
        for port in clean_port(port, _all_ports):
            yield port

def addclient(args, script):
    exists = False
    existing_client = None
    #Check if the client already exists
    for client in script.get_clients():
        if client.identifier.lower() == args.identifier.lower():
            exists = True
            existing_client = client
            break
    
    if not exists: # new client
        try:
            script.clients.append(Client(args.macs, args.identifier, open_all_ports=args.open_all_ports))
        except ValueError as e:
            print e
            sys.exit(1)
        print 'Adding client %s.' % args.identifier
    else:
        script.clients.remove(existing_client)
        for mac in args.macs:
            if Client.check_mac(mac):
                if existing_client.macs.count(mac) > 0:
                    print 'Skipping MAC address "%s" which is already registered for %s.' % (mac, args.identifier)
                else:
                    existing_client.macs.append(mac)
            else:
                print 'Skipping invalid MAC address "%s"' % mac
        script.clients.append(existing_client)
        print 'Updating client %s.' % args.identifier
    script.save()

def delclient(args, script):
    existing_client = None
    for client in script.get_clients():
        if client.identifier.lower() == args.identifier.lower():
            existing_client = client
            break
    if existing_client is None:
        print 'Client "%s" doesn\'t exists, nothing to do.' % args.identifier
        return
    script.clients.remove(existing_client)
    script.save()

def enclient(args, script):
    existing_client = None
    for client in script.get_clients():
        if client.identifier.lower() == args.identifier.lower():
            existing_client = client
            break
    if existing_client is None:
        print 'Client "%s" doesn\'t exists, nothing to do.' % args.identifier
        return
    existing_client.enabled = True
    script.save()

def disclient(args, script):
    existing_client = None
    for client in script.get_clients():
        if client.identifier.lower() == args.identifier.lower():
            existing_client = client
            break
    if existing_client is None:
        print 'Client "%s" doesn\'t exists, nothing to do.' % args.identifier
        return
    existing_client.enabled = False
    script.save()

def upgrade(args, script):
    script.save()

def addservice(args, script):
    args.service = args.service.upper()
    external = args.type == 'external' and not args.restricted
    restricted = args.restricted
    
    services = Service.get(args.protocol, external=external, restricted=restricted)
    if Service.exists(args.service, args.protocol, external=external, restricted=restricted):
        args.ports = '%s,%s' % (args.ports, Service.get(args.protocol, name=args.service).s_ports)
        services.remove(Service.get(args.protocol, external=external, restricted=restricted, name=args.service))
        Service.remove(args.service, args.protocol, external=external, restricted=restricted)
    try:
        Service(args.service, args.protocol, [str(port) for port in clean_ports(args.ports, services) if port is not None], external=external, restricted=restricted)
    except ValueError as e:
        print e
        sys.exit(3)
    script.save()
    
def delservice(args, script):
    external = args.type == 'external' and not args.restricted
    restricted = args.restricted
    
    if Service.exists(args.service, args.protocol, external=external, restricted=restricted):
        Service.remove(args.service, args.protocol, external=external, restricted=restricted)
        script.save()
        return
    print 'Service "%s" doesn\'t exists, nothing to do.' % args.service
    return

def list_wan(args, script):
    print '\nWAN : %s' % script.wan
    print 'WAN_IP : %s' % script.wan_ip
    print

def list_lan(args, script):
    print '\nLAN : %s' % script.wan
    print 'LAN_IP : %s' % script.wan_ip
    print 'LAN_R : %s' % script.lan_r
    print

def list_services(args, script):
    services = sorted(Service.get('both', all=True), key=lambda service: service.name)
    print
    for service in services:
        print service
    print

def list_clients(args, script):
    for client in script.get_clients():
        print '\n', client
    print
    
def list_all(args, script):
    print '\n -- WAN --'
    list_wan(args, script)
    print ' -- LAN --'
    list_lan(args, script)
    print ' -- Clients --'
    list_clients(args, script)
    print ' -- Services --'
    list_services(args, script)

def info(args, script):
    searchme = re.compile('%s' % args.clientorservice, re.I)
    for client in script.get_clients():
        if searchme.search(client.identifier) is not None:
            print '\n', client
    services = sorted(Service.get('both', all=True), key=lambda service: service.name)
    for service in services:
        if searchme.search(service.name) is not None:
            print '\n', service
    

if __name__ == '__main__':
    parser = ArgumentParser(description="Firewall")
    
    subparsers = parser.add_subparsers()
    #upgrade
    parser_upgrade = subparsers.add_parser('upgrade', help='Upgrade generated script if base script has been modified')
    parser_upgrade.set_defaults(func=upgrade)
    #addclient parser
    parser_addclient = subparsers.add_parser('addclient', help='Add client')
    parser_addclient.add_argument("identifier", metavar='IDENTIFIER', help='Client identifier to be added')
    parser_addclient.add_argument("macs", nargs='+', metavar='MAC', help='MAC address(es) of the client to be added')
    parser_addclient.add_argument("-o", "--open-all-ports", dest='open_all_ports', action='store_true', help='If this option is set, the firewall open all ports for the client')
    parser_addclient.set_defaults(func=addclient)
    #delclient parser
    parser_delclient = subparsers.add_parser('delclient', help='Delete MAC address(es) of a client, if no MAC adresse specified, delete the client')
    parser_delclient.add_argument("identifier", metavar='IDENTIFIER', help='Client identifier to be deleted')
    parser_delclient.add_argument("macs", nargs='*', metavar='MAC', help='MAC address(es) of the client to be deleted')
    parser_delclient.set_defaults(func=delclient)
    #disclient parser
    parser_disclient = subparsers.add_parser('disclient', help='Disable a client without deleting him')
    parser_disclient.add_argument("identifier", metavar='IDENTIFIER', help='Client identifier to be disabled')
    parser_disclient.set_defaults(func=disclient)
    #enclient parser
    parser_enclient = subparsers.add_parser('enclient', help='Enable a disabled client')
    parser_enclient.add_argument("identifier", metavar='IDENTIFIER', help='Client identifier to be enabled')
    parser_enclient.set_defaults(func=enclient)
    #addservice parser
    parser_addservice = subparsers.add_parser('addservice', help='Add a service with a list of ports for the all the clients')
    parser_addservice.add_argument("-p", "--protocol", choices=['tcp','udp'], default='tcp')
    parser_addservice.add_argument("-t", "--type", choices=['external','internal'], default='external')
    parser_addservice.add_argument("-r", "--restricted", action='store_true')
    parser_addservice.add_argument("service", metavar='SERVICE', help='Service identifier')
    parser_addservice.add_argument("ports", metavar='PORTS', help='Comma separated list of ports, or range of ports (colon separated). ex: 1,4,12:33,90. Limited to 15 ports (range just count for two).')
    parser_addservice.set_defaults(func=addservice)
    #delservice parser
    parser_delservice = subparsers.add_parser('delservice', help='Delete a service')
    parser_delservice.add_argument("-p", "--protocol", choices=['tcp','udp','both'], default='both')
    parser_delservice.add_argument("-t", "--type", choices=['external','internal'], default='external')
    parser_delservice.add_argument("-r", "--restricted", action='store_true')
    parser_delservice.add_argument("service", metavar='SERVICE', help='Service identifier')
    parser_delservice.set_defaults(func=delservice)
    #list parser
    parser_list = subparsers.add_parser('list', help='List informations on clients and services')
    subparser_list = parser_list.add_subparsers()
    #list wan parser
    parser_list_wan = subparser_list.add_parser('wan', help='List WAN parameters')
    parser_list_wan.set_defaults(func=list_wan)
    #list lan parser
    parser_list_wan = subparser_list.add_parser('lan', help='List LAN parameters')
    parser_list_wan.set_defaults(func=list_lan)
    #list services parser
    parser_list_services = subparser_list.add_parser('services', help='List all services')
    parser_list_services.set_defaults(func=list_services)
    #list clients parser
    parser_list_clients = subparser_list.add_parser('clients', help='List all clients')
    parser_list_clients.set_defaults(func=list_clients)
    #list all parser
    parser_list_all = subparser_list.add_parser('all', help='List all clients and services')
    parser_list_all.set_defaults(func=list_all)
    #info parser
    parser_info = subparsers.add_parser('info', help='Get informations on designated service or client')
    parser_info.add_argument("clientorservice", metavar='CLIENT | SERVICE', help='Client or Service identifier')
    parser_info.set_defaults(func=info)
    
    args = parser.parse_args()
    script = Script()
    if script.parse():
        args.func(args, script)
    else:
        del script
        script = Script()
        if script.parse():
            args.func(args, script)
        else:
            print "Gnnnn !"
