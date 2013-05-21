#!/usr/bin/env python
import argparse
import logging
import sys
import logging.handlers
import math
import socket
import struct
import subprocess
import re
import binascii
import select
import json
import random

import gevent.monkey
import dpkt


LOGGER = logging.getLogger('fqlan')

LAN_INTERFACE = None
IFCONFIG_PATH = None
RE_IFCONFIG_IP = re.compile(r'inet addr:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
RE_MAC_ADDRESS = re.compile(r'[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+')
ETH_ADDR_BROADCAST = '\xff\xff\xff\xff\xff\xff'
ETH_ADDR_UNSPEC = '\x00\x00\x00\x00\x00\x00'


def main():
    global LAN_INTERFACE
    global IFCONFIG_PATH

    gevent.monkey.patch_all()
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument('--log-file')
    argument_parser.add_argument('--log-level', choices=['INFO', 'DEBUG'], default='INFO')
    argument_parser.add_argument('--lan-interface', default='eth0')
    argument_parser.add_argument('--ifconfig-path')
    sub_parsers = argument_parser.add_subparsers()
    scan_parser = sub_parsers.add_parser('scan', help='scan LAN devices')
    scan_parser.add_argument('ip', help='ipv4 address', nargs='+')
    scan_parser.set_defaults(handler=scan)
    args = argument_parser.parse_args()
    LAN_INTERFACE = args.lan_interface
    IFCONFIG_PATH = args.ifconfig_path
    log_level = getattr(logging, args.log_level)
    logging.basicConfig(stream=sys.stdout, level=log_level, format='%(asctime)s %(levelname)s %(message)s')
    if args.log_file:
        handler = logging.handlers.RotatingFileHandler(
            args.log_file, maxBytes=1024 * 256, backupCount=0)
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        handler.setLevel(log_level)
        logging.getLogger('fqlan').addHandler(handler)
    args.handler(**{k: getattr(args, k) for k in vars(args) \
                    if k not in {'handler', 'log_file', 'log_level', 'lan_interface', 'ifconfig_path'}})


def scan(ip):
    my_ip, my_mac = get_ip_and_mac()
    if not my_ip:
        return
    if not my_mac:
        return
    sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
    try:
        sock.bind((LAN_INTERFACE, dpkt.ethernet.ETH_TYPE_ARP))
        for ip in list_ip(ip):
            send_arp_request(sock, my_mac, my_ip, ip)
        count = 0
        found_set = set()
        while True:
            ins, outs, errors = select.select([sock], [], [sock], timeout=1)
            if errors:
                raise Exception('socket error: %s' % errors)
            if ins:
                found_ip, found_mac = receive_arp_reply(ins[0])
                if my_ip != found_ip and (found_ip, found_mac) not in found_set:
                    found_set.add((found_ip, found_mac))
                    sys.stderr.write(json.dumps([found_ip, found_mac]))
                    sys.stderr.write('\n')
            else:
                count += 1
                if count > 3: # no response for 3 seconds
                    break
    finally:
        sock.close()


def send_arp_request(sock, my_mac, my_ip, request_ip):
    arp = dpkt.arp.ARP()
    arp.sha = eth_aton(my_mac)
    arp.spa = socket.inet_aton(my_ip)
    arp.tha = ETH_ADDR_UNSPEC
    arp.tpa = socket.inet_aton(request_ip)
    arp.op = dpkt.arp.ARP_OP_REQUEST
    eth = dpkt.ethernet.Ethernet()
    eth.src = arp.sha
    eth.dst = ETH_ADDR_BROADCAST
    eth.data = arp
    eth.type = dpkt.ethernet.ETH_TYPE_ARP
    sock.send(str(eth))


def receive_arp_reply(sock):
    eth = dpkt.ethernet.Ethernet(sock.recv(8192))
    arp = eth.data
    return socket.inet_ntoa(arp.spa), eth_ntoa(arp.sha)


def eth_aton(mac):
    sp = mac.split(':')
    mac = ''.join(sp)
    return binascii.unhexlify(mac)


def eth_ntoa(mac):
    return binascii.hexlify(mac)


def list_ip(ip_list):
    ip_set = set()
    for ip in ip_list:
        if '/' in ip:
            start_ip, _, netmask = ip.partition('/')
            netmask = int(netmask)
            if netmask < 24:
                raise Exception('only support /24 or smaller ip range')
            start_ip_as_int = ip_to_int(start_ip)
            for i in range(int(math.pow(2, 32 - netmask))):
                ip_set.add(start_ip_as_int + i)
        else:
            ip_set.add(ip_to_int(ip))
    for j in range(2): # repeat the random scan twice
        ip_list = list(ip_set)
        done = False
        while not done:
            for i in range(32):
                if not ip_list:
                    done = True
                    break
                ip_as_int = random.choice(ip_list) # random scan for apple device
                ip_list.remove(ip_as_int)
                yield int_to_ip(ip_as_int)
            gevent.sleep(0.1)

def ip_to_int(ip):
    return struct.unpack('!i', socket.inet_aton(ip))[0]


def int_to_ip(ip_as_int):
    return socket.inet_ntoa(struct.pack('!i', ip_as_int))


def get_ip_and_mac():
    try:
        if IFCONFIG_PATH:
            output = subprocess.check_output(
                [IFCONFIG_PATH, 'ifconfig' if 'busybox' in IFCONFIG_PATH else '', LAN_INTERFACE],
                stderr=subprocess.STDOUT)
        else:
            output = subprocess.check_output('ifconfig %s' % LAN_INTERFACE, stderr=subprocess.STDOUT, shell=True)
        output = output.lower()
        match = RE_MAC_ADDRESS.search(output)
        if match:
            mac = match.group(0)
        else:
            mac = None
        match = RE_IFCONFIG_IP.search(output)
        if match:
            ip = match.group(1)
        else:
            ip = None
        return ip, mac
    except subprocess.CalledProcessError, e:
        LOGGER.error('failed to get ip and mac: %s' % e.output)
        return None, None
    except:
        LOGGER.exception('failed to get ip and mac')
        return None, None


if '__main__' == __name__:
    main()