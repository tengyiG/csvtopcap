import argparse
import glob
import os
import random
import re
import socket
import pandas as pd
from scapy.all import Ether, IP, IPv6, PcapWriter, UDP

eth_type_ipv6 = 0x86DD
eth_type_ipv4 = 0x0800
packets = []


def parse_arguments():
  parser = argparse.ArgumentParser(description='Process some files.')
  parser.add_argument(
      '--csv_file', type=str, nargs='*', help='CSV file(s) to process'
  )
  parser.add_argument(
      '--pcap_file', type=str, nargs='*', help='PCAP file(s) to save'
  )
  parser.add_argument(
      '--src_mac',
      type=str,
      default='00:11:22:33:44:55',
      help='Source MAC address',
  )
  parser.add_argument(
      '--dst_mac',
      type=str,
      default='55:44:33:22:11:00',
      help='Destination MAC address',
  )
  parser.add_argument(
      '--flow_label',
      type=str,
      default='false',
      help='Whether to generate flow label',
  )
  parser.add_argument(
      '--payload_size',
      type=str,
      default='1472',
      help='Payload',
  )
  return parser.parse_args()


def is_valid_ipv4(ip):
  try:
    socket.inet_pton(socket.AF_INET, ip)
    return True
  except socket.error:
    return False


def is_valid_ipv6(ip):
  try:
    socket.inet_pton(socket.AF_INET6, ip)
    return True
  except socket.error:
    return False


def is_valid_mac(mac):
  if re.match('[0-9a-f]{2}(:[0-9a-f]{2}){5}$', mac.lower()):
    return True
  else:
    return False


def generate_flow_label():
  return random.getrandbits(20)


def process_csv_and_pcap_files(args):
  if args.csv_file:
    csv_files = args.csv_file
    for csv_file in csv_files:
      if not csv_file.endswith('.csv'):
        raise ValueError(f'Invalid CSV file: {csv_file}. Must end with .csv')
    if args.pcap_file:
      pcap_files = args.pcap_file
      for pcap_file in pcap_files:
        if not pcap_file.endswith('.pcap'):
          raise ValueError(
              f'Invalid PCAP file: {pcap_file}. Must end with .pcap'
          )
      if len(csv_files) != len(pcap_files):
        raise ValueError(
            'The number of CSV files must match the number of PCAP files.'
        )
    else:
      pcap_files = [
          f'{os.path.splitext(csv_file)[0]}.pcap' for csv_file in csv_files
      ]
  else:
    csv_files = glob.glob('*.csv')
    pcap_files = [
        f'{os.path.splitext(csv_file)[0]}.pcap' for csv_file in csv_files
    ]

  return csv_files, pcap_files


def validate_mac_addresses(args):
  if not is_valid_mac(args.src_mac):
    print(
        f'Invalid src_mac provided: {args.src_mac}. Using default:'
        ' 00:11:22:33:44:55'
    )
    args.src_mac = '00:11:22:33:44:55'

  if not is_valid_mac(args.dst_mac):
    print(
        f'Invalid dst_mac provided: {args.dst_mac}. Using default:'
        ' 55:44:33:22:11:00'
    )
    args.dst_mac = '55:44:33:22:11:00'


def process_files(csv_files, pcap_files, args):
  for csv_file, pcap_file in zip(csv_files, pcap_files):
    if not os.path.exists(csv_file):
      print(f'This CSV file {csv_file} does not exist')
      continue

    print(f'Processing {csv_file} -> {pcap_file}')
    df = pd.read_csv(csv_file)

    for index, row in df.iterrows():
      outer_src_ip = row['src_ip']
      outer_dst_ip = row['dst_ip']
      outer_src_port = row['src_port']
      outer_dst_port = row['dst_port']

      if is_valid_ipv6(outer_src_ip) and is_valid_ipv6(outer_dst_ip):
        outer_ether = Ether(
            src=args.src_mac, dst=args.dst_mac, type=eth_type_ipv6
        )
        flow_label: int = 0
        if args.flow_label == 'true':
          flow_label = generate_flow_label()
        outer_ip = IPv6(src=outer_src_ip, dst=outer_dst_ip, fl=flow_label)
      elif is_valid_ipv4(outer_src_ip) and is_valid_ipv4(outer_dst_ip):
        outer_ether = Ether(
            src=args.src_mac, dst=args.dst_mac, type=eth_type_ipv4
        )
        outer_ip = IP(src=outer_src_ip, dst=outer_dst_ip)
      else:
        print(
            f'Invalid outer IP address at row {index}: src_ip={outer_src_ip},'
            f' dst_ip={outer_dst_ip}'
        )
        continue

      if not pd.isna(outer_src_port) and not pd.isna(outer_dst_port):
        outer_udp = UDP(sport=int(outer_src_port), dport=int(outer_dst_port))
      else:
        print(
            f'Invalid outer UDP port at row {index}: src_port={outer_src_port},'
            f' dst_port={outer_dst_port}'
        )
        continue

      packet = outer_ether / outer_ip / outer_udp / '0'*int(args.payload)
      packets.append(packet)

    writer = PcapWriter(pcap_file, append=True, sync=True)
    for pkt in packets:
      writer.write(pkt)
    writer.close()

    print(f'PCAP file saved as {pcap_file}')


def main():
  args = parse_arguments()
  csv_files, pcap_files = process_csv_and_pcap_files(args)
  validate_mac_addresses(args)
  process_files(csv_files, pcap_files, args)


if __name__ == '__main__':
  main()
