# csvtopcap
This repository includes a simple script translating the csv files into pcap files within outer ether, outer ip, and outer udp.

# Prerequisites
* The csv files must include these titles at the first row: src_ip, dst_ip, src_port, and dst_port.
* The csv files must exist, otherwise no pcap files will be generated.

# Args
* csv_file: if not providing this, this script will automatically translate all csv files under current directory.
* pcap_file: without providing this, pcap file names will be the same as csv file names: e.g., my_csv_file.csv -> my_csv_file.pcap. The length of the pcap file list (if provided) must be the same as the length of csv_file list.
* src_mac: without providing this, it is "00:11:22:33:44:55" by default.
* dst_mac: without providing this, it is "55:44:33:22:11:00" by default.
* flow_label: it is by default "false", if you want to generate flow label within the ipv6 headers, set it as "true", and random 20 bits of flow label will be generated within the ipv6 header.
* eth_type_ipv4: a fixed value of 0x0800
* eth_type_ipv6: a fixed value of 0x86DD
* payload_size: the payload size. By defualt it is 1472 bytes, that makes the packet (l3) size 1500 bytes and framesize (l2) as 1514 bytes.

# Usage
python3 csv_to_pcap.py --csv_file my_csv1.csv my_csv2.csv --pcap_file my_pcap1.pcap my_pcap2.pcap --src_mac 22:11:33:44:55:00 --dst_mac 44:55:11:22:33:00 --flow_label true
