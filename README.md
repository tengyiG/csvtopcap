# csvtopcap
This repository includes a simple script translating the csv files into pcap files within outer ether, outer ip, and outer udp.

# Prerequisites
* The csv files must include these titles at the first row: src_ip, dst_ip, src_port, and dst_port.
* The csv files must exist, otherwise no pcap files will be generated.

# Args
* csv_file: if not providing this, this script will automatically translate all csv files under current directory.
* pcap_file: without providing this, pcap file names will be the same as csv file names: e.g., my_csv_file.csv -> my_csv_file_part(1/2/3/4/5).pcap. The length of the pcap file list (if provided) must be the same as the length of csv_file list. At least part1 pcap file will be generated.
* src_mac: without providing this, it is "00:11:22:33:44:55" by default.
* dst_mac: without providing this, it is "55:44:33:22:11:00" by default.
* flow_label: it is by default "False", if you want to generate flow label within the ipv6 headers, set it as "True", and random 20 bits of flow label will be generated within the ipv6 header.
* eth_type_ipv4: a fixed value of 0x0800
* eth_type_ipv6: a fixed value of 0x86DD
* max_file_size: the max file size in MB, by default it is 500 MB. If a file is generated larger than 500 MB, then the my_pcap_file_part2.pcap will be generated.
* imix: it is by default "False". When it is False, fixed payload size of 1472 will be generated. If imix is set to True, payload sizes will be randomly generated such that:
    * the first 5% of the row packets will be generated with randomly generated payload size within the range [64, 256)
    * the following 5% of the packets will generated with randomly generated payload size within the range [256, 1024)
    * the following 10% of the packets will generated with randomly generated payload size within the range [1024, 2048)
    * the following 20% of the packets will generated with randomly generated payload size within the range [2048, 4192)
    * the following 20% of the packets will generated with randomly generated payload size within the range [4192, 9001)
    * the following 40% of the packets will generated with randomly generated payload size of 9001

# Usage
```bash
python3 csv_to_pcap.py --csv_file test.csv test2.csv --pcap_file test.pcap test2.pcap --imix True --max_file_size 300 --flow_label True --src_mac 22:11:33:44:55:00 --dst_mac 44:55:11:22:33:00
```

Print outs:
```
--flow_label is activated
--imix is activated
Max file size: 300
Processing test.csv -> test_part1.pcap
PCAP file saved as test_part1.pcap
Processing test.csv -> test_part2.pcap
PCAP file saved as test_part2.pcap
Processing test2.csv -> test2_part1.pcap
PCAP file saved as test2_part1.pcap
Processing test2.csv -> test2_part2.pcap
PCAP file saved as test2_part2.pcap
```

# Performance
For a csv file which is 10 MB, expect this script to run at least 1 minute to generate the pcap file. Expect 2 minutes for 10-MB-sized csv file if you are going to generate flow label and imix.

