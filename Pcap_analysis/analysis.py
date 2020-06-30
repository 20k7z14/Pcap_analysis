import os
import sys
import pandas as pd

import pre_process as pre
import scatter as sc

TMP_CSV_FILE = '../pcap_csv/tmp'
COLUMN_NAME = [
    "date",
    # geoip data
    "country",      "iso_code",     "ASN",
    # ip
    "ip_version",   "ip_ihl",       "ip_tos",
    "ip_len",       "ip_id",        "ip_flags",
    "ip_frag",      "ip_ttl",       "ip_proto",
    "ip_src",       "ip_dst",       "ip_options",
    # transport layer
    "l4_sport",     "l4_dport",
    # tcp
    "tcp_seq",      "tcp_ack",      "tcp_dataofs",
    "tcp_flags",    "tcp_window",   "tcp_options",
    # udp
    "udp_len",
    # icmp
    "icmp_type",    "icmp_code",
    "icmp_id",      "icmp_seq",
    # raw data
    "raw",
]

if __name__ == '__main__':
    args = sys.argv
    if args[1] == '-c': #TODO extract condition after args[2]
        directory_path,column,value = args[2],args[3],args[4]

        if os.path.exists(TMP_CSV_FILE):
            pre.extract_csv(directory_path,column,value)
        else:
            os.mkdir(TMP_CSV_FILE)
            pre.extract_csv(directory_path,column,value)

    elif args[1] == '-show':
        path, xlabel, ylabel = args[3], args[4], args[5]

        if args[2] == '-ip': # individual
            chart = sc.Scatter(path, xlabel, ylabel)
            chart.singleFlatScatter()

        # elif args[2] == '-all':
        #     chart = sc.Scatter(path, xlabel, ylabel, ip)
        #     chart.quadFlatScatter()
