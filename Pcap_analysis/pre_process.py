import os
import glob
import pandas as pd
from tqdm import tqdm

COMMON_CSV_PATH = '../pcap_csv'
TARGET_CSV_PATH = '../pcap_csv/target'

COLUMN_NAME = (
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
)

def extract_csv(directory, col,val):
    filepaths = glob.glob(f'{directory}/*.csv')
    output = pd.DataFrame()
    for p in tqdm(filepaths):
        df = pd.read_csv(p,names=COLUMN_NAME)
        output = pd.concat([output,df[df[col]==val]])

    val = val.replace(':','_')
    output.to_csv(f'{directory}_{val}.csv')

