from bcc import BPF
from bcc.containers import filter_by_containers
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import sleep, strftime
from kube_crawler import get_metadata, poll_kube_api
from prometheus_client import Histogram, Counter, Gauge
import threading
import os


ms = Histogram("request_duration_seconds", "TCP event latency", ["namespace", "name", "port"])
tx_kb = Histogram("transmitted_bytes", "Number of sent bytes during TCP event", ["namespace", "name"])
rx_kb = Histogram("acknowledged_bytes", "Number of received bytes during TCP event", ["namespace", "name", "port"])
request_sent = Counter("requests_sent", "Total request sent", ["namespace", "name"])
request_received = Counter("requests_received", "Total request received", ["namespace", "name", "port"])


# define BPF program
with open('prober.c', 'r') as f:
    bpf_text = f.read()

args = lambda: None
args.cgroupmap = None
args.mntnsmap = None

bpf_text = filter_by_containers(args) + bpf_text

# initialize BPF
b = BPF(text=bpf_text)

DEBUG = os.getenv("DEBUG", False)


def process_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)

    dataDict = {
        "source_ip": inet_ntop(AF_INET, pack("I", event.saddr)),
        "source_port": event.lport,
        "destination_ip": inet_ntop(AF_INET, pack("I", event.daddr)),
        "destination_port": event.dport,
        "transmit_bytes": int(event.tx_b),
        "receive_bytes": int(event.rx_b),
        "duration": float(event.span_us) / 1000
    }

    if DEBUG:
        print(dataDict)

    update_metrics(dataDict)

def process_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)

    dataDict = {
        "source_ip": inet_ntop(AF_INET6, event.saddr),
        "source_port": event.lport,
        "destination_ip": inet_ntop(AF_INET6, event.daddr),
        "destination_port": event.dport,
        "transmit_bytes": int(event.tx_b),
        "receive_bytes": int(event.rx_b),
        "duration": float(event.span_us) / 1000,
    }

    if DEBUG:
        print(dataDict)

    update_metrics(dataDict)

def update_metrics(data):
    source = get_metadata(data['source_ip'])
    destination = get_metadata(data['destination_ip'])

    if source is None and destination is None:
        return

    if source is not None:
        request_sent.labels(source['namespace'], source['name']).inc()
        tx_kb.labels(source['namespace'], source['name']).observe(data['transmit_bytes'])

    if destination is not None:
        request_received.labels(destination['namespace'], destination['name'], data['destination_port']).inc()
        rx_kb.labels(destination['namespace'], destination['name'], data['destination_port']).observe(data['receive_bytes'])
        ms.labels(destination['namespace'], destination['name'], data['destination_port']).observe(data['duration'])


# read events
b["ipv4_events"].open_perf_buffer(process_ipv4_event, page_cnt=64)
b["ipv6_events"].open_perf_buffer(process_ipv6_event, page_cnt=64)


def probe():
    print("Started polling eBPF data buffer")
    while 1:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()