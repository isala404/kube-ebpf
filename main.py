from kube_crawler import poll_kube_api
from prometheus_client import start_http_server
from prober import probe
import threading
import time

print("Starting prometheus web server at :8000")
start_http_server(8000)

# Start Pollinng Kubernetes and ebpf maps in the background
kube_thrd = threading.Thread(target=poll_kube_api, args=())
ebpf_thrd = threading.Thread(target=probe, args=())

kube_thrd.daemon = True
kube_thrd.start()

ebpf_thrd.daemon = True
ebpf_thrd.start()

# Check of both processes are running
while kube_thrd.is_alive() and ebpf_thrd.is_alive():
    time.sleep(5)

if not kube_thrd.is_alive():
    print("kube api thread exited")

if not ebpf_thrd.is_alive():
    print("ebpf thread exited")
