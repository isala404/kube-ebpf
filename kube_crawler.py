import time
import requests
import os

# Read the token from kubernetes runtime mount
with open('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r') as f:
    token = f.read()

KUBERNETES_SERVICE_HOST = os.getenv('KUBERNETES_SERVICE_HOST')
KUBERNETES_PORT_443_TCP_PORT = os.getenv('KUBERNETES_PORT_443_TCP_PORT')
NODE_NAME = os.getenv('NODE_NAME')
DEBUG = os.getenv("DEBUG", False)


pods_list = {}


def get_metadata(ip):
    if ip in pods_list:
        return pods_list[ip]
    else:
        None

def poll_kube_api():
    print("Started polling Kubernetes API")

    while True:

        # Query Kubernetes API with a fieldSelector to scope to the pod
        r = requests.get(f"https://{KUBERNETES_SERVICE_HOST}:{KUBERNETES_PORT_443_TCP_PORT}/api/v1/pods?fieldSelector=spec.nodeName={NODE_NAME}", headers={'Authorization': f'Bearer {token}'},  verify="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")

        try:
            data = r.json()
            pods_list_ = {}

            # for each pod update the hashmap with the key as the pod IP
            # and namespace and name as the value, so we can easily query 
            # the pod data by IP
            for item in data['items']:
                pods_list_[item['status']['podIP']] = {
                    'namespace': item['metadata']['namespace'],
                    'name': item['metadata']['name']
                }

            global pods_list
            pods_list = pods_list_

            print(f"{len(pods_list)} pods are monitored by the agent")
            if DEBUG:
                print(pods_list)

        except:
            print("Error while reading data from kube api")
            print(r.text)
            return

        time.sleep(10)