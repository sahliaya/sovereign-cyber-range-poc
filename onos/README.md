# ONOS controller setup

The PoC uses ONOS running in a Docker container, reachable at
`127.0.0.1:6653` (OpenFlow) and `127.0.0.1:8181` (REST API, credentials
`onos`/`rocks` by default).

```bash
docker run -d --name onos -p 6653:6653 -p 8181:8181 -p 8101:8101 onosproject/onos
```

Wait for the REST API to come up (can take 30-60s on first boot):

```bash
until curl -s -o /dev/null -w '%{http_code}' -u onos:rocks \
  http://127.0.0.1:8181/onos/v1/devices | grep -q 200; do sleep 5; done
```

The device list will be empty until Mininet starts and the switch connects
(see `../mininet/start_topology.sh`).
