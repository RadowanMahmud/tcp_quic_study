# Performance Study of QUIC over Cellular Network

### Setup the environment

1. Create 3 VMs (Ubuntu 22.04 LTS was used originally)
2. Setup Routing
   => Enable ip forwarding -
   ```bash
   sudo sysctl -w net.ipv4.ip_forward=1
   ```
   => Make a VM a router between the two, setup routes such that all the traffic goes through that VM
   ```bash
   sudo ip route add <destination_network> via <gateway_ip> dev <interface>
   ```
3. Setup bandwidth limit at the VM acting as router
   ```bash
   sudo tc qdisc add dev <interface> root tbf rate <rate> burst 10kb latency <latency>
   ```

### Build Quiche

```bash
cargo build --examples --features qlog
```

### Steps to run:

Start a http3-server:

```bash
 cd quiche/quiche
 ../target/debug/examples/http3-server cca
```

(N.B: Files inside examples/root are served by the server)

Run the client:

   ```bash
   cd quiche/quiche
   QLOGDIR=. ../target/debug/examples/http3-client http://192.168.122.33:4433/sample.txt cubic > /dev/null
   ```

N.B: Last argument can be: cubic/reno/bbr/bbr2

### Simulating mobile network:

```bash
git clone https://github.com/williamsentosa95/cellreplay.git
cd cellReplay
mm-cellular 8 traces/tmobile/driving/up-delay-light-pdo traces/tmobile/driving/down-delay-light-pdo \
traces/tmobile/driving/up-heavy-pdo traces/tmobile/driving/down-heavy-pdo \
--psize-latency-offset-up=traces/tmobile/driving/latency-offset-up \
--psize-latency-offset-down=traces/tmobile/driving/latency-offset-down
```
