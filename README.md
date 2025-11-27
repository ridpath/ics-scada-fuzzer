# ics-scada-fuzzer

**Single-file fuzzer for core ICS/OT protocols**  
Modbus/TCP • DNP3 • S7comm • IEC 60870-5-104 • OPC-UA

### Usage

#### Dependencies
- `libpcap-dev` - Packet capture library
- `libssl-dev` - OpenSSL for cryptographic functions  
- `zlib1g-dev` - Compression library

#### Install dependencies (Debian/Ubuntu)
```bash
sudo apt update
sudo apt install libpcap-dev libssl-dev zlib1g-dev
```
Compile
```bash
gcc -O2 -pthread -o ics-fuzzer ics_fuzzer.c -lpcap -lcrypto -lz
```
Test against a target
```bash
./ics-fuzzer -t 192.168.1.100 -p modbus -i 1000 -T 4 -v
```


### Features
- Works offline / air-gapped (common in OT)
- Stateful + stateless modes
- Protocol-aware mutation + correct CRC/length recalculation
- Built-in OT-specific dictionary & boundary values
- Crash verification (reconnect test)
- 8 mutation strategies (random, bitflip, overflow, dictionary, format-string, type confusion, time-based, sequence violation)
- Live stats + detailed log of every anomaly
- PCAP recording & replay for traffic analysis and corpus generation
- OPC-UA protocol support for industrial data exchange
- Enhanced crash detection with protocol-specific anomaly signatures
- Thread-safe atomic operations for stable multi-threading

### Supported protocols & default ports

| Protocol            | Port  | Notes                                      |
|---------------------|-------|--------------------------------------------|
| Modbus/TCP          | 502   | Fully stateful capable                     |
| DNP3                | 20000 | Correct CRC16 + link/application layer     |
| S7comm              | 102   | Siemens S7-300/400/1200/1500               |
| IEC 60870-5-104     | 2404  | Full APCI handling                         |
|OPC-UA    | 4840  | OPC Unified Architecture                         |

### Quick examples
```bash
# OPC-UA fuzzing with dictionary attacks
./ics-fuzzer -t 192.168.2.50 -P 4840 -p opcua -s dictionary -i 8000 -T 8

# Record traffic to PCAP for analysis
./ics-fuzzer -t 192.168.1.100 -p modbus -i 10000 -R modbus_fuzz.pcap

# Replay from PCAP with mutation
./ics-fuzzer -t 192.168.1.100 -p modbus -r replay.pcap

# Aggressive Modbus fuzzing
./ics-fuzzer -t 10.10.20.50 -i 100000 -T 32 -m 0.1 -s overflow

# Stateful DNP3 sequence violation  
./ics-fuzzer -t 10.10.30.20 -p dnp3 -S -s sequence -i 20000

# IEC104 with format string attacks
./ics-fuzzer -t 10.10.40.15 -p iec104 -s format -T 20
```
### Full options
| Option           | Parameter                         | Description                                      |
|------------------|-----------------------------------|--------------------------------------------------|
| `-t`             | `<ip>`                            | Target IP                                        |
| `-P`             | `<port>`                          | Port (overrides default)                         |
| `-p`             | `modbus \| dnp3 \| s7 \| iec104`  | Protocol to fuzz                                 |
| `-i`             | `<n>`                             | Iterations per thread                            |
| `-m`             | `<0.0-1.0>`                       | Mutation rate                                    |
| `-s`             | `random \| bitflip \| overflow \| dictionary \| format \| type \| time \| sequence` | Mutation strategy |
| `-T`             | `<1-64>`                          | Number of threads (max 64)                       |
| `-S`             | —                                 | Enable stateful mode                             |
| `-d`             | `<ms>`                            | Delay between packets (milliseconds)             |
| `-v`             | —                                 | Verbose output                                   |
| `-l`             | `<file>`                          | Log file (default: `ics_fuzzer.log`)             |
| `-h`             | —                                 | Show help                                        |
| `-R`             | `<file.pcap>`                     | Record traffic to PCAP file                      |
| `-r`             | `<file.pcap>`                     | Replay from PCAP file                            |
| `-p`             | `modbus \| dnp3 \| s7 \| iec104 \| opcua`  | Protocol to fuzz |

### Disclaimer
For authorized security testing only.
OT environments control physical processes. Never use without explicit permission.


License
------------------------

This project is licensed under the [MIT License](LICENSE).

> Use this software **only** in environments you **own** or have **explicit authorization** to test.
> Misuse of this tool is illegal and unethical.
