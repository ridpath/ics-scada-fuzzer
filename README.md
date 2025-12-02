<!--
ICS SCADA fuzzer, industrial control system security testing, OT protocol fuzzer,
Modbus TCP exploit research, DNP3 fuzz testing, IEC 60870-5-104 fuzzing tool,
OPC-UA fuzz tool cybersecurity, S7comm protocol security testing,
industrial automation penetration testing, critical infrastructure cyber assessment,
water treatment SCADA fuzzing, power grid cyber attack simulation,
ICS protocol mutation engine, cyber physical system exploitation,
PLC logic manipulation detection, OT blue team validation toolkit,
industrial protocol anomaly testing, fuzzing safety system protocols,
substation protocol fuzzing tool, OT penetration testing lab tool,
ICS cyber range testing utility, ridpath GitHub research tools,
critical infrastructure malware research, protocol-aware fuzzing engine,
ICS vulnerability discovery platform, exploit dev for OT systems,
authorized security testing only
-->

# ICS-SCADA-Fuzzer  
Protocol Aware Industrial Control System Mutation Testing Toolkit

![status: alpha](https://img.shields.io/badge/status-alpha-yellow)
![stability: experimental](https://img.shields.io/badge/stability-experimental-orange)
![license: MIT](https://img.shields.io/badge/license-MIT-blue)
![domain: ICS/OT](https://img.shields.io/badge/domain-ICS%20%7C%20OT-critical)
![detection: SIEM-tested](https://img.shields.io/badge/tested-SIEM%20integration-lightgrey)


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

## MITRE ATT&CK ICS Mapping

| Technique | ID |
|---------|--------|
| Modify Controller Tasking | T0858 |
| Manipulate I/O Points | T0831 |
| Impair Process Control | T0828 |
| Valid Protocol Abuse | T0843 |
| Protocol Data Manipulation | T0837 |
| Exploit ICS Protocols | T0861 |
| Denial of Control | T0813 |

> Mapping aligns to **MITRE ATT&CK for ICS v13**

## Safety Notice

Industrial equipment controls **physical processes**:

- Safety relay trips  
- Pump/generator mis-operation  
- Arc-flash hazards  
- Loss of cooling / overpressure conditions

**Never** run against:
- Production OT networks
- Real utilities without change controls
- Anything without explicit written authorization

This tool is for:
- Testbeds  
- ICS cyber ranges  
- Blue/red research labs  
- PLC simulators  

### Disclaimer
For authorized security testing only.
OT environments control physical processes. Never use without explicit permission.


License
------------------------

This project is licensed under the [MIT License](LICENSE).

> Use this software **only** in environments you **own** or have **explicit authorization** to test.
> Misuse of this tool is illegal and unethical.
<!--
ICS fuzzing engine, protocol exploitation toolkit, anomaly detection ICS,
Modbus DNP3 S7 fuzzing tool download, air gapped OT red team tool,
PLC fuzzing research, IEC-104 cybersecurity, OPC-UA node exploitation,
industrial cybersecurity advanced tooling, ICS asset resilience testing,
OT protocol fuzz mutation strategies, critical infrastructure cyber defense,
suricata zeek detection testing feeds, SIEM alert validation toolkit,
fuzz testing safety systems, ICS malware resilience testing
-->
