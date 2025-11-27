# ics-scada-fuzzer

**Single-file, zero-dependency fuzzer for core ICS/OT protocols**  
Modbus/TCP • DNP3 • S7comm • IEC 60870-5-104

Born out of real red-team and research engagements.  
No build system. No Python. Just `gcc && go`.

```bash
gcc -O2 -pthread -o ics-fuzzer ics_fuzzer.c -lcrypto -lz
./ics-fuzzer -t 192.168.1.100 -p modbus -i 50000 -T 16 -m 0.06
```
### Features
- Works offline / air-gapped (common in OT)
- Stateful + stateless modes
- Protocol-aware mutation + correct CRC/length recalculation
- Built-in OT-specific dictionary & boundary values
- Crash verification (reconnect test)
- 8 mutation strategies (random, bitflip, overflow, dictionary, format-string, type confusion, time-based, sequence violation)
- Live stats + detailed log of every anomaly

### Supported protocols & default ports

| Protocol            | Port  | Notes                                      |
|---------------------|-------|--------------------------------------------|
| Modbus/TCP          | 502   | Fully stateful capable                     |
| DNP3                | 20000 | Correct CRC16 + link/application layer     |
| S7comm              | 102   | Siemens S7-300/400/1200/1500               |
| IEC 60870-5-104     | 2404  | Full APCI handling                         |

### Quick examples
```bash
# Aggressive Modbus fuzzing
./ics-fuzzer -t 10.10.20.50 -i 100000 -T 32 -m 0.1 -s overflow

# Stateful DNP3 sequence violation campaign
./ics-fuzzer -t 10.10.30.20 -P 20000 -p dnp3 -S -s sequence -i 20000

# IEC104 format-string attempts
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

### Disclaimer
For authorized security testing only.
OT environments control physical processes. Never use without explicit permission.


License
------------------------

This project is licensed under the [MIT License](LICENSE).

> Use this software **only** in environments you **own** or have **explicit authorization** to test.
> Misuse of this tool is illegal and unethical.
