# ShieldNet Gateway — edge performance datasheet

_Generated (unix): `1781107067` · commit `6c6406bdfa8c394d9aad18e7c496d9148f519026` · all SNG figures measured by the `sng-bench` harness._

Every throughput figure is reported in two columns:

- **dry-run** — the in-process craft+measure+report pipeline with no NIC in the loop (the synthetic ceiling; runs on any CI runner).
- **wire** — real `AF_PACKET` frames transmitted over a veth pair with `sng-edge` enforcing in-path under `CAP_NET_RAW` on the self-hosted `sng-bench-wire` runner (the measured line-rate floor).


## Executive summary

| SKU | vCPU | RAM | NIC | target | firewall dry-run | firewall wire | inspected dry-run | inspected wire | meets target (wire) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :---: |
| large | 16 | 32 GB | 50 Gbps | 12.00 Gbps | 100.30 Gbps | 18.39 Gbps | 100.22 Gbps | 19.87 Gbps | yes |
| medium | 8 | 16 GB | 25 Gbps | 6.00 Gbps | 98.38 Gbps | 18.90 Gbps | 100.85 Gbps | 19.75 Gbps | yes |
| micro | 2 | 2 GB | 1 Gbps | 0.80 Gbps | 97.50 Gbps | 19.35 Gbps | 99.44 Gbps | 19.35 Gbps | yes |
| small | 4 | 8 GB | 10 Gbps | 2.50 Gbps | 93.22 Gbps | 18.98 Gbps | 100.06 Gbps | 19.21 Gbps | yes |

## Per-SKU detail

### large (16 vCPU / 32 GB, 50 Gbps NIC)

#### Throughput matrix — max Gbps, dry-run / wire (packet size × inspection)

| packet size | no-inspect dry-run | no-inspect wire | url-cat dry-run | url-cat wire | full-tls dry-run | full-tls wire |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 64B | 9.43 Gbps | 0.24 Gbps | 9.49 Gbps | 0.25 Gbps | 9.36 Gbps | 0.24 Gbps |
| 512B | 45.58 Gbps | 1.96 Gbps | 46.61 Gbps | 1.89 Gbps | 47.71 Gbps | 2.03 Gbps |
| 1500B | 76.55 Gbps | 5.37 Gbps | 74.12 Gbps | 5.42 Gbps | 74.47 Gbps | 5.61 Gbps |
| 9000B | 100.30 Gbps | 18.39 Gbps | 102.75 Gbps | 18.91 Gbps | 100.22 Gbps | 19.87 Gbps |

#### Latency percentiles (per-packet)

| packet size | inspection | p50 | p95 | p99 | max |
| --- | --- | ---: | ---: | ---: | ---: |
| 64B | no-inspect | 71 ns | 150 ns | 161 ns | 2.146 ms |
| 64B | url-cat | 70 ns | 141 ns | 160 ns | 140.743 µs |
| 64B | full-tls | 70 ns | 141 ns | 160 ns | 479.545 µs |
| 512B | no-inspect | 100 ns | 170 ns | 191 ns | 2.188 ms |
| 512B | url-cat | 100 ns | 171 ns | 200 ns | 2.942 ms |
| 512B | full-tls | 101 ns | 180 ns | 200 ns | 750.511 µs |
| 1500B | no-inspect | 180 ns | 251 ns | 270 ns | 175.948 µs |
| 1500B | url-cat | 170 ns | 240 ns | 261 ns | 445.622 µs |
| 1500B | full-tls | 180 ns | 260 ns | 270 ns | 252.752 µs |
| 9000B | no-inspect | 681 ns | 761 ns | 1.132 µs | 1.847 ms |
| 9000B | url-cat | 681 ns | 761 ns | 1.162 µs | 710.656 µs |
| 9000B | full-tls | 731 ns | 811 ns | 832 ns | 166.030 µs |

#### Resource utilisation at each throughput operating point

| packet size | inspection | mean CPU | peak RSS (MiB) |
| --- | --- | ---: | ---: |
| 64B | no-inspect | 0.0% | 3.5 |
| 64B | url-cat | 0.0% | 3.8 |
| 64B | full-tls | 0.0% | 3.8 |
| 512B | no-inspect | 0.0% | 3.8 |
| 512B | url-cat | 0.0% | 3.8 |
| 512B | full-tls | 0.0% | 3.8 |
| 1500B | no-inspect | 0.0% | 3.8 |
| 1500B | url-cat | 0.0% | 3.8 |
| 1500B | full-tls | 0.0% | 3.8 |
| 9000B | no-inspect | 0.0% | 3.8 |
| 9000B | url-cat | 0.0% | 3.8 |
| 9000B | full-tls | 0.0% | 3.8 |

### medium (8 vCPU / 16 GB, 25 Gbps NIC)

#### Throughput matrix — max Gbps, dry-run / wire (packet size × inspection)

| packet size | no-inspect dry-run | no-inspect wire | url-cat dry-run | url-cat wire | full-tls dry-run | full-tls wire |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 64B | 9.78 Gbps | 0.25 Gbps | 9.55 Gbps | 0.24 Gbps | 9.54 Gbps | 0.24 Gbps |
| 512B | 47.44 Gbps | 1.98 Gbps | 46.76 Gbps | 1.93 Gbps | 48.56 Gbps | 1.90 Gbps |
| 1500B | 75.73 Gbps | 5.58 Gbps | 75.86 Gbps | 5.50 Gbps | 74.53 Gbps | 5.43 Gbps |
| 9000B | 98.38 Gbps | 18.90 Gbps | 97.10 Gbps | 19.15 Gbps | 100.85 Gbps | 19.75 Gbps |

#### Latency percentiles (per-packet)

| packet size | inspection | p50 | p95 | p99 | max |
| --- | --- | ---: | ---: | ---: | ---: |
| 64B | no-inspect | 70 ns | 150 ns | 161 ns | 2.350 ms |
| 64B | url-cat | 70 ns | 150 ns | 160 ns | 319.747 µs |
| 64B | full-tls | 70 ns | 150 ns | 160 ns | 84.808 µs |
| 512B | no-inspect | 100 ns | 170 ns | 181 ns | 2.318 ms |
| 512B | url-cat | 101 ns | 171 ns | 200 ns | 2.135 ms |
| 512B | full-tls | 110 ns | 180 ns | 200 ns | 2.237 ms |
| 1500B | no-inspect | 170 ns | 240 ns | 270 ns | 105.877 µs |
| 1500B | url-cat | 171 ns | 240 ns | 261 ns | 126.396 µs |
| 1500B | full-tls | 171 ns | 240 ns | 261 ns | 2.472 ms |
| 9000B | no-inspect | 741 ns | 822 ns | 1.252 µs | 2.507 ms |
| 9000B | url-cat | 691 ns | 771 ns | 1.153 µs | 1.940 ms |
| 9000B | full-tls | 691 ns | 762 ns | 1.212 µs | 90.509 µs |

#### Resource utilisation at each throughput operating point

| packet size | inspection | mean CPU | peak RSS (MiB) |
| --- | --- | ---: | ---: |
| 64B | no-inspect | 0.0% | 3.8 |
| 64B | url-cat | 0.0% | 3.8 |
| 64B | full-tls | 0.0% | 3.8 |
| 512B | no-inspect | 0.0% | 3.8 |
| 512B | url-cat | 0.0% | 3.8 |
| 512B | full-tls | 0.0% | 3.8 |
| 1500B | no-inspect | 0.0% | 3.8 |
| 1500B | url-cat | 0.0% | 3.8 |
| 1500B | full-tls | 0.0% | 3.8 |
| 9000B | no-inspect | 0.0% | 3.8 |
| 9000B | url-cat | 0.0% | 3.8 |
| 9000B | full-tls | 0.0% | 3.8 |

### micro (2 vCPU / 2 GB, 1 Gbps NIC)

#### Throughput matrix — max Gbps, dry-run / wire (packet size × inspection)

| packet size | no-inspect dry-run | no-inspect wire | url-cat dry-run | url-cat wire | full-tls dry-run | full-tls wire |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 64B | 9.57 Gbps | 0.25 Gbps | 9.49 Gbps | 0.26 Gbps | 9.38 Gbps | 0.25 Gbps |
| 512B | 47.30 Gbps | 1.98 Gbps | 47.45 Gbps | 1.98 Gbps | 46.99 Gbps | 1.95 Gbps |
| 1500B | 78.62 Gbps | 5.46 Gbps | 75.09 Gbps | 5.53 Gbps | 73.59 Gbps | 5.48 Gbps |
| 9000B | 97.50 Gbps | 19.35 Gbps | 97.91 Gbps | 19.49 Gbps | 99.44 Gbps | 19.35 Gbps |

#### Latency percentiles (per-packet)

| packet size | inspection | p50 | p95 | p99 | max |
| --- | --- | ---: | ---: | ---: | ---: |
| 64B | no-inspect | 71 ns | 150 ns | 161 ns | 2.238 ms |
| 64B | url-cat | 70 ns | 150 ns | 160 ns | 84.727 µs |
| 64B | full-tls | 70 ns | 140 ns | 160 ns | 116.557 µs |
| 512B | no-inspect | 100 ns | 170 ns | 190 ns | 2.057 ms |
| 512B | url-cat | 110 ns | 180 ns | 200 ns | 2.301 ms |
| 512B | full-tls | 100 ns | 171 ns | 191 ns | 2.446 ms |
| 1500B | no-inspect | 171 ns | 250 ns | 261 ns | 203.591 µs |
| 1500B | url-cat | 180 ns | 260 ns | 290 ns | 87.634 µs |
| 1500B | full-tls | 170 ns | 241 ns | 261 ns | 153.226 µs |
| 9000B | no-inspect | 731 ns | 811 ns | 1.042 µs | 2.459 ms |
| 9000B | url-cat | 732 ns | 821 ns | 1.192 µs | 2.420 ms |
| 9000B | full-tls | 731 ns | 812 ns | 1.353 µs | 2.063 ms |

#### Resource utilisation at each throughput operating point

| packet size | inspection | mean CPU | peak RSS (MiB) |
| --- | --- | ---: | ---: |
| 64B | no-inspect | 0.0% | 3.8 |
| 64B | url-cat | 0.0% | 3.8 |
| 64B | full-tls | 0.0% | 3.8 |
| 512B | no-inspect | 0.0% | 3.8 |
| 512B | url-cat | 0.0% | 3.8 |
| 512B | full-tls | 0.0% | 3.8 |
| 1500B | no-inspect | 0.0% | 3.8 |
| 1500B | url-cat | 0.0% | 3.8 |
| 1500B | full-tls | 0.0% | 3.8 |
| 9000B | no-inspect | 0.0% | 3.8 |
| 9000B | url-cat | 0.0% | 3.8 |
| 9000B | full-tls | 0.0% | 3.8 |

### small (4 vCPU / 8 GB, 10 Gbps NIC)

#### Throughput matrix — max Gbps, dry-run / wire (packet size × inspection)

| packet size | no-inspect dry-run | no-inspect wire | url-cat dry-run | url-cat wire | full-tls dry-run | full-tls wire |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 64B | 9.26 Gbps | 0.24 Gbps | 9.43 Gbps | 0.25 Gbps | 9.36 Gbps | 0.25 Gbps |
| 512B | 45.75 Gbps | 1.91 Gbps | 46.33 Gbps | 1.87 Gbps | 45.59 Gbps | 1.98 Gbps |
| 1500B | 78.13 Gbps | 5.53 Gbps | 75.92 Gbps | 5.41 Gbps | 73.78 Gbps | 5.54 Gbps |
| 9000B | 93.22 Gbps | 18.98 Gbps | 97.48 Gbps | 18.64 Gbps | 100.06 Gbps | 19.21 Gbps |

#### Latency percentiles (per-packet)

| packet size | inspection | p50 | p95 | p99 | max |
| --- | --- | ---: | ---: | ---: | ---: |
| 64B | no-inspect | 80 ns | 150 ns | 161 ns | 283.740 µs |
| 64B | url-cat | 71 ns | 150 ns | 161 ns | 2.436 ms |
| 64B | full-tls | 71 ns | 150 ns | 161 ns | 140.953 µs |
| 512B | no-inspect | 100 ns | 171 ns | 190 ns | 87.293 µs |
| 512B | url-cat | 100 ns | 170 ns | 191 ns | 2.447 ms |
| 512B | full-tls | 110 ns | 180 ns | 191 ns | 140.894 µs |
| 1500B | no-inspect | 170 ns | 260 ns | 290 ns | 2.383 ms |
| 1500B | url-cat | 170 ns | 241 ns | 271 ns | 55.143 µs |
| 1500B | full-tls | 180 ns | 251 ns | 261 ns | 80.090 µs |
| 9000B | no-inspect | 742 ns | 831 ns | 1.372 µs | 2.191 ms |
| 9000B | url-cat | 692 ns | 802 ns | 1.243 µs | 2.015 ms |
| 9000B | full-tls | 741 ns | 831 ns | 1.283 µs | 2.163 ms |

#### Resource utilisation at each throughput operating point

| packet size | inspection | mean CPU | peak RSS (MiB) |
| --- | --- | ---: | ---: |
| 64B | no-inspect | 0.0% | 3.8 |
| 64B | url-cat | 0.0% | 3.8 |
| 64B | full-tls | 0.0% | 3.8 |
| 512B | no-inspect | 0.0% | 3.8 |
| 512B | url-cat | 0.0% | 3.8 |
| 512B | full-tls | 0.0% | 3.8 |
| 1500B | no-inspect | 0.0% | 3.8 |
| 1500B | url-cat | 0.0% | 3.8 |
| 1500B | full-tls | 0.0% | 3.8 |
| 9000B | no-inspect | 0.0% | 3.8 |
| 9000B | url-cat | 0.0% | 3.8 |
| 9000B | full-tls | 0.0% | 3.8 |

## Competitor comparison

Competitor figures are vendor-published throughput for purpose-built hardware/ASIC appliances; SNG is software-only on a generic x86 VM. The comparison is informative, **not** apples-to-apples. SNG numbers are the measured 1500B peak at each inspection depth, shown for both the dry-run ceiling and the real-wire floor.

### large (vs 16-core class)

_No competitor appliance is catalogued for the 16-core class._

### medium (vs 8-core class)

| competitor | firewall (no-inspect) | NGFW (url-cat) | IPS/threat (full-tls) | source |
| --- | ---: | ---: | ---: | --- |
| **SNG medium** (dry-run) | 75.73 Gbps | 75.86 Gbps | 74.53 Gbps | sng-bench |
| **SNG medium** (wire) | 5.58 Gbps | 5.50 Gbps | 5.43 Gbps | sng-bench |
| Fortinet FortiGate 100F | 20.00 Gbps | 1.60 Gbps | 2.60 Gbps | FortiGate 100F datasheet (firewall / IPS / NGFW throughput, 1518B UDP) |

- SNG 5.58 Gbps (software, VM) vs Fortinet FortiGate 100F 20.00 Gbps published (-72%) — informative, not apples-to-apples: NP6Lite/CP9 ASIC fixed appliance; SNG is software-only on a generic x86 VM
- SNG 5.50 Gbps (software, VM) vs Fortinet FortiGate 100F 1.60 Gbps published (+243%) — informative, not apples-to-apples: NP6Lite/CP9 ASIC fixed appliance; SNG is software-only on a generic x86 VM
- SNG 5.43 Gbps (software, VM) vs Fortinet FortiGate 100F 2.60 Gbps published (+109%) — informative, not apples-to-apples: NP6Lite/CP9 ASIC fixed appliance; SNG is software-only on a generic x86 VM

### micro (vs 2-core class)

| competitor | firewall (no-inspect) | NGFW (url-cat) | IPS/threat (full-tls) | source |
| --- | ---: | ---: | ---: | --- |
| **SNG micro** (dry-run) | 78.62 Gbps | 75.09 Gbps | 73.59 Gbps | sng-bench |
| **SNG micro** (wire) | 5.46 Gbps | 5.53 Gbps | 5.48 Gbps | sng-bench |
| Fortinet FortiGate 40F | 5.00 Gbps | 0.60 Gbps | 0.80 Gbps | FortiGate 40F datasheet (firewall / IPS / NGFW throughput, 1518B UDP) |
| Palo Alto PA-440 | 3.10 Gbps | — | 0.70 Gbps | PA-400 series datasheet (firewall / threat-prevention throughput) |

- SNG 5.46 Gbps (software, VM) vs Fortinet FortiGate 40F 5.00 Gbps published (+9%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 5.46 Gbps (software, VM) vs Palo Alto PA-440 3.10 Gbps published (+76%) — informative, not apples-to-apples: single-pass hardware appliance; SNG is software-only on a generic x86 VM
- SNG 5.53 Gbps (software, VM) vs Fortinet FortiGate 40F 0.60 Gbps published (+821%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 5.48 Gbps (software, VM) vs Fortinet FortiGate 40F 0.80 Gbps published (+585%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 5.48 Gbps (software, VM) vs Palo Alto PA-440 0.70 Gbps published (+683%) — informative, not apples-to-apples: single-pass hardware appliance; SNG is software-only on a generic x86 VM

### small (vs 4-core class)

| competitor | firewall (no-inspect) | NGFW (url-cat) | IPS/threat (full-tls) | source |
| --- | ---: | ---: | ---: | --- |
| **SNG small** (dry-run) | 78.13 Gbps | 75.92 Gbps | 73.78 Gbps | sng-bench |
| **SNG small** (wire) | 5.53 Gbps | 5.41 Gbps | 5.54 Gbps | sng-bench |
| Fortinet FortiGate 60F | 10.00 Gbps | 1.00 Gbps | 1.40 Gbps | FortiGate 60F datasheet (firewall / IPS / NGFW throughput, 1518B UDP) |
| Palo Alto PA-450 | 5.20 Gbps | — | 1.60 Gbps | PA-400 series datasheet (firewall / threat-prevention throughput) |
| Check Point 3600 | 3.40 Gbps | — | 0.65 Gbps | Check Point 3600 datasheet (firewall / IPS throughput) |

- SNG 5.53 Gbps (software, VM) vs Fortinet FortiGate 60F 10.00 Gbps published (-45%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 5.53 Gbps (software, VM) vs Palo Alto PA-450 5.20 Gbps published (+6%) — informative, not apples-to-apples: single-pass hardware appliance; SNG is software-only on a generic x86 VM
- SNG 5.53 Gbps (software, VM) vs Check Point 3600 3.40 Gbps published (+63%) — informative, not apples-to-apples: fixed security appliance; SNG is software-only on a generic x86 VM
- SNG 5.41 Gbps (software, VM) vs Fortinet FortiGate 60F 1.00 Gbps published (+441%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 5.54 Gbps (software, VM) vs Fortinet FortiGate 60F 1.40 Gbps published (+296%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 5.54 Gbps (software, VM) vs Palo Alto PA-450 1.60 Gbps published (+246%) — informative, not apples-to-apples: single-pass hardware appliance; SNG is software-only on a generic x86 VM
- SNG 5.54 Gbps (software, VM) vs Check Point 3600 0.65 Gbps published (+753%) — informative, not apples-to-apples: fixed security appliance; SNG is software-only on a generic x86 VM

## Cost analysis

SNG cloud opex, assuming **$0.0416/vCPU-hour** (representative public-cloud general-purpose on-demand, us-east-1) over **730 hours/month**. $/Gbps uses the **real-wire** firewall peak (the number an operator actually provisions against); the dry-run $/Gbps is shown alongside as the synthetic floor on cost. Appliance capex / support TCO is vendor-quote territory and intentionally **not** invented here.

| SKU | vCPU | est. $/mo | firewall wire Gbps | $/Gbps (wire) | firewall dry-run Gbps | $/Gbps (dry-run) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| large | 16 | $486 | 18.39 Gbps | $26 | 100.30 Gbps | $5 |
| medium | 8 | $243 | 18.90 Gbps | $13 | 98.38 Gbps | $2 |
| micro | 2 | $61 | 19.35 Gbps | $3 | 97.50 Gbps | $1 |
| small | 4 | $121 | 18.98 Gbps | $6 | 93.22 Gbps | $1 |

