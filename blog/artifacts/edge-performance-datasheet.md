# ShieldNet Gateway — edge performance datasheet

_Generated (unix): `1780963388` · commit `3c2c0fc9c29e85a656e77b3cd1bdd0bf77124e6c` · all SNG figures measured by the `sng-bench` harness._

## Executive summary

| SKU | vCPU | RAM | NIC | target | firewall (no-inspect) | inspected (full-tls) | meets target |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | :---: |
| branch-large | 8 | 16 GB | 25 Gbps | 10.00 Gbps | 97.54 Gbps | 97.36 Gbps | yes |
| branch-medium | 4 | 8 GB | 10 Gbps | 5.00 Gbps | 96.45 Gbps | 96.93 Gbps | yes |
| branch-small | 2 | 4 GB | 1 Gbps | 0.80 Gbps | 96.36 Gbps | 97.31 Gbps | yes |
| cloud-pop-small | 4 | 8 GB | 10 Gbps | 2.00 Gbps | 96.28 Gbps | 95.48 Gbps | yes |

## Per-SKU detail

### branch-large (8 vCPU / 16 GB, 25 Gbps NIC)

#### Throughput matrix — max Gbps (packet size × inspection)

| packet size | no-inspect | url-cat | full-tls |
| --- | ---: | ---: | ---: |
| 64B | 8.36 Gbps | 8.77 Gbps | 8.71 Gbps |
| 512B | 46.71 Gbps | 44.78 Gbps | 44.78 Gbps |
| 1500B | 73.01 Gbps | 74.73 Gbps | 72.76 Gbps |
| 9000B | 97.54 Gbps | 95.98 Gbps | 97.36 Gbps |

#### Latency percentiles (per-packet)

| packet size | inspection | p50 | p95 | p99 | max |
| --- | --- | ---: | ---: | ---: | ---: |
| 64B | no-inspect | 80 ns | 151 ns | 170 ns | 32.871 µs |
| 64B | url-cat | 80 ns | 160 ns | 170 ns | 41.228 µs |
| 64B | full-tls | 80 ns | 151 ns | 170 ns | 30.036 µs |
| 512B | no-inspect | 110 ns | 180 ns | 191 ns | 47.027 µs |
| 512B | url-cat | 101 ns | 180 ns | 191 ns | 37.090 µs |
| 512B | full-tls | 110 ns | 190 ns | 191 ns | 31.138 µs |
| 1500B | no-inspect | 180 ns | 260 ns | 270 ns | 36.257 µs |
| 1500B | url-cat | 180 ns | 250 ns | 270 ns | 33.804 µs |
| 1500B | full-tls | 180 ns | 260 ns | 270 ns | 46.558 µs |
| 9000B | no-inspect | 732 ns | 812 ns | 822 ns | 54.061 µs |
| 9000B | url-cat | 732 ns | 821 ns | 822 ns | 36.398 µs |
| 9000B | full-tls | 732 ns | 812 ns | 822 ns | 35.356 µs |

#### Resource utilisation at each throughput operating point

| packet size | inspection | mean CPU | peak RSS (MiB) |
| --- | --- | ---: | ---: |
| 64B | no-inspect | 0.0% | 1.0 |
| 64B | url-cat | 0.0% | 3.0 |
| 64B | full-tls | 0.0% | 3.0 |
| 512B | no-inspect | 0.0% | 3.0 |
| 512B | url-cat | 0.0% | 3.0 |
| 512B | full-tls | 0.0% | 3.0 |
| 1500B | no-inspect | 0.0% | 3.0 |
| 1500B | url-cat | 0.0% | 3.0 |
| 1500B | full-tls | 0.0% | 3.0 |
| 9000B | no-inspect | 0.0% | 3.0 |
| 9000B | url-cat | 0.0% | 3.0 |
| 9000B | full-tls | 0.0% | 3.0 |

### branch-medium (4 vCPU / 8 GB, 10 Gbps NIC)

#### Throughput matrix — max Gbps (packet size × inspection)

| packet size | no-inspect | url-cat | full-tls |
| --- | ---: | ---: | ---: |
| 64B | 8.74 Gbps | 8.74 Gbps | 8.74 Gbps |
| 512B | 45.22 Gbps | 44.99 Gbps | 45.33 Gbps |
| 1500B | 73.26 Gbps | 73.44 Gbps | 72.97 Gbps |
| 9000B | 96.45 Gbps | 95.24 Gbps | 96.93 Gbps |

#### Latency percentiles (per-packet)

| packet size | inspection | p50 | p95 | p99 | max |
| --- | --- | ---: | ---: | ---: | ---: |
| 64B | no-inspect | 80 ns | 160 ns | 171 ns | 55.073 µs |
| 64B | url-cat | 80 ns | 151 ns | 170 ns | 37.741 µs |
| 64B | full-tls | 80 ns | 160 ns | 170 ns | 33.693 µs |
| 512B | no-inspect | 110 ns | 190 ns | 200 ns | 45.184 µs |
| 512B | url-cat | 110 ns | 190 ns | 200 ns | 35.627 µs |
| 512B | full-tls | 110 ns | 190 ns | 200 ns | 46.176 µs |
| 1500B | no-inspect | 180 ns | 260 ns | 270 ns | 36.719 µs |
| 1500B | url-cat | 180 ns | 270 ns | 341 ns | 74.319 µs |
| 1500B | full-tls | 180 ns | 260 ns | 270 ns | 35.776 µs |
| 9000B | no-inspect | 742 ns | 831 ns | 1.273 µs | 36.258 µs |
| 9000B | url-cat | 742 ns | 831 ns | 832 ns | 36.478 µs |
| 9000B | full-tls | 742 ns | 831 ns | 1.263 µs | 49.653 µs |

#### Resource utilisation at each throughput operating point

| packet size | inspection | mean CPU | peak RSS (MiB) |
| --- | --- | ---: | ---: |
| 64B | no-inspect | 0.0% | 3.0 |
| 64B | url-cat | 0.0% | 3.0 |
| 64B | full-tls | 0.0% | 3.0 |
| 512B | no-inspect | 0.0% | 3.0 |
| 512B | url-cat | 0.0% | 3.0 |
| 512B | full-tls | 0.0% | 3.0 |
| 1500B | no-inspect | 0.0% | 3.0 |
| 1500B | url-cat | 0.0% | 3.0 |
| 1500B | full-tls | 0.0% | 3.0 |
| 9000B | no-inspect | 0.0% | 3.0 |
| 9000B | url-cat | 0.0% | 3.0 |
| 9000B | full-tls | 0.0% | 3.0 |

### branch-small (2 vCPU / 4 GB, 1 Gbps NIC)

#### Throughput matrix — max Gbps (packet size × inspection)

| packet size | no-inspect | url-cat | full-tls |
| --- | ---: | ---: | ---: |
| 64B | 8.84 Gbps | 8.87 Gbps | 8.90 Gbps |
| 512B | 46.71 Gbps | 45.51 Gbps | 46.34 Gbps |
| 1500B | 73.42 Gbps | 74.42 Gbps | 71.54 Gbps |
| 9000B | 96.36 Gbps | 96.39 Gbps | 97.31 Gbps |

#### Latency percentiles (per-packet)

| packet size | inspection | p50 | p95 | p99 | max |
| --- | --- | ---: | ---: | ---: | ---: |
| 64B | no-inspect | 80 ns | 150 ns | 161 ns | 30.757 µs |
| 64B | url-cat | 80 ns | 151 ns | 170 ns | 39.564 µs |
| 64B | full-tls | 71 ns | 150 ns | 170 ns | 29.855 µs |
| 512B | no-inspect | 100 ns | 171 ns | 191 ns | 46.477 µs |
| 512B | url-cat | 110 ns | 181 ns | 191 ns | 50.715 µs |
| 512B | full-tls | 110 ns | 181 ns | 191 ns | 41.287 µs |
| 1500B | no-inspect | 180 ns | 250 ns | 270 ns | 38.792 µs |
| 1500B | url-cat | 180 ns | 251 ns | 270 ns | 34.144 µs |
| 1500B | full-tls | 180 ns | 260 ns | 270 ns | 62.707 µs |
| 9000B | no-inspect | 742 ns | 831 ns | 1.263 µs | 67.326 µs |
| 9000B | url-cat | 742 ns | 822 ns | 1.192 µs | 70.101 µs |
| 9000B | full-tls | 742 ns | 822 ns | 832 ns | 93.404 µs |

#### Resource utilisation at each throughput operating point

| packet size | inspection | mean CPU | peak RSS (MiB) |
| --- | --- | ---: | ---: |
| 64B | no-inspect | 0.0% | 3.0 |
| 64B | url-cat | 0.0% | 3.0 |
| 64B | full-tls | 0.0% | 3.0 |
| 512B | no-inspect | 0.0% | 3.0 |
| 512B | url-cat | 0.0% | 3.0 |
| 512B | full-tls | 0.0% | 3.0 |
| 1500B | no-inspect | 0.0% | 3.0 |
| 1500B | url-cat | 0.0% | 3.0 |
| 1500B | full-tls | 0.0% | 3.0 |
| 9000B | no-inspect | 0.0% | 3.0 |
| 9000B | url-cat | 0.0% | 3.0 |
| 9000B | full-tls | 0.0% | 3.0 |

### cloud-pop-small (4 vCPU / 8 GB, 10 Gbps NIC)

#### Throughput matrix — max Gbps (packet size × inspection)

| packet size | no-inspect | url-cat | full-tls |
| --- | ---: | ---: | ---: |
| 64B | 8.73 Gbps | 8.73 Gbps | 8.79 Gbps |
| 512B | 44.45 Gbps | 44.66 Gbps | 45.52 Gbps |
| 1500B | 74.74 Gbps | 73.49 Gbps | 73.90 Gbps |
| 9000B | 96.28 Gbps | 97.53 Gbps | 95.48 Gbps |

#### Latency percentiles (per-packet)

| packet size | inspection | p50 | p95 | p99 | max |
| --- | --- | ---: | ---: | ---: | ---: |
| 64B | no-inspect | 80 ns | 160 ns | 170 ns | 49.212 µs |
| 64B | url-cat | 80 ns | 160 ns | 170 ns | 77.064 µs |
| 64B | full-tls | 80 ns | 160 ns | 170 ns | 64.340 µs |
| 512B | no-inspect | 110 ns | 190 ns | 191 ns | 225.350 µs |
| 512B | url-cat | 110 ns | 190 ns | 191 ns | 44.723 µs |
| 512B | full-tls | 110 ns | 190 ns | 191 ns | 36.458 µs |
| 1500B | no-inspect | 180 ns | 260 ns | 270 ns | 264.473 µs |
| 1500B | url-cat | 180 ns | 260 ns | 271 ns | 59.982 µs |
| 1500B | full-tls | 180 ns | 260 ns | 270 ns | 44.352 µs |
| 9000B | no-inspect | 742 ns | 831 ns | 841 ns | 36.147 µs |
| 9000B | url-cat | 742 ns | 831 ns | 841 ns | 399.025 µs |
| 9000B | full-tls | 742 ns | 831 ns | 842 ns | 37.219 µs |

#### Resource utilisation at each throughput operating point

| packet size | inspection | mean CPU | peak RSS (MiB) |
| --- | --- | ---: | ---: |
| 64B | no-inspect | 0.0% | 3.0 |
| 64B | url-cat | 0.0% | 3.0 |
| 64B | full-tls | 0.0% | 3.0 |
| 512B | no-inspect | 0.0% | 3.0 |
| 512B | url-cat | 0.0% | 3.0 |
| 512B | full-tls | 0.0% | 3.0 |
| 1500B | no-inspect | 0.0% | 3.0 |
| 1500B | url-cat | 0.0% | 3.0 |
| 1500B | full-tls | 0.0% | 3.0 |
| 9000B | no-inspect | 0.0% | 3.0 |
| 9000B | url-cat | 0.0% | 3.0 |
| 9000B | full-tls | 0.0% | 3.0 |

## Competitor comparison

Competitor figures are vendor-published throughput for purpose-built hardware/ASIC appliances; SNG is software-only on a generic x86 VM. The comparison is informative, **not** apples-to-apples. SNG numbers are the measured 1500B peak at each inspection depth.

### branch-large (vs 8-core class)

| competitor | firewall (no-inspect) | NGFW (url-cat) | IPS/threat (full-tls) | source |
| --- | ---: | ---: | ---: | --- |
| **SNG branch-large** (measured) | 73.01 Gbps | 74.73 Gbps | 72.76 Gbps | sng-bench |
| Fortinet FortiGate 100F | 20.00 Gbps | 1.60 Gbps | 2.60 Gbps | FortiGate 100F datasheet (firewall / IPS / NGFW throughput, 1518B UDP) |

- SNG 73.01 Gbps (software, VM) vs Fortinet FortiGate 100F 20.00 Gbps published (+265%) — informative, not apples-to-apples: NP6Lite/CP9 ASIC fixed appliance; SNG is software-only on a generic x86 VM
- SNG 74.73 Gbps (software, VM) vs Fortinet FortiGate 100F 1.60 Gbps published (+4571%) — informative, not apples-to-apples: NP6Lite/CP9 ASIC fixed appliance; SNG is software-only on a generic x86 VM
- SNG 72.76 Gbps (software, VM) vs Fortinet FortiGate 100F 2.60 Gbps published (+2698%) — informative, not apples-to-apples: NP6Lite/CP9 ASIC fixed appliance; SNG is software-only on a generic x86 VM

### branch-medium (vs 4-core class)

| competitor | firewall (no-inspect) | NGFW (url-cat) | IPS/threat (full-tls) | source |
| --- | ---: | ---: | ---: | --- |
| **SNG branch-medium** (measured) | 73.26 Gbps | 73.44 Gbps | 72.97 Gbps | sng-bench |
| Fortinet FortiGate 60F | 10.00 Gbps | 1.00 Gbps | 1.40 Gbps | FortiGate 60F datasheet (firewall / IPS / NGFW throughput, 1518B UDP) |
| Palo Alto PA-450 | 5.20 Gbps | — | 1.60 Gbps | PA-400 series datasheet (firewall / threat-prevention throughput) |
| Check Point 3600 | 3.40 Gbps | — | 0.65 Gbps | Check Point 3600 datasheet (firewall / IPS throughput) |

- SNG 73.26 Gbps (software, VM) vs Fortinet FortiGate 60F 10.00 Gbps published (+633%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 73.26 Gbps (software, VM) vs Palo Alto PA-450 5.20 Gbps published (+1309%) — informative, not apples-to-apples: single-pass hardware appliance; SNG is software-only on a generic x86 VM
- SNG 73.26 Gbps (software, VM) vs Check Point 3600 3.40 Gbps published (+2055%) — informative, not apples-to-apples: fixed security appliance; SNG is software-only on a generic x86 VM
- SNG 73.44 Gbps (software, VM) vs Fortinet FortiGate 60F 1.00 Gbps published (+7244%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 72.97 Gbps (software, VM) vs Fortinet FortiGate 60F 1.40 Gbps published (+5112%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 72.97 Gbps (software, VM) vs Palo Alto PA-450 1.60 Gbps published (+4461%) — informative, not apples-to-apples: single-pass hardware appliance; SNG is software-only on a generic x86 VM
- SNG 72.97 Gbps (software, VM) vs Check Point 3600 0.65 Gbps published (+11126%) — informative, not apples-to-apples: fixed security appliance; SNG is software-only on a generic x86 VM

### branch-small (vs 2-core class)

| competitor | firewall (no-inspect) | NGFW (url-cat) | IPS/threat (full-tls) | source |
| --- | ---: | ---: | ---: | --- |
| **SNG branch-small** (measured) | 73.42 Gbps | 74.42 Gbps | 71.54 Gbps | sng-bench |
| Fortinet FortiGate 40F | 5.00 Gbps | 0.60 Gbps | 0.80 Gbps | FortiGate 40F datasheet (firewall / IPS / NGFW throughput, 1518B UDP) |
| Palo Alto PA-440 | 3.10 Gbps | — | 0.70 Gbps | PA-400 series datasheet (firewall / threat-prevention throughput) |

- SNG 73.42 Gbps (software, VM) vs Fortinet FortiGate 40F 5.00 Gbps published (+1368%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 73.42 Gbps (software, VM) vs Palo Alto PA-440 3.10 Gbps published (+2268%) — informative, not apples-to-apples: single-pass hardware appliance; SNG is software-only on a generic x86 VM
- SNG 74.42 Gbps (software, VM) vs Fortinet FortiGate 40F 0.60 Gbps published (+12304%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 71.54 Gbps (software, VM) vs Fortinet FortiGate 40F 0.80 Gbps published (+8842%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 71.54 Gbps (software, VM) vs Palo Alto PA-440 0.70 Gbps published (+10119%) — informative, not apples-to-apples: single-pass hardware appliance; SNG is software-only on a generic x86 VM

### cloud-pop-small (vs 4-core class)

| competitor | firewall (no-inspect) | NGFW (url-cat) | IPS/threat (full-tls) | source |
| --- | ---: | ---: | ---: | --- |
| **SNG cloud-pop-small** (measured) | 74.74 Gbps | 73.49 Gbps | 73.90 Gbps | sng-bench |
| Fortinet FortiGate 60F | 10.00 Gbps | 1.00 Gbps | 1.40 Gbps | FortiGate 60F datasheet (firewall / IPS / NGFW throughput, 1518B UDP) |
| Palo Alto PA-450 | 5.20 Gbps | — | 1.60 Gbps | PA-400 series datasheet (firewall / threat-prevention throughput) |
| Check Point 3600 | 3.40 Gbps | — | 0.65 Gbps | Check Point 3600 datasheet (firewall / IPS throughput) |

- SNG 74.74 Gbps (software, VM) vs Fortinet FortiGate 60F 10.00 Gbps published (+647%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 74.74 Gbps (software, VM) vs Palo Alto PA-450 5.20 Gbps published (+1337%) — informative, not apples-to-apples: single-pass hardware appliance; SNG is software-only on a generic x86 VM
- SNG 74.74 Gbps (software, VM) vs Check Point 3600 3.40 Gbps published (+2098%) — informative, not apples-to-apples: fixed security appliance; SNG is software-only on a generic x86 VM
- SNG 73.49 Gbps (software, VM) vs Fortinet FortiGate 60F 1.00 Gbps published (+7249%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 73.90 Gbps (software, VM) vs Fortinet FortiGate 60F 1.40 Gbps published (+5179%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 73.90 Gbps (software, VM) vs Palo Alto PA-450 1.60 Gbps published (+4519%) — informative, not apples-to-apples: single-pass hardware appliance; SNG is software-only on a generic x86 VM
- SNG 73.90 Gbps (software, VM) vs Check Point 3600 0.65 Gbps published (+11269%) — informative, not apples-to-apples: fixed security appliance; SNG is software-only on a generic x86 VM

## Cost analysis

SNG cloud opex, assuming **$0.0416/vCPU-hour** (representative public-cloud general-purpose on-demand, us-east-1) over **730 hours/month**. $/Gbps uses the measured peak at each depth. Appliance capex / support TCO is vendor-quote territory and intentionally **not** invented here.

| SKU | vCPU | est. $/mo | firewall Gbps | $/Gbps (firewall) | full-tls Gbps | $/Gbps (full-tls) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| branch-large | 8 | $243 | 97.54 Gbps | $2 | 97.36 Gbps | $2 |
| branch-medium | 4 | $121 | 96.45 Gbps | $1 | 96.93 Gbps | $1 |
| branch-small | 2 | $61 | 96.36 Gbps | $1 | 97.31 Gbps | $1 |
| cloud-pop-small | 4 | $121 | 96.28 Gbps | $1 | 95.48 Gbps | $1 |

