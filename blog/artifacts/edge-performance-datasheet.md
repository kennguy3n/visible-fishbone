# ShieldNet Gateway — edge performance datasheet

_Generated (unix): `1781107000` · commit `6c6406bdfa8c394d9aad18e7c496d9148f519026` · all SNG figures measured by the `sng-bench` harness._

## Executive summary

| SKU | vCPU | RAM | NIC | target | firewall (no-inspect) | inspected (full-tls) | meets target |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | :---: |
| branch-large | 8 | 16 GB | 25 Gbps | 10.00 Gbps | 88.31 Gbps | 96.50 Gbps | yes |
| branch-medium | 4 | 8 GB | 10 Gbps | 5.00 Gbps | 94.56 Gbps | 94.61 Gbps | yes |
| branch-small | 2 | 4 GB | 1 Gbps | 0.80 Gbps | 93.02 Gbps | 95.95 Gbps | yes |
| cloud-pop-small | 4 | 8 GB | 10 Gbps | 2.00 Gbps | 96.25 Gbps | 95.12 Gbps | yes |

## Per-SKU detail

### branch-large (8 vCPU / 16 GB, 25 Gbps NIC)

#### Throughput matrix — max Gbps (packet size × inspection)

| packet size | no-inspect | url-cat | full-tls |
| --- | ---: | ---: | ---: |
| 64B | 8.85 Gbps | 9.08 Gbps | 8.93 Gbps |
| 512B | 44.91 Gbps | 46.72 Gbps | 46.72 Gbps |
| 1500B | 74.92 Gbps | 75.27 Gbps | 75.28 Gbps |
| 9000B | 88.31 Gbps | 90.12 Gbps | 96.50 Gbps |

#### Latency percentiles (per-packet)

| packet size | inspection | p50 | p95 | p99 | max |
| --- | --- | ---: | ---: | ---: | ---: |
| 64B | no-inspect | 80 ns | 151 ns | 161 ns | 254.335 µs |
| 64B | url-cat | 80 ns | 151 ns | 170 ns | 223.206 µs |
| 64B | full-tls | 80 ns | 151 ns | 161 ns | 3.177 ms |
| 512B | no-inspect | 111 ns | 190 ns | 201 ns | 3.211 ms |
| 512B | url-cat | 110 ns | 190 ns | 200 ns | 3.205 ms |
| 512B | full-tls | 110 ns | 190 ns | 200 ns | 2.541 ms |
| 1500B | no-inspect | 180 ns | 261 ns | 301 ns | 2.691 ms |
| 1500B | url-cat | 180 ns | 260 ns | 271 ns | 3.098 ms |
| 1500B | full-tls | 180 ns | 260 ns | 280 ns | 210.613 µs |
| 9000B | no-inspect | 742 ns | 1.273 µs | 1.463 µs | 3.299 ms |
| 9000B | url-cat | 741 ns | 832 ns | 1.392 µs | 3.230 ms |
| 9000B | full-tls | 742 ns | 832 ns | 1.383 µs | 3.091 ms |

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

### branch-medium (4 vCPU / 8 GB, 10 Gbps NIC)

#### Throughput matrix — max Gbps (packet size × inspection)

| packet size | no-inspect | url-cat | full-tls |
| --- | ---: | ---: | ---: |
| 64B | 8.64 Gbps | 8.49 Gbps | 8.82 Gbps |
| 512B | 44.67 Gbps | 43.40 Gbps | 44.06 Gbps |
| 1500B | 71.14 Gbps | 70.87 Gbps | 71.64 Gbps |
| 9000B | 94.56 Gbps | 92.84 Gbps | 94.61 Gbps |

#### Latency percentiles (per-packet)

| packet size | inspection | p50 | p95 | p99 | max |
| --- | --- | ---: | ---: | ---: | ---: |
| 64B | no-inspect | 80 ns | 151 ns | 161 ns | 96.911 µs |
| 64B | url-cat | 80 ns | 151 ns | 171 ns | 84.747 µs |
| 64B | full-tls | 80 ns | 151 ns | 161 ns | 60.533 µs |
| 512B | no-inspect | 110 ns | 181 ns | 191 ns | 83.536 µs |
| 512B | url-cat | 110 ns | 181 ns | 191 ns | 38.702 µs |
| 512B | full-tls | 110 ns | 181 ns | 191 ns | 87.784 µs |
| 1500B | no-inspect | 180 ns | 260 ns | 270 ns | 88.695 µs |
| 1500B | url-cat | 180 ns | 260 ns | 271 ns | 74.279 µs |
| 1500B | full-tls | 180 ns | 260 ns | 270 ns | 70.181 µs |
| 9000B | no-inspect | 731 ns | 811 ns | 822 ns | 50.093 µs |
| 9000B | url-cat | 731 ns | 811 ns | 822 ns | 144.038 µs |
| 9000B | full-tls | 731 ns | 812 ns | 1.112 µs | 2.284 ms |

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

### branch-small (2 vCPU / 4 GB, 1 Gbps NIC)

#### Throughput matrix — max Gbps (packet size × inspection)

| packet size | no-inspect | url-cat | full-tls |
| --- | ---: | ---: | ---: |
| 64B | 8.80 Gbps | 8.92 Gbps | 9.08 Gbps |
| 512B | 46.55 Gbps | 46.61 Gbps | 45.55 Gbps |
| 1500B | 74.13 Gbps | 74.18 Gbps | 73.89 Gbps |
| 9000B | 93.02 Gbps | 96.23 Gbps | 95.95 Gbps |

#### Latency percentiles (per-packet)

| packet size | inspection | p50 | p95 | p99 | max |
| --- | --- | ---: | ---: | ---: | ---: |
| 64B | no-inspect | 80 ns | 151 ns | 161 ns | 2.076 ms |
| 64B | url-cat | 80 ns | 151 ns | 170 ns | 290.112 µs |
| 64B | full-tls | 80 ns | 151 ns | 161 ns | 2.661 ms |
| 512B | no-inspect | 110 ns | 180 ns | 191 ns | 2.920 ms |
| 512B | url-cat | 110 ns | 180 ns | 191 ns | 2.302 ms |
| 512B | full-tls | 110 ns | 180 ns | 191 ns | 1.938 ms |
| 1500B | no-inspect | 180 ns | 260 ns | 271 ns | 2.395 ms |
| 1500B | url-cat | 180 ns | 260 ns | 271 ns | 2.113 ms |
| 1500B | full-tls | 180 ns | 261 ns | 301 ns | 2.143 ms |
| 9000B | no-inspect | 741 ns | 1.192 µs | 1.483 µs | 2.500 ms |
| 9000B | url-cat | 741 ns | 822 ns | 1.202 µs | 2.881 ms |
| 9000B | full-tls | 741 ns | 832 ns | 1.362 µs | 2.529 ms |

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

### cloud-pop-small (4 vCPU / 8 GB, 10 Gbps NIC)

#### Throughput matrix — max Gbps (packet size × inspection)

| packet size | no-inspect | url-cat | full-tls |
| --- | ---: | ---: | ---: |
| 64B | 8.94 Gbps | 8.76 Gbps | 8.74 Gbps |
| 512B | 44.36 Gbps | 44.75 Gbps | 44.58 Gbps |
| 1500B | 68.35 Gbps | 70.52 Gbps | 72.50 Gbps |
| 9000B | 96.25 Gbps | 95.93 Gbps | 95.12 Gbps |

#### Latency percentiles (per-packet)

| packet size | inspection | p50 | p95 | p99 | max |
| --- | --- | ---: | ---: | ---: | ---: |
| 64B | no-inspect | 80 ns | 151 ns | 161 ns | 236.070 µs |
| 64B | url-cat | 80 ns | 151 ns | 171 ns | 204.341 µs |
| 64B | full-tls | 80 ns | 151 ns | 161 ns | 301.753 µs |
| 512B | no-inspect | 110 ns | 180 ns | 191 ns | 330.667 µs |
| 512B | url-cat | 110 ns | 180 ns | 191 ns | 211.915 µs |
| 512B | full-tls | 110 ns | 180 ns | 191 ns | 288.648 µs |
| 1500B | no-inspect | 180 ns | 261 ns | 300 ns | 317.582 µs |
| 1500B | url-cat | 180 ns | 260 ns | 270 ns | 3.041 ms |
| 1500B | full-tls | 180 ns | 260 ns | 271 ns | 130.193 µs |
| 9000B | no-inspect | 731 ns | 812 ns | 1.253 µs | 3.107 ms |
| 9000B | url-cat | 731 ns | 811 ns | 822 ns | 2.677 ms |
| 9000B | full-tls | 731 ns | 812 ns | 1.212 µs | 2.844 ms |

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

Competitor figures are vendor-published throughput for purpose-built hardware/ASIC appliances; SNG is software-only on a generic x86 VM. The comparison is informative, **not** apples-to-apples. SNG numbers are the measured 1500B peak at each inspection depth.

### branch-large (vs 8-core class)

| competitor | firewall (no-inspect) | NGFW (url-cat) | IPS/threat (full-tls) | source |
| --- | ---: | ---: | ---: | --- |
| **SNG branch-large** (measured) | 74.92 Gbps | 75.27 Gbps | 75.28 Gbps | sng-bench |
| Fortinet FortiGate 100F | 20.00 Gbps | 1.60 Gbps | 2.60 Gbps | FortiGate 100F datasheet (firewall / IPS / NGFW throughput, 1518B UDP) |

- SNG 74.92 Gbps (software, VM) vs Fortinet FortiGate 100F 20.00 Gbps published (+275%) — informative, not apples-to-apples: NP6Lite/CP9 ASIC fixed appliance; SNG is software-only on a generic x86 VM
- SNG 75.27 Gbps (software, VM) vs Fortinet FortiGate 100F 1.60 Gbps published (+4605%) — informative, not apples-to-apples: NP6Lite/CP9 ASIC fixed appliance; SNG is software-only on a generic x86 VM
- SNG 75.28 Gbps (software, VM) vs Fortinet FortiGate 100F 2.60 Gbps published (+2795%) — informative, not apples-to-apples: NP6Lite/CP9 ASIC fixed appliance; SNG is software-only on a generic x86 VM

### branch-medium (vs 4-core class)

| competitor | firewall (no-inspect) | NGFW (url-cat) | IPS/threat (full-tls) | source |
| --- | ---: | ---: | ---: | --- |
| **SNG branch-medium** (measured) | 71.14 Gbps | 70.87 Gbps | 71.64 Gbps | sng-bench |
| Fortinet FortiGate 60F | 10.00 Gbps | 1.00 Gbps | 1.40 Gbps | FortiGate 60F datasheet (firewall / IPS / NGFW throughput, 1518B UDP) |
| Palo Alto PA-450 | 5.20 Gbps | — | 1.60 Gbps | PA-400 series datasheet (firewall / threat-prevention throughput) |
| Check Point 3600 | 3.40 Gbps | — | 0.65 Gbps | Check Point 3600 datasheet (firewall / IPS throughput) |

- SNG 71.14 Gbps (software, VM) vs Fortinet FortiGate 60F 10.00 Gbps published (+611%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 71.14 Gbps (software, VM) vs Palo Alto PA-450 5.20 Gbps published (+1268%) — informative, not apples-to-apples: single-pass hardware appliance; SNG is software-only on a generic x86 VM
- SNG 71.14 Gbps (software, VM) vs Check Point 3600 3.40 Gbps published (+1992%) — informative, not apples-to-apples: fixed security appliance; SNG is software-only on a generic x86 VM
- SNG 70.87 Gbps (software, VM) vs Fortinet FortiGate 60F 1.00 Gbps published (+6987%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 71.64 Gbps (software, VM) vs Fortinet FortiGate 60F 1.40 Gbps published (+5017%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 71.64 Gbps (software, VM) vs Palo Alto PA-450 1.60 Gbps published (+4378%) — informative, not apples-to-apples: single-pass hardware appliance; SNG is software-only on a generic x86 VM
- SNG 71.64 Gbps (software, VM) vs Check Point 3600 0.65 Gbps published (+10922%) — informative, not apples-to-apples: fixed security appliance; SNG is software-only on a generic x86 VM

### branch-small (vs 2-core class)

| competitor | firewall (no-inspect) | NGFW (url-cat) | IPS/threat (full-tls) | source |
| --- | ---: | ---: | ---: | --- |
| **SNG branch-small** (measured) | 74.13 Gbps | 74.18 Gbps | 73.89 Gbps | sng-bench |
| Fortinet FortiGate 40F | 5.00 Gbps | 0.60 Gbps | 0.80 Gbps | FortiGate 40F datasheet (firewall / IPS / NGFW throughput, 1518B UDP) |
| Palo Alto PA-440 | 3.10 Gbps | — | 0.70 Gbps | PA-400 series datasheet (firewall / threat-prevention throughput) |

- SNG 74.13 Gbps (software, VM) vs Fortinet FortiGate 40F 5.00 Gbps published (+1383%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 74.13 Gbps (software, VM) vs Palo Alto PA-440 3.10 Gbps published (+2291%) — informative, not apples-to-apples: single-pass hardware appliance; SNG is software-only on a generic x86 VM
- SNG 74.18 Gbps (software, VM) vs Fortinet FortiGate 40F 0.60 Gbps published (+12263%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 73.89 Gbps (software, VM) vs Fortinet FortiGate 40F 0.80 Gbps published (+9137%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 73.89 Gbps (software, VM) vs Palo Alto PA-440 0.70 Gbps published (+10456%) — informative, not apples-to-apples: single-pass hardware appliance; SNG is software-only on a generic x86 VM

### cloud-pop-small (vs 4-core class)

| competitor | firewall (no-inspect) | NGFW (url-cat) | IPS/threat (full-tls) | source |
| --- | ---: | ---: | ---: | --- |
| **SNG cloud-pop-small** (measured) | 68.35 Gbps | 70.52 Gbps | 72.50 Gbps | sng-bench |
| Fortinet FortiGate 60F | 10.00 Gbps | 1.00 Gbps | 1.40 Gbps | FortiGate 60F datasheet (firewall / IPS / NGFW throughput, 1518B UDP) |
| Palo Alto PA-450 | 5.20 Gbps | — | 1.60 Gbps | PA-400 series datasheet (firewall / threat-prevention throughput) |
| Check Point 3600 | 3.40 Gbps | — | 0.65 Gbps | Check Point 3600 datasheet (firewall / IPS throughput) |

- SNG 68.35 Gbps (software, VM) vs Fortinet FortiGate 60F 10.00 Gbps published (+583%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 68.35 Gbps (software, VM) vs Palo Alto PA-450 5.20 Gbps published (+1214%) — informative, not apples-to-apples: single-pass hardware appliance; SNG is software-only on a generic x86 VM
- SNG 68.35 Gbps (software, VM) vs Check Point 3600 3.40 Gbps published (+1910%) — informative, not apples-to-apples: fixed security appliance; SNG is software-only on a generic x86 VM
- SNG 70.52 Gbps (software, VM) vs Fortinet FortiGate 60F 1.00 Gbps published (+6952%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 72.50 Gbps (software, VM) vs Fortinet FortiGate 60F 1.40 Gbps published (+5079%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 72.50 Gbps (software, VM) vs Palo Alto PA-450 1.60 Gbps published (+4431%) — informative, not apples-to-apples: single-pass hardware appliance; SNG is software-only on a generic x86 VM
- SNG 72.50 Gbps (software, VM) vs Check Point 3600 0.65 Gbps published (+11054%) — informative, not apples-to-apples: fixed security appliance; SNG is software-only on a generic x86 VM

## Cost analysis

SNG cloud opex, assuming **$0.0416/vCPU-hour** (representative public-cloud general-purpose on-demand, us-east-1) over **730 hours/month**. $/Gbps uses the measured peak at each depth. Appliance capex / support TCO is vendor-quote territory and intentionally **not** invented here.

| SKU | vCPU | est. $/mo | firewall Gbps | $/Gbps (firewall) | full-tls Gbps | $/Gbps (full-tls) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| branch-large | 8 | $243 | 88.31 Gbps | $3 | 96.50 Gbps | $3 |
| branch-medium | 4 | $121 | 94.56 Gbps | $1 | 94.61 Gbps | $1 |
| branch-small | 2 | $61 | 93.02 Gbps | $1 | 95.95 Gbps | $1 |
| cloud-pop-small | 4 | $121 | 96.25 Gbps | $1 | 95.12 Gbps | $1 |

