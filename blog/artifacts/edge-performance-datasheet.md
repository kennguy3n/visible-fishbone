# ShieldNet Gateway — edge performance datasheet

_Generated (unix): `1781226673` · all SNG figures measured by the `sng-bench` harness._

Every throughput figure is reported in two columns:

- **dry-run** — the in-process craft+measure+report pipeline with no NIC in the loop (the synthetic ceiling; runs on any CI runner).
- **wire** — real `AF_PACKET` frames transmitted over a veth pair with `sng-edge` enforcing in-path under `CAP_NET_RAW` on the self-hosted `sng-bench-wire` runner (the measured line-rate floor).


## Executive summary

| SKU | vCPU | RAM | NIC | target | firewall dry-run | firewall wire | inspected dry-run | inspected wire | meets target (wire) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :---: |
| branch-large | 8 | 16 GB | 25 Gbps | 10.00 Gbps | 96.04 Gbps | 18.96 Gbps | 97.23 Gbps | 19.12 Gbps | yes |
| branch-medium | 4 | 8 GB | 10 Gbps | 5.00 Gbps | 100.41 Gbps | 18.90 Gbps | 100.54 Gbps | 18.48 Gbps | yes |
| branch-small | 2 | 4 GB | 1 Gbps | 0.80 Gbps | 97.85 Gbps | 18.69 Gbps | 98.16 Gbps | 18.70 Gbps | yes |
| cloud-pop-small | 4 | 8 GB | 10 Gbps | 2.00 Gbps | 97.20 Gbps | 18.53 Gbps | 96.30 Gbps | 19.51 Gbps | yes |

## Per-SKU detail

### branch-large (8 vCPU / 16 GB, 25 Gbps NIC)

#### Throughput matrix — max Gbps, dry-run / wire (packet size × inspection)

| packet size | no-inspect dry-run | no-inspect wire | url-cat dry-run | url-cat wire | full-tls dry-run | full-tls wire |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 64B | 8.61 Gbps | 0.25 Gbps | 8.71 Gbps | 0.25 Gbps | 8.91 Gbps | 0.25 Gbps |
| 512B | 44.85 Gbps | 1.85 Gbps | 45.08 Gbps | 1.85 Gbps | 44.62 Gbps | 1.85 Gbps |
| 1500B | 77.59 Gbps | 5.38 Gbps | 74.44 Gbps | 5.37 Gbps | 75.44 Gbps | 5.40 Gbps |
| 9000B | 96.04 Gbps | 18.96 Gbps | 99.54 Gbps | 19.50 Gbps | 97.23 Gbps | 19.12 Gbps |

#### Latency percentiles (per-packet)

| packet size | inspection | p50 | p95 | p99 | max |
| --- | --- | ---: | ---: | ---: | ---: |
| 64B | no-inspect | 80 ns | 160 ns | 170 ns | 34.033 µs |
| 64B | url-cat | 70 ns | 150 ns | 161 ns | 54.792 µs |
| 64B | full-tls | 70 ns | 150 ns | 161 ns | 43.151 µs |
| 512B | no-inspect | 110 ns | 180 ns | 200 ns | 36.098 µs |
| 512B | url-cat | 110 ns | 190 ns | 200 ns | 36.077 µs |
| 512B | full-tls | 110 ns | 180 ns | 200 ns | 35.817 µs |
| 1500B | no-inspect | 171 ns | 260 ns | 311 ns | 60.743 µs |
| 1500B | url-cat | 161 ns | 240 ns | 261 ns | 35.086 µs |
| 1500B | full-tls | 170 ns | 241 ns | 261 ns | 34.955 µs |
| 9000B | no-inspect | 741 ns | 822 ns | 982 ns | 52.208 µs |
| 9000B | url-cat | 741 ns | 831 ns | 882 ns | 126.086 µs |
| 9000B | full-tls | 742 ns | 832 ns | 1.353 µs | 53.620 µs |

#### Resource utilisation at each throughput operating point

| packet size | inspection | mean CPU | peak RSS (MiB) |
| --- | --- | ---: | ---: |
| 64B | no-inspect | 0.0% | 3.7 |
| 64B | url-cat | 0.0% | 4.1 |
| 64B | full-tls | 0.0% | 4.1 |
| 512B | no-inspect | 0.0% | 4.1 |
| 512B | url-cat | 0.0% | 4.1 |
| 512B | full-tls | 0.0% | 4.1 |
| 1500B | no-inspect | 0.0% | 4.1 |
| 1500B | url-cat | 0.0% | 4.1 |
| 1500B | full-tls | 0.0% | 4.1 |
| 9000B | no-inspect | 0.0% | 4.1 |
| 9000B | url-cat | 0.0% | 4.1 |
| 9000B | full-tls | 0.0% | 4.1 |

### branch-medium (4 vCPU / 8 GB, 10 Gbps NIC)

#### Throughput matrix — max Gbps, dry-run / wire (packet size × inspection)

| packet size | no-inspect dry-run | no-inspect wire | url-cat dry-run | url-cat wire | full-tls dry-run | full-tls wire |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 64B | 8.95 Gbps | 0.25 Gbps | 8.98 Gbps | 0.25 Gbps | 8.96 Gbps | 0.24 Gbps |
| 512B | 46.36 Gbps | 1.92 Gbps | 46.84 Gbps | 1.92 Gbps | 46.06 Gbps | 1.94 Gbps |
| 1500B | 75.93 Gbps | 5.32 Gbps | 75.22 Gbps | 5.28 Gbps | 75.58 Gbps | 5.36 Gbps |
| 9000B | 100.41 Gbps | 18.90 Gbps | 101.08 Gbps | 18.66 Gbps | 100.54 Gbps | 18.48 Gbps |

#### Latency percentiles (per-packet)

| packet size | inspection | p50 | p95 | p99 | max |
| --- | --- | ---: | ---: | ---: | ---: |
| 64B | no-inspect | 80 ns | 160 ns | 170 ns | 37.400 µs |
| 64B | url-cat | 71 ns | 150 ns | 161 ns | 91.972 µs |
| 64B | full-tls | 80 ns | 160 ns | 170 ns | 127.949 µs |
| 512B | no-inspect | 101 ns | 180 ns | 191 ns | 59.741 µs |
| 512B | url-cat | 110 ns | 190 ns | 200 ns | 37.660 µs |
| 512B | full-tls | 100 ns | 171 ns | 191 ns | 187.149 µs |
| 1500B | no-inspect | 170 ns | 260 ns | 271 ns | 41.227 µs |
| 1500B | url-cat | 171 ns | 260 ns | 270 ns | 52.969 µs |
| 1500B | full-tls | 171 ns | 260 ns | 271 ns | 56.726 µs |
| 9000B | no-inspect | 731 ns | 821 ns | 1.193 µs | 39.023 µs |
| 9000B | url-cat | 731 ns | 821 ns | 972 ns | 37.019 µs |
| 9000B | full-tls | 731 ns | 821 ns | 1.253 µs | 40.776 µs |

#### Resource utilisation at each throughput operating point

| packet size | inspection | mean CPU | peak RSS (MiB) |
| --- | --- | ---: | ---: |
| 64B | no-inspect | 0.0% | 4.1 |
| 64B | url-cat | 0.0% | 4.1 |
| 64B | full-tls | 0.0% | 4.1 |
| 512B | no-inspect | 0.0% | 4.1 |
| 512B | url-cat | 0.0% | 4.1 |
| 512B | full-tls | 0.0% | 4.1 |
| 1500B | no-inspect | 0.0% | 4.1 |
| 1500B | url-cat | 0.0% | 4.1 |
| 1500B | full-tls | 0.0% | 4.1 |
| 9000B | no-inspect | 0.0% | 4.1 |
| 9000B | url-cat | 0.0% | 4.1 |
| 9000B | full-tls | 0.0% | 4.1 |

### branch-small (2 vCPU / 4 GB, 1 Gbps NIC)

#### Throughput matrix — max Gbps, dry-run / wire (packet size × inspection)

| packet size | no-inspect dry-run | no-inspect wire | url-cat dry-run | url-cat wire | full-tls dry-run | full-tls wire |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 64B | 8.77 Gbps | 0.24 Gbps | 8.91 Gbps | 0.25 Gbps | 8.68 Gbps | 0.24 Gbps |
| 512B | 46.03 Gbps | 1.89 Gbps | 45.57 Gbps | 1.89 Gbps | 47.10 Gbps | 1.92 Gbps |
| 1500B | 74.05 Gbps | 5.32 Gbps | 74.59 Gbps | 5.33 Gbps | 75.07 Gbps | 5.28 Gbps |
| 9000B | 97.85 Gbps | 18.69 Gbps | 99.69 Gbps | 18.81 Gbps | 98.16 Gbps | 18.70 Gbps |

#### Latency percentiles (per-packet)

| packet size | inspection | p50 | p95 | p99 | max |
| --- | --- | ---: | ---: | ---: | ---: |
| 64B | no-inspect | 71 ns | 150 ns | 161 ns | 43.301 µs |
| 64B | url-cat | 70 ns | 150 ns | 170 ns | 95.158 µs |
| 64B | full-tls | 71 ns | 150 ns | 161 ns | 35.787 µs |
| 512B | no-inspect | 101 ns | 180 ns | 191 ns | 65.773 µs |
| 512B | url-cat | 110 ns | 180 ns | 191 ns | 36.148 µs |
| 512B | full-tls | 110 ns | 181 ns | 191 ns | 104.214 µs |
| 1500B | no-inspect | 171 ns | 261 ns | 331 ns | 56.345 µs |
| 1500B | url-cat | 170 ns | 240 ns | 261 ns | 51.877 µs |
| 1500B | full-tls | 170 ns | 241 ns | 261 ns | 36.849 µs |
| 9000B | no-inspect | 741 ns | 822 ns | 882 ns | 77.013 µs |
| 9000B | url-cat | 741 ns | 822 ns | 1.092 µs | 37.099 µs |
| 9000B | full-tls | 741 ns | 821 ns | 882 ns | 36.689 µs |

#### Resource utilisation at each throughput operating point

| packet size | inspection | mean CPU | peak RSS (MiB) |
| --- | --- | ---: | ---: |
| 64B | no-inspect | 0.0% | 4.1 |
| 64B | url-cat | 0.0% | 4.1 |
| 64B | full-tls | 0.0% | 4.1 |
| 512B | no-inspect | 0.0% | 4.1 |
| 512B | url-cat | 0.0% | 4.1 |
| 512B | full-tls | 0.0% | 4.1 |
| 1500B | no-inspect | 0.0% | 4.1 |
| 1500B | url-cat | 0.0% | 4.1 |
| 1500B | full-tls | 0.0% | 4.1 |
| 9000B | no-inspect | 0.0% | 4.1 |
| 9000B | url-cat | 0.0% | 4.1 |
| 9000B | full-tls | 0.0% | 4.1 |

### cloud-pop-small (4 vCPU / 8 GB, 10 Gbps NIC)

#### Throughput matrix — max Gbps, dry-run / wire (packet size × inspection)

| packet size | no-inspect dry-run | no-inspect wire | url-cat dry-run | url-cat wire | full-tls dry-run | full-tls wire |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 64B | 8.78 Gbps | 0.24 Gbps | 9.06 Gbps | 0.24 Gbps | 9.01 Gbps | 0.24 Gbps |
| 512B | 46.61 Gbps | 1.90 Gbps | 45.55 Gbps | 1.91 Gbps | 45.92 Gbps | 1.80 Gbps |
| 1500B | 74.62 Gbps | 5.26 Gbps | 74.60 Gbps | 5.29 Gbps | 75.55 Gbps | 5.27 Gbps |
| 9000B | 97.20 Gbps | 18.53 Gbps | 96.56 Gbps | 18.85 Gbps | 96.30 Gbps | 19.51 Gbps |

#### Latency percentiles (per-packet)

| packet size | inspection | p50 | p95 | p99 | max |
| --- | --- | ---: | ---: | ---: | ---: |
| 64B | no-inspect | 70 ns | 150 ns | 161 ns | 36.878 µs |
| 64B | url-cat | 71 ns | 151 ns | 161 ns | 119.023 µs |
| 64B | full-tls | 70 ns | 150 ns | 161 ns | 58.910 µs |
| 512B | no-inspect | 110 ns | 181 ns | 200 ns | 48.010 µs |
| 512B | url-cat | 110 ns | 190 ns | 201 ns | 147.756 µs |
| 512B | full-tls | 110 ns | 190 ns | 201 ns | 38.101 µs |
| 1500B | no-inspect | 171 ns | 260 ns | 270 ns | 41.297 µs |
| 1500B | url-cat | 171 ns | 260 ns | 261 ns | 99.926 µs |
| 1500B | full-tls | 171 ns | 260 ns | 261 ns | 41.136 µs |
| 9000B | no-inspect | 741 ns | 831 ns | 1.272 µs | 45.976 µs |
| 9000B | url-cat | 741 ns | 831 ns | 1.252 µs | 56.305 µs |
| 9000B | full-tls | 741 ns | 831 ns | 1.183 µs | 44.373 µs |

#### Resource utilisation at each throughput operating point

| packet size | inspection | mean CPU | peak RSS (MiB) |
| --- | --- | ---: | ---: |
| 64B | no-inspect | 0.0% | 4.1 |
| 64B | url-cat | 0.0% | 4.1 |
| 64B | full-tls | 0.0% | 4.1 |
| 512B | no-inspect | 0.0% | 4.1 |
| 512B | url-cat | 0.0% | 4.1 |
| 512B | full-tls | 0.0% | 4.1 |
| 1500B | no-inspect | 0.0% | 4.1 |
| 1500B | url-cat | 0.0% | 4.1 |
| 1500B | full-tls | 0.0% | 4.1 |
| 9000B | no-inspect | 0.0% | 4.1 |
| 9000B | url-cat | 0.0% | 4.1 |
| 9000B | full-tls | 0.0% | 4.1 |

## Competitor comparison

Competitor figures are vendor-published throughput for purpose-built hardware/ASIC appliances; SNG is software-only on a generic x86 VM. The comparison is informative, **not** apples-to-apples. SNG numbers are the measured 1500B peak at each inspection depth, shown for both the dry-run ceiling and the real-wire floor.

### branch-large (vs 8-core class)

| competitor | firewall (no-inspect) | NGFW (url-cat) | IPS/threat (full-tls) | source |
| --- | ---: | ---: | ---: | --- |
| **SNG branch-large** (dry-run) | 77.59 Gbps | 74.44 Gbps | 75.44 Gbps | sng-bench |
| **SNG branch-large** (wire) | 5.38 Gbps | 5.37 Gbps | 5.40 Gbps | sng-bench |
| Fortinet FortiGate 100F | 20.00 Gbps | 1.60 Gbps | 2.60 Gbps | FortiGate 100F datasheet (firewall / IPS / NGFW throughput, 1518B UDP) |

- SNG 5.38 Gbps (software, VM) vs Fortinet FortiGate 100F 20.00 Gbps published (-73%) — informative, not apples-to-apples: NP6Lite/CP9 ASIC fixed appliance; SNG is software-only on a generic x86 VM
- SNG 5.37 Gbps (software, VM) vs Fortinet FortiGate 100F 1.60 Gbps published (+236%) — informative, not apples-to-apples: NP6Lite/CP9 ASIC fixed appliance; SNG is software-only on a generic x86 VM
- SNG 5.40 Gbps (software, VM) vs Fortinet FortiGate 100F 2.60 Gbps published (+108%) — informative, not apples-to-apples: NP6Lite/CP9 ASIC fixed appliance; SNG is software-only on a generic x86 VM

### branch-medium (vs 4-core class)

| competitor | firewall (no-inspect) | NGFW (url-cat) | IPS/threat (full-tls) | source |
| --- | ---: | ---: | ---: | --- |
| **SNG branch-medium** (dry-run) | 75.93 Gbps | 75.22 Gbps | 75.58 Gbps | sng-bench |
| **SNG branch-medium** (wire) | 5.32 Gbps | 5.28 Gbps | 5.36 Gbps | sng-bench |
| Fortinet FortiGate 60F | 10.00 Gbps | 1.00 Gbps | 1.40 Gbps | FortiGate 60F datasheet (firewall / IPS / NGFW throughput, 1518B UDP) |
| Palo Alto PA-450 | 5.20 Gbps | — | 1.60 Gbps | PA-400 series datasheet (firewall / threat-prevention throughput) |
| Check Point 3600 | 3.40 Gbps | — | 0.65 Gbps | Check Point 3600 datasheet (firewall / IPS throughput) |

- SNG 5.32 Gbps (software, VM) vs Fortinet FortiGate 60F 10.00 Gbps published (-47%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 5.32 Gbps (software, VM) vs Palo Alto PA-450 5.20 Gbps published (+2%) — informative, not apples-to-apples: single-pass hardware appliance; SNG is software-only on a generic x86 VM
- SNG 5.32 Gbps (software, VM) vs Check Point 3600 3.40 Gbps published (+57%) — informative, not apples-to-apples: fixed security appliance; SNG is software-only on a generic x86 VM
- SNG 5.28 Gbps (software, VM) vs Fortinet FortiGate 60F 1.00 Gbps published (+428%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 5.36 Gbps (software, VM) vs Fortinet FortiGate 60F 1.40 Gbps published (+283%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 5.36 Gbps (software, VM) vs Palo Alto PA-450 1.60 Gbps published (+235%) — informative, not apples-to-apples: single-pass hardware appliance; SNG is software-only on a generic x86 VM
- SNG 5.36 Gbps (software, VM) vs Check Point 3600 0.65 Gbps published (+724%) — informative, not apples-to-apples: fixed security appliance; SNG is software-only on a generic x86 VM

### branch-small (vs 2-core class)

| competitor | firewall (no-inspect) | NGFW (url-cat) | IPS/threat (full-tls) | source |
| --- | ---: | ---: | ---: | --- |
| **SNG branch-small** (dry-run) | 74.05 Gbps | 74.59 Gbps | 75.07 Gbps | sng-bench |
| **SNG branch-small** (wire) | 5.32 Gbps | 5.33 Gbps | 5.28 Gbps | sng-bench |
| Fortinet FortiGate 40F | 5.00 Gbps | 0.60 Gbps | 0.80 Gbps | FortiGate 40F datasheet (firewall / IPS / NGFW throughput, 1518B UDP) |
| Palo Alto PA-440 | 3.10 Gbps | — | 0.70 Gbps | PA-400 series datasheet (firewall / threat-prevention throughput) |

- SNG 5.32 Gbps (software, VM) vs Fortinet FortiGate 40F 5.00 Gbps published (+6%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 5.32 Gbps (software, VM) vs Palo Alto PA-440 3.10 Gbps published (+72%) — informative, not apples-to-apples: single-pass hardware appliance; SNG is software-only on a generic x86 VM
- SNG 5.33 Gbps (software, VM) vs Fortinet FortiGate 40F 0.60 Gbps published (+788%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 5.28 Gbps (software, VM) vs Fortinet FortiGate 40F 0.80 Gbps published (+561%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 5.28 Gbps (software, VM) vs Palo Alto PA-440 0.70 Gbps published (+655%) — informative, not apples-to-apples: single-pass hardware appliance; SNG is software-only on a generic x86 VM

### cloud-pop-small (vs 4-core class)

| competitor | firewall (no-inspect) | NGFW (url-cat) | IPS/threat (full-tls) | source |
| --- | ---: | ---: | ---: | --- |
| **SNG cloud-pop-small** (dry-run) | 74.62 Gbps | 74.60 Gbps | 75.55 Gbps | sng-bench |
| **SNG cloud-pop-small** (wire) | 5.26 Gbps | 5.29 Gbps | 5.27 Gbps | sng-bench |
| Fortinet FortiGate 60F | 10.00 Gbps | 1.00 Gbps | 1.40 Gbps | FortiGate 60F datasheet (firewall / IPS / NGFW throughput, 1518B UDP) |
| Palo Alto PA-450 | 5.20 Gbps | — | 1.60 Gbps | PA-400 series datasheet (firewall / threat-prevention throughput) |
| Check Point 3600 | 3.40 Gbps | — | 0.65 Gbps | Check Point 3600 datasheet (firewall / IPS throughput) |

- SNG 5.26 Gbps (software, VM) vs Fortinet FortiGate 60F 10.00 Gbps published (-47%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 5.26 Gbps (software, VM) vs Palo Alto PA-450 5.20 Gbps published (+1%) — informative, not apples-to-apples: single-pass hardware appliance; SNG is software-only on a generic x86 VM
- SNG 5.26 Gbps (software, VM) vs Check Point 3600 3.40 Gbps published (+55%) — informative, not apples-to-apples: fixed security appliance; SNG is software-only on a generic x86 VM
- SNG 5.29 Gbps (software, VM) vs Fortinet FortiGate 60F 1.00 Gbps published (+429%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 5.27 Gbps (software, VM) vs Fortinet FortiGate 60F 1.40 Gbps published (+276%) — informative, not apples-to-apples: SoC4-accelerated fixed appliance; SNG is software-only on a generic x86 VM
- SNG 5.27 Gbps (software, VM) vs Palo Alto PA-450 1.60 Gbps published (+229%) — informative, not apples-to-apples: single-pass hardware appliance; SNG is software-only on a generic x86 VM
- SNG 5.27 Gbps (software, VM) vs Check Point 3600 0.65 Gbps published (+710%) — informative, not apples-to-apples: fixed security appliance; SNG is software-only on a generic x86 VM

## Cost analysis

SNG cloud opex, assuming **$0.0416/vCPU-hour** (representative public-cloud general-purpose on-demand, us-east-1) over **730 hours/month**. $/Gbps uses the **real-wire** firewall peak (the number an operator actually provisions against); the dry-run $/Gbps is shown alongside as the synthetic floor on cost. Appliance capex / support TCO is vendor-quote territory and intentionally **not** invented here.

| SKU | vCPU | est. $/mo | firewall wire Gbps | $/Gbps (wire) | firewall dry-run Gbps | $/Gbps (dry-run) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| branch-large | 8 | $243 | 18.96 Gbps | $13 | 96.04 Gbps | $3 |
| branch-medium | 4 | $121 | 18.90 Gbps | $6 | 100.41 Gbps | $1 |
| branch-small | 2 | $61 | 18.69 Gbps | $3 | 97.85 Gbps | $1 |
| cloud-pop-small | 4 | $121 | 18.53 Gbps | $7 | 97.20 Gbps | $1 |

