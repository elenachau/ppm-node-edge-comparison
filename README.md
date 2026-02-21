# Probabilistic Packet Marking Simulation

## Overview

Simulate **Probabilistic Packet Marking (PPM)** and compare:

- Node Sampling  
- Edge Sampling  

Evaluate traceback accuracy for DoS attacks under varying marking probabilities and attack rates.

---

## Network Constraints

- Max hops: ≤ 15  
- Routers: 10–20  
- Branches: 3–5  
- Unique router IDs  
- Attackers at branch ends (≤ 1 per branch)  
- Normal users send low-rate traffic  

---

## Parameters

**Marking probability**  
`p ∈ {0.2, 0.4, 0.5, 0.6, 0.8}`  

**Attack rate multiplier**  
`x ∈ {10, 100, 1000}`

Attackers send packets at `x` times normal rate.

---

## Experiments

### 1. Single Attacker
- 1 attacker + 1 normal user  
- Compare node vs edge sampling  
- Plot accuracy vs `p` and `x`

### 2. Two Attackers
- 2 attackers + 1 normal user  
- Repeat full comparison  

---