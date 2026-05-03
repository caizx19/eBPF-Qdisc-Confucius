# eBPF Confucius Qdisc

This repository implements the Confucius queueing discipline presented in Meng's PhD. thesis (https://zilimeng.com/papers/phd_thesis.pdf) using eBPF. It is a simplified version where the weight of each queue is predefined and constant.

## Content
* **Flow Classification:** Dynamically identifies greedy flows (queue length > 15) and real-time flows (queue length < 5), assigning them fair-share and high-priority target weights, respectively.
* **EWMA Weight Smoothing:** Utilizes Exponentially Weighted Moving Average (EWMA) with a shift factor of 4 (alpha = 1/16) to smoothly transition weights.
* **Deficit Weighted Round Robin (DWRR):** Employs a credit-based polling mechanism for fair and efficient dequeuing.

## Tests
Due to the lack of a dedicated testbed, this eBPF Confucius Qdisc has only been attached to the NIC and can successfully schedule traffic, but its core functions, such as smooth weight shifting and periodic detection of flow queue occupancy, have not been fully tested.
