# Running PINT on Mininet

This repository gives the sample code to run and test PINT on Mininet.

## Requirements
1. Mininet supporting bmv2 (https://github.com/nsg-ethz/p4-learning)
2. networkx (pip install networkx)
3. scapy (pip install scapy)
4. numpy (pip install numpy)

## Steps to run PINT
- Create topology.

Ensure you are running this in VM with Mininet.
Create a Mininet topology to conduct path tracing on path size N.

`python topo_allocator.py 5`

where 5 indicates that path tracing needs to be conducted on five switches. In our paper, we used N= 5, 36, 59.

- Start Mininet.

Start Mininet with the newly constructed topology.

`sudo p4run --config p4app.json`

- Start path tracing.

Start path tracing by specifying the length of path (N).

`sudo python exp.py 5`

where 5 indicates the length of path.

- Generate results.

Generate results using:

`python analyze.py`
