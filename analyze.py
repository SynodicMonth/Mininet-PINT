import os
import struct
import zlib


def read_config(file_name="config"):
    global_hash_range = 0
    receiver_interface = ""
    receiver_ip = ""
    common_log = ""
    total_packets = 0
    f = open(file_name, "r")
    for line in f:
        line = line.strip().split("=")
        key = line[0]
        value = line[1]
        if key == "global_hash_range":
            global_hash_range = int(value)
        if key == "receiver_interface":
            receiver_interface = value
        if key == "receiver_ip":
            receiver_ip = value
        if key == "common_log":
            common_log = value
        if key == "total_packets":
            total_packets = int(value)
    f.close()

    return global_hash_range, receiver_interface, receiver_ip, common_log, total_packets


def hops_as_route(d):
    # {1: 0, 5: 4, 4: 3, 3: 2, 2: 1} -> 0->1->2->3->4
    sorted_dict = sorted(d.items(), key=lambda x: x[0])
    route = ""
    for item in sorted_dict:
        route += str(item[1]) + "->"
    return route[:-2]


def analyze_file(file_name, mode="PINT8", max_hops=5, global_hash_range=1000000, xor_hash_threshold=100000):
    max_bit_range_map = {"PINT8": 255, "PINT4": 7, "PINT1": 1}
    max_bit_range = max_bit_range_map[mode]
    uncertain_hop_switch_map = {}
    hop_switch_map = {}
    unsolved_xor_hops = []  # in (digest, xored_hop[]) format
    packets_needed = 0
    results = []

    f = open(file_name, "r")
    for line in f:
        packets_needed += 1
        data = line.strip().split(",")
        num_packets = int(data[0])
        ttl = int(data[1])
        pkt_id = int(data[2])
        asm_hash = int(data[3])
        digest_raw = int(data[4])
        actual_switch_id = int(data[5])
        # print(bin(digest_raw))
        if mode == "PINT8":
            digest = (digest_raw & (0xff << 32)) >> 32
        elif mode == "PINT4":
            digest = (digest_raw & (0xf << 16)) >> 16
        else:
            digest = digest_raw & 0x1
        decider_hash = (zlib.crc32(struct.pack("!H",pkt_id)) & 0xffffffff) % 100
        if decider_hash < 50:
            # replacement digest
            # iterate over all the possible hops
            hop = -1
            for i in range(max_hops, 0, -1):
                global_hash = (zlib.crc32(struct.pack("!HI", pkt_id, i)) & 0xffffffff) % global_hash_range
                if global_hash <= global_hash_range / i:
                    # print("Found the hop: ", i)
                    hop = i
                    break
            if hop == -1:
                raise Exception("Hop not found")

            # iterate over all the possible switches
            possible_switches = set()
            for i in range(0, max_hops):
                digest_hash = (zlib.crc32(struct.pack("!IH", i, pkt_id)) & 0xffffffff) % max_bit_range
                if digest_hash == digest:
                    possible_switches.add(i)
                    # print("Found the switch for hop ", hop, ": ", i)
            if len(possible_switches) == 0:
                raise Exception("Switch not found")
            if hop not in uncertain_hop_switch_map:
                uncertain_hop_switch_map[hop] = set(possible_switches)
            else:
                uncertain_hop_switch_map[hop].intersection_update(possible_switches)

            # check if we have found the switch
            if len(uncertain_hop_switch_map[hop]) == 1:
                hop_switch_map[hop] = uncertain_hop_switch_map[hop].pop()
                del uncertain_hop_switch_map[hop]
                # print("Found the switch: ", hop_switch_map[hop], "Groud truth: ", actual_switch_id)
                if hop_switch_map[hop] != actual_switch_id:
                    raise Exception("Switch not found")

            # check if we have found a solution
            if len(hop_switch_map) == max_hops:
                print("Found the solution:", hops_as_route(hop_switch_map), "in", packets_needed, "packets")
                results.append(packets_needed)
                packets_needed = 0
                hop_switch_map = {}
                uncertain_hop_switch_map = {}
                unsolved_xor_hops = []

        else:
            # xor digest
            if digest == 0:
                continue
            # iterate over all the possible hops
            xored_hops = []
            for i in range(max_hops, 0, -1):
                global_hash = (zlib.crc32(struct.pack("!HI", pkt_id, i)) & 0xffffffff) % global_hash_range
                if global_hash <= xor_hash_threshold:
                    xored_hops.append(i)
            if len(xored_hops) == 0:
                raise Exception("No hop found for xor")

            # add the digest to the list
            unsolved_xor_hops.append((digest, xored_hops))

            # decode unsolved_xor_hops if possible
            # unsolved_xor_hops with degree of freedom 1 can be decoded
            # since solving one hop will possibly give information to solve the other hops,
            # so we use a fixed point iteration to solve the hops
            def solvable_hops():
                for i in range(len(unsolved_xor_hops)):
                    digest, xored_hops = unsolved_xor_hops[i]
                    degree_of_freedom = len([x not in hop_switch_map for x in xored_hops])
                    if degree_of_freedom == 1:
                        return i
                return -1

            while True:
                idx = solvable_hops()
                if idx == -1:
                    break  # no more solvable hops
                digest, xored_hops = unsolved_xor_hops[idx]
                remaining_hop = -1
                for i in xored_hops:
                    if i in hop_switch_map:
                        digest ^= hop_switch_map[i]
                    else:
                        remaining_hop = i
                if remaining_hop != -1:
                    hop_switch_map[remaining_hop] = digest
                    # print("Found the switch (xor): ", hop_switch_map[remaining_hop])
                del unsolved_xor_hops[idx]

            # check if we have found a solution
            if len(hop_switch_map) == max_hops:
                print("Found the solution:", hops_as_route(hop_switch_map), "in", packets_needed, "packets")
                results.append(packets_needed)
                packets_needed = 0
                hop_switch_map = {}
                uncertain_hop_switch_map = {}
                unsolved_xor_hops = []

    f.close()
    return results


if __name__ == "__main__":
    global_hash_range, receiver_interface, receiver_ip, common_log, total_packets = read_config()
    results = analyze_file("experiments/5/5/255_1000000", "PINT4", 5, global_hash_range)
    # get avg, median and 99th percentile
    results.sort()
    avg = sum(results) / len(results)
    median = results[len(results) // 2]
    percentile_99 = results[int(len(results) * 0.99)]
    print("Average packets needed:", avg)
    print("Median packets needed:", median)
    print("99th percentile packets needed:", percentile_99)
