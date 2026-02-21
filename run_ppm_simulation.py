from collections import defaultdict
from platform import node
import matplotlib.pyplot as plt
import random

# IP traceback packet structure for PPM
class Packet:
    def __init__(self):
        # node sampling field
        self.node = None
        
        # edge sampling field
        self.start = None
        self.end = None
        self.distance = -1 # -1 is uninitialized packet

def mark_edge_sampling(packet, router_id, p):
    if random.random() < p: # start a new edge marking
        packet.distance = 0 # reset distance
        packet.start = router_id # mark start of edge
    else:
        if packet.distance == 0: # indicates previous router marked the start of edge
            packet.end = router_id # mark end of edge
        if packet.distance != -1: # if packet is initialized, increment distance
            packet.distance += 1 # increment distance for edge sampling

def mark_node_sampling(packet, router_id, p):
    # overwrites previous value in node sampling field with current router ID
    if random.random() < p:
        packet.node = router_id

def perform_traceback(attacker_count, x_rate, p, trials=10):
    # simulate network topology and reconstruction procedure

    # 3 branches
    b1_path = list(range(10, 0, -1)) + [0] # 10 hops from attacker 1 to victim
    b2_path = [14, 13, 12, 11, 3, 2, 1, 0] # 14 hops from attacker 2 to victim, merges with b1 at router 3
    path_b3 = [18, 17, 16, 15, 4, 3, 2, 1, 0] # 18 hops from normal host to victim, merges with b1 at router 4

    # victim attempts to find edges for attacker 1
    attacker_1_edges = []
    for i in range(len(b1_path) - 1):
        dist = len(b1_path) - 2 - i # distance from victim
        attacker_1_edges.append((b1_path[i], b1_path[i+1], dist)) # (start, end, distance)

    avg_edge_acc = 0
    avg_node_acc = 0

    for _ in range(trials):
        node_table = defaultdict(int) # for node sampling reconstruction
        edge_tree = set() # for edge sampling reconstruction
        normal_count = 100
        attacker_count = normal_count * x_rate # attacker rate is x times higher

        # define traffic flow per branch based on 1 or 2 attackers
        scenarios = [
            (b1_path, attacker_count), # attacker 1 traffic
            (b2_path, attacker_count if attacker_count == 2 else normal_count), # attacker 2 traffic or normal traffic if only 1 attacker
            (path_b3, normal_count) # normal traffic
        ]

        # marking procedure
        for path, count in scenarios:
            for _ in range(count):
                pkt = Packet()
                for router_id in path[:-1]: # mark packet at each router along the path except victim (receiver)
                    mark_node_sampling(pkt, router_id, p)
                    mark_edge_sampling(pkt, router_id, p)
                
                # reconstruction procedure
                if pkt.node is not None: # check if packet was marked in node sampling
                    node_table[pkt.node] += 1 # increment count for marked router in node sampling table
                if pkt.start is not None:
                    if pkt.distance == 0: # means the router that marked the packet is the victim's immediate neighbor (no routers in between)
                        edge_tree.add((pkt.start, 0, 0)) # add edge with distance 0 to edge tree
                    elif pkt.end is not None: # captures edge between two routers
                        edge_tree.add((pkt.start, pkt.end, pkt.distance)) # store edge as (start, end, distance) in edge tree
        
        ### evaluate accuracy for node sampling
        
        # # node reconstruction
        # sorted_nodes = [n for n, c in sorted(node_table.items(), key=lambda item: item[1], reverse=True)]
        # top_k = set(sorted_nodes[:len(b1_path)-1])
        # actual = set(b1_path[:-1])
        # avg_node_acc += (len(actual.intersection(top_k)) / len(actual)) * 100

        # # edge Reconstruction
        # found = sum(1 for e in attacker_1_edges if e in edge_tree)
        # avg_edge_acc += (found / len(attacker_1_edges)) * 100


        # convert frequency table into list of (router_id, frequency) and sort by frequency
        node_list = []
        for r_id, count in node_table.items():
            node_list.append([r_id, count])
        
        # sort list so routers with highest frequency are at the top
        node_list.sort(key=lambda x: x[1], reverse=True)

        top_10_frequent_routers = []
        for i in range(min(len(node_list), 10)):
            router_id = node_list[i][0]
            top_10_frequent_routers.append(router_id)
        
        # compare routers against actual attacker path
        correct_nodes_found = 0
        attacker_path_set = set(b1_path[:-1]) # set of routers in attacker 1 path (excluding victim)

        for router_id in top_10_frequent_routers:
            if router_id in attacker_path_set:
                correct_nodes_found += 1

        # calculate percentage accuracy for node sampling
        avg_node_acc += (correct_nodes_found / 10) * 100

        ### evaluate accuracy for edge sampling to see if every edge was captured
        found_edges = 0
        total_edges_to_find = len(attacker_1_edges)
        for edge in attacker_1_edges:
            if edge in edge_tree:
                found_edges += 1
        avg_edge_acc += (found_edges / total_edges_to_find) * 100
    
    return avg_node_acc / trials, avg_edge_acc / trials

def main():
    p = [0.2, 0.4, 0.5, 0.6, 0.8] # sampling probability
    x_rate = [10, 100, 1000] # attacker traffic rate compared to normal traffic

    # plotting results
    fig1, ax1 = plt.subplots()
    for x in x_rate:
        node_acc, edge_acc = [], []
        for prob in p:
            n, e = perform_traceback(1, x, prob)
            node_acc.append(n)
            edge_acc.append(e)
        ax1.plot(p, node_acc, '--o', label=f'Node x={x}')
        ax1.plot(p, edge_acc, '--x', label=f'Edge x={x}')
    ax1.set_title("Attacker vs Normal Traffic")
    ax1.set_xlabel("Marking Probability (p)")
    ax1.set_ylabel("Accuracy (%)")
    ax1.grid(True)
    ax1.legend()
    
    fig2, ax2 = plt.subplots()
    for x in x_rate:
        node_acc, edge_acc = [], []
        for prob in p:
            n, e = perform_traceback(2, x, prob)
            node_acc.append(n)
            edge_acc.append(e)
        ax2.plot(p, node_acc, '--o', label=f'Node x={x}')
        ax2.plot(p, edge_acc, '--x', label=f'Edge x={x}')
    ax2.set_title("2 Attackers vs Normal Traffic")
    ax2.set_xlabel("Marking Probability (p)")
    ax2.set_ylabel("Accuracy (%)")
    ax2.grid(True)
    ax2.legend()

    plt.show()

if __name__ == "__main__":
    main()
