### Project Overview
This project implements a router simulation that handles packet forwarding, ARP (Address Resolution Protocol) requests and replies, ICMP (Internet Control Message Protocol) communication, and LPM (Longest Prefix Match) using a trie-based structure for efficient route lookup.

The main components of the router include:

1. **Packet Queue** - A FIFO queue that stores packets waiting for ARP resolution.
2. **ARP Table** - A lookup table for MAC addresses associated with IP addresses.
3. **Routing Table** - A trie-based implementation for fast Longest Prefix Match (LPM) lookups.
4. **ICMP Handling** - Custom-built packets for ICMP Echo Reply, Time Exceeded, and Destination Unreachable.

---

### Data Structures

#### 1. `trie_node`
Represents a node in the trie structure used for fast LPM lookups. It contains:
- `children`: An array of child nodes (0 and 1).
- `route`: A pointer to the route associated with this node if it matches an IP prefix.

##### Functions:
- `insert_route`: Inserts a route into the trie by traversing bit by bit and creating new nodes if necessary.
- `route_table_entry`: Searches for the longest prefix match for a given IP address.


#### 2. `packet`
A structure for storing packet data in the queue, including:
- `payload`: The packet data.
- `length`: The size of the packet.
- `interface`: The network interface to be used.
- `next_hop`: The next hop IP address for ARP resolution.

---

### Main Logic Flow

#### **Initialization**
1. Create packet queue, ARP table, routing table, and trie structure.

#### **Packet Processing**

1. **Ethernet Header Analysis**
   - If `0x0800`: IPv4 packet
   - If `0x0806`: ARP packet

---

### IPv4 Packet Handling

2. **ICMP Processing**
   - If the packet is for the router:
     - If it's ICMP Echo Request, construct an Echo Reply and send it back.

3. **Checksum and TTL Verification**
   - If the checksum is invalid, the packet is dropped.
   - If TTL < 1, an ICMP Time Exceeded packet is sent back.

4. **Longest Prefix Match (LPM)**
   - Search the trie for the best matching route.
   - If no route is found, send ICMP Destination Unreachable.

5. **Packet Forwarding**
   - Decrease TTL and recalculate checksum.
   - Update the source MAC with the router's interface MAC.

6. **ARP Resolution**
   - If the MAC address of the next hop is unknown:
     - Create an ARP Request and enqueue the packet.
     - When the ARP Reply is received, dequeue and forward the packet.

---

### ARP Packet Handling

1. **Request Processing**
   - If it's an ARP Request for the router, construct a reply and send it back.

2. **Reply Processing**
   - Add the MAC address to the ARP table.
   - Forward any queued packets waiting for this MAC address.
