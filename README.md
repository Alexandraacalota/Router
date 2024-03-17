Copyright 2023 Alexandra-Maria Calota
# Dataplane Router

## Overview

The Dataplane Router is a robust networking tool equipped with essential functionalities for packet routing and handling. Below are the key features and implementation details of the router.

## Functionalities

- **Forwarding:** The router can efficiently send IPv4 packets to their intended destinations.
- **ARP Protocol:** It supports the Address Resolution Protocol (ARP), enabling the sending and receiving of ARP packets, including requests and replies.

## Router Implementation

### Routing and ARP Tables

- **Routing Table:** The router allocates and utilizes a routing table, typically read from a text file. This table helps determine the best route for packets based on their destination IP addresses.
- **ARP Table:** The ARP table is dynamic, with entries added only after receiving ARP packets. This table is crucial for mapping IP addresses to MAC addresses.

### Packet Processing

#### IPv4 Packets

1. **Data Integrity Check:** The router performs a check to ensure the data integrity of incoming IPv4 packets.
2. **Time to Live (TTL) Check:** It verifies the TTL of the packet and decrements it if it is higher than one.
3. **Routing:** Utilizing the Longest Prefix Match algorithm, the router determines the best route for the packet.
4. **Address Resolution:** If the MAC address of the next hop is not found in the ARP table, the router broadcasts an ARP request to obtain it.
5. **Packet Queueing:** The initial packet is temporarily stored in a queue along with its length.

#### ARP Packets

1. **ARP Request Handling:** When an ARP request is received, the router responds by switching the source and destination addresses and sending an ARP reply.
2. **ARP Reply Handling:** Upon receiving an ARP reply, the router completes the packet's destination MAC address and forwards it to the appropriate interface.

#### Other Packet Types

- **Drop Policy:** If the packet is of a type other than IPv4 or ARP, the router drops it and proceeds to the next packet.

## Conclusion

The Dataplane Router offers a reliable solution for network routing and ARP functionality. Its robust implementation ensures efficient packet handling and routing, making it an invaluable component in modern network infrastructure.
