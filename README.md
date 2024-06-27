Enescu Maria 321CA

# Dataplane Router

This project focuses on implementing the dataplane router component.
The following tasks have been successfully completed:
* `Routing process implementation`
* `Efficient Longest Prefix Match algorithm`
* `ICMP (Internet Control Message Protocol) protocol implementation`

### Project Structure Starting from the Main Function

- **Routing Process Implementation**
    - I read and sorted the routing table, using qsort I sorted it
    in ascending order by prefix and mask.
    - I parsed the ARP table to associate IP addresses with MAC addresses.

   - **IPv4 Packet Management**:
        - I check if the received packet is of IPv4 type:
            - I check if the packet is intended for the router:
            - **Implementarea Protocolului ICMP**:
              - I check if the packet is an ICMP Echo Request:
                  - I call the `handle_icmp_echo_request` function which
                  sends the packet back from where it came by swapping the
                  addresses in the IP and MAC headers from destination
                  to source, and generates an ICMP Echo Reply response.

- Every received IP packet is checked by calling the `verify_ip_packet
function, which involves the following cases:
   - If the packet is not valid, it returns `false`, and its processing is
    interrupted with `continue`, avoiding further operations on a corrupt or
    expiring packet, with the cases being:
       - **Implementarea Protocolului ICMP**:
           - if the packet's Time to Live has expired, the `error` function
            generates and sends an `ICMP error packet of type 11 (Time Exceeded)`;
           - the original checksum is saved, and the checksum in the IP header
            is reset to 0 to calculate the sum of the current header,
            if the calculated checksum does not match the original, the packet
            is considered corrupt;
   - If the packet is valid, it returns `true`, the TTL is decremented,
    indicating that the packet has made a jump, the checksum is recalculated
    and updated in the IP header to reflect the change.

- The `route_packet` function is called for every IP packet validated by
`verify_ip_packet`, involving the following steps in the routing process:
   - **Efficient Algorithm for Longest Prefix Match**:
       - Binary search is used to find the best match for the destination
       IP address in the packet header. This determines the
       next destination (next hop) or the interface through which the packet
       should be sent;
       - **Implementarea Protocolului ICMP**:
            - If no route is found, `index_match == -1`, meaning the router does
            not have a path to the destination, so the `error` function is called
            to generate and send an `ICMP error packet of type 3 (Destination Unreachable)`;
       - Then, the packet is dispatched to the final destination or next hop through
       the specified interface in the corresponding entry from the routing table.

