# Case record: Dyn DDoS

Assessed against rules R4-R6 of the companion paper's Method section (frame, node/governance partition, evidence per condition). Extracted from the paper's own Demonstration section (Section 6) -- this is the same analysis stated in the manuscript, deposited here as a standalone, citable record.

# Denial of service against a concentrated provider

## Frame
 On 21 October 2016 a Mirai botnet directed traffic at Dyn's managed DNS infrastructure, disrupting access to services whose authoritative DNS Dyn hosted. Domains: Dyn (d_D); customer organisations (d_{c}); end users and their resolvers; device owners; the botnet operator.

## Operation, at Dyn
 *Invariant:* authoritative servers answer legitimate queries for customer zones. *Operation:* exhaust resources so that legitimate queries go unanswered. *Interface:* present, relational; public query admission from a very large source population. *Execution Pathway:* present, local; query processing. *Authority:* present, local; the service's control over its own resource allocation. *Payload:* the traffic. *Delivery:* externally initiated, from devices under the direction of a command channel acquired by compromise, which under R6 is not a Control Plane of the devices' owners.

Every condition is present, as it is for the service working normally, and the node-level account describes the mechanism without explaining why volume matters~. That is not remedied here and is not a counterexample: magnitude is excluded by the snapshot criterion.

## System-of-systems structure
 For the operation *an end user reaches a customer's service by name*, resolution routes traverse the customer's authoritative servers, so every customer whose routes traversed Dyn had a Dependency on it by~(see main text), and that Dependency had high fan-out across Dyn's customers. Where Dyn was the only authoritative provider it was also a Cut. Where a customer used a second, independently operated provider on separate infrastructure it was not. The pair is an H5 matched configuration: nothing at any node the customer operates differs between them.

## What the case shows
 The structural account identifies which domains' operations lose their Execution Pathway when a node is removed, independently of how it is removed or how much traffic removal takes: exactly those for which the node is a Cut. It does not say how much traffic that is, or how badly customers with a second provider were degraded, which is a question of capacity. The case also shows why fan-out and Cut are operators rather than cells. What made the incident reach many parties was a Dependency of high fan-out with Cut; CrowdStrike (Section~(see main text)) turned on External Trust of high fan-out. The two share no relation class and share both operators. Measurement work has since found critical dependence on single third-party DNS providers to remain common among popular sites.
