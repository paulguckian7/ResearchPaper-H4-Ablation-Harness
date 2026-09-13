# Case record: Federated token forgery

Assessed against rules R4-R6 of the companion paper's Method section (frame, node/governance partition, evidence per condition). Extracted from the paper's own Demonstration section (Section 6) -- this is the same analysis stated in the manuscript, deposited here as a standalone, citable record.

# Federated token forgery: conferring External Trust

## Frame
 In May and June 2023 an actor accessed Exchange Online mailboxes of 22 organisations and over 500 individuals using tokens signed with a consumer account signing key created in 2016, which the service's token validation accepted for enterprise access. Two frames are stated. In the service frame, the acting mechanism is the mail service and the issuer is the provider's signing infrastructure, in the same governance domain. In the customer frame, the assessing domain is a customer organisation, which designated the provider as both identity issuer and mail service.

## Operation, service frame
 *Invariant:* a tenant's mailbox contents are disclosed only to principals authorised by that tenant. *Operation:* disclose contents to a requester whose token was not issued for that tenant's principals. *Interface:* present; the mail access interface admits requests bearing tokens that pass validation, and validation at the time admitted tokens signed with the consumer key. *Execution Pathway:* present, local to the service; request handling reaches mailbox retrieval. *Authority:* present, relational; the control exercised is that the token's signature establishes, which is a conferring Control Plane from the signing infrastructure. *Payload:* forged tokens. *Delivery:* externally initiated.

## System-of-systems structure
 In the customer frame every instance has gamma=1 (governance-crossing): the mechanism, its route, the issuer and the state are governed elsewhere. The relation is conferring External Trust of high fan-out: one signing key supplied it for every tenant whose enterprise tokens the service would accept from that key, and the review board observed that the reach of a single key can be very large. The case is also a custody arrangement, in which the implicated state is held under Authority exercised in another domain (Section~(see main text)).

## What the case tests
 Two ablations are analytically separable. Withdrawing trust in the consumer key for enterprise tokens denies admission, an Interface ablation. Restricting the audiences and tenants for which that key's tokens establish Authority, while its tokens continue to be admitted for the consumer service, is a source-specific Authority ablation. The incident is naturally described as a failure of the second: a key scoped to one population conferred Authority over another. That the case separates the two in analysis supports the Authority-row placement of the conferring form. Whether the service's implementation separated them is a question for the testbed of Section~(see main text), not something the review establishes.
