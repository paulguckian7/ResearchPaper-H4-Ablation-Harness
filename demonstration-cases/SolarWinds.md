# Case record: SolarWinds

Assessed against rules R4-R6 of the companion paper's Method section (frame, node/governance partition, evidence per condition). Extracted from the paper's own Demonstration section (Section 6) -- this is the same analysis stated in the manuscript, deposited here as a standalone, citable record.

# SolarWinds at ecosystem scale

The node-level paper analysed installation and command-and-control at a customer server~. At ecosystem scale the update channel is a governance-crossing directing relation from the vendor to each customer, classified as directing External Trust where a source-specific Authority ablation exists for the updating mechanism (Section~(see main text)), and the vendor reported that fewer than 18,000 customers may have installed affected versions, which bounds kappa from above in customer domains.

## Relocation
 Signing governed admission, and the node-level analysis placed it on Interface. Signing relocated the trust from the distribution channel to the vendor's build and signing process. The malicious code was introduced upstream of signing, so the signature correctly attested the vendor's endorsement of what it had built. An admission control that verifies origin cannot internalise selection of content, which is the form H6 takes. A customer review of the update would have internalised the decision to install; whether it would have internalised selection depends on whether review could have detected what the build contained, which is the capacity bound stated with H6.

## A second crossing
 CISA reported that the actor forged authentication tokens after obtaining federation signing material, and used them against cloud-hosted resources. In the frame of a cloud service configured to trust a customer's federation infrastructure, that infrastructure is an external issuer designated by tenant configuration, and the relation is conferring External Trust in the opposite direction to the update channel. One campaign therefore traversed a directing relation from vendor to customer and a conferring relation from customer to cloud provider. In the node-level paper's notation, a completed operation conferred the conditions of the next~, and each conferral here crossed a governance boundary.
