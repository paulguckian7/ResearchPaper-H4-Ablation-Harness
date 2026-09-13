# Case record: CrowdStrike

Assessed against rules R4-R6 of the companion paper's Method section (frame, node/governance partition, evidence per condition). Extracted from the paper's own Demonstration section (Section 6) -- this is the same analysis stated in the manuscript, deposited here as a standalone, citable record.

# CrowdStrike at ecosystem scale

The node-level analysis of the sensor, Channel File 291 and automatic delivery is unchanged~. The frame is widened to the vendor's publishing mechanism (d_v), customer organisations (d_1, ..., d_n) and organisations consuming services those customers provide.

## System-of-systems structure
 The content channel is a directing relation from the vendor's publishing mechanism to the sensor, designated by each customer on installation. A source-specific Authority ablation exists for it (paragraph H4 below), so it is classified as directing External Trust. The vendor's review distinguished Sensor Content, whose deployment customers controlled through sensor update policy, from Rapid Response Content, delivered by the vendor; the latter is the relation analysed. Its fan-out kappa counts customer domains, and the publishing mechanism is also a Concentration, the entry point for content into every customer's hosts. Microsoft's estimate counted devices, not domains, and the two should not be conflated. For each customer the publishing mechanism was a Cut for content updates, since no alternative source was designated. Dependency arises where an organisation that did not run the sensor had operations whose routes traversed systems of one that did, with Cut where those were its only routes. The structure predicts such effects; public reporting is consistent with them, and they were not coded here.

## Corollary 2
 The channel is an adaptation channel with an independently governed source, and by~(see main text) no customer could deny its conditions while retaining content updates from the vendor.

## H4
 Microsoft subsequently announced a Windows endpoint security platform intended to allow security products to run outside kernel mode. In the terms of Table~(see main text), this is a source-specific Authority ablation for the directing relation: vendor content continues to be admitted and routed, and the mechanism processing it lacks the kernel-state control the node-level operation implicated. The directing form has the predicted ablation for this relation. That is a demonstration of existence, not a test.

## H6
 The vendor committed to give customers granular control over when and where Rapid Response Content is deployed. Control over where is structural: it changes which hosts admit the content. Control over when is dynamic and outside this paper. Neither gives the customer a mechanism that evaluates what the content instructs. H6 therefore predicts that the External Trust relation persists after the change, with its admission scope internalised and its selection not.
