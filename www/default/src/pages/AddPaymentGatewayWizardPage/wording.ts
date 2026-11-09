import type { CompleteStepWording } from '../../components/gateway-add-via-oob/CompleteStep';
import type { DetailsStepWording } from '../../components/gateway-add-via-oob/EnterDetailsStep';
import type { LinkStepWording } from '../../components/gateway-add-via-oob/EnterOOBLinkStep';

export const DETAILS_WORDING: Partial<DetailsStepWording> = {
  title: 'Enter Payment Gateway Details',
  intro:
    'Provide a name and description for the agent-pay gateway you are connecting to. They identify it in Connections → Payment Gateways and in the Payment element of your surfaces.',
  nameLabel: 'Payment Gateway Name',
  namePlaceholder: 'e.g., agent-pay production',
  nameRequired: 'Payment gateway name is required',
};

export const LINK_WORDING: Partial<LinkStepWording> = {
  intro:
    "Enter the Connection Point Link and secret that agent-pay's administrator shared with you. agent-pay must expose a payment surface on that connection point for your surfaces to charge through it.",
  helpBody:
    "agent-pay's administrator creates a Connection Point in agent-pay and shares its link and secret with you. This gateway uses them to set up a secure DIDComm connection to agent-pay, which its administrator then approves.",
};

export const COMPLETE_WORDING: Partial<CompleteStepWording> = {
  heading: 'Payment gateway ready',
  body: "agent-pay approved the connection and answers as a payment gateway. Pick it in a surface's Payment element to charge through it.",
  viewLabel: 'View Payment Gateway',
};
