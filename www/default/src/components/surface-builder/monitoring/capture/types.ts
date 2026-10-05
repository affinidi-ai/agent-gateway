export interface CapturedPayload {
  timestamp: Date;
  payload: any;
  response_payload?: any;
  outbound_request?: any;
  inbound_response?: any;
  channel: string;
  validation_status: string;
  validation_error?: string;
}

export interface DisplayedCaptureMeta {
  timestamp: Date;
  channel: string;
}

export const MAX_HISTORY = 10;
