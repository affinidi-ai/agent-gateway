import { useEffect, useRef, useState } from 'react';
import { CapturedPayload, DisplayedCaptureMeta, MAX_HISTORY } from './types';

export interface CaptureStreamState {
  captured: CapturedPayload[];
  count: number;
  isPaused: boolean;
  latestInboundRequest: string;
  latestOutboundRequest: string;
  latestInboundResponse: string;
  latestOutboundResponse: string;
  latestValidationStatus: string;
  latestValidationError?: string;
  displayedCapture: DisplayedCaptureMeta | null;
}

export interface CaptureStreamActions {
  setPaused: (paused: boolean) => void;
  clear: () => void;
  loadCapture: (capture: CapturedPayload) => void;
}

const EMPTY: CaptureStreamState = {
  captured: [],
  count: 0,
  isPaused: false,
  latestInboundRequest: '',
  latestOutboundRequest: '',
  latestInboundResponse: '',
  latestOutboundResponse: '',
  latestValidationStatus: 'success',
  latestValidationError: undefined,
  displayedCapture: null,
};

/**
 * Subscribes to `payload_captured` ws-message custom events and keeps a
 * ring buffer of the last `MAX_HISTORY` captures whose `config_id` matches
 * the supplied surface id. The hook is otherwise self-contained: callers
 * just render its state.
 */
export function useSurfaceCaptureStream(
  configId: string
): CaptureStreamState & CaptureStreamActions {
  const [state, setState] = useState<CaptureStreamState>(EMPTY);
  const isPausedRef = useRef(false);

  useEffect(() => {
    isPausedRef.current = state.isPaused;
  }, [state.isPaused]);

  useEffect(() => {
    const handler = (event: Event) => {
      const data = (event as CustomEvent).detail;
      if (!data || data.type !== 'payload_captured' || data.config_id !== configId) return;
      if (isPausedRef.current) return;

      const newPayload: CapturedPayload = {
        timestamp: new Date(data.timestamp || new Date()),
        payload: data.payload,
        response_payload: data.response_payload,
        outbound_request: data.outbound_request,
        inbound_response: data.inbound_response,
        channel: data.channel,
        validation_status: data.validation_status || 'success',
        validation_error: data.validation_error,
      };

      setState(prev => ({
        ...prev,
        captured: [newPayload, ...prev.captured.slice(0, MAX_HISTORY - 1)],
        count: prev.count + 1,
        latestInboundRequest: JSON.stringify(data.payload, null, 2),
        latestOutboundRequest: data.outbound_request
          ? JSON.stringify(data.outbound_request, null, 2)
          : '',
        latestInboundResponse: data.inbound_response
          ? JSON.stringify(data.inbound_response, null, 2)
          : '',
        latestOutboundResponse: data.response_payload
          ? JSON.stringify(data.response_payload, null, 2)
          : '',
        latestValidationStatus: data.validation_status || 'success',
        latestValidationError: data.validation_error,
        displayedCapture: { timestamp: newPayload.timestamp, channel: newPayload.channel },
      }));
    };
    window.addEventListener('ws-message', handler);
    return () => window.removeEventListener('ws-message', handler);
  }, [configId]);

  const setPaused = (paused: boolean) => {
    isPausedRef.current = paused;
    setState(prev => ({
      ...prev,
      isPaused: paused,
      displayedCapture: paused ? prev.displayedCapture : null,
    }));
  };

  const clear = () => setState(EMPTY);

  const loadCapture = (capture: CapturedPayload) => {
    isPausedRef.current = true;
    setState(prev => ({
      ...prev,
      isPaused: true,
      latestInboundRequest: JSON.stringify(capture.payload, null, 2),
      latestOutboundRequest: capture.outbound_request
        ? JSON.stringify(capture.outbound_request, null, 2)
        : '',
      latestInboundResponse: capture.inbound_response
        ? JSON.stringify(capture.inbound_response, null, 2)
        : '',
      latestOutboundResponse: capture.response_payload
        ? JSON.stringify(capture.response_payload, null, 2)
        : '',
      latestValidationStatus: capture.validation_status,
      latestValidationError: capture.validation_error,
      displayedCapture: { timestamp: capture.timestamp, channel: capture.channel },
    }));
  };

  return { ...state, setPaused, clear, loadCapture };
}
