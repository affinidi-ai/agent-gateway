import { createContext, useContext } from 'react';
import type { AgentSurface } from '../../api';
import type { Protocol } from './elements/types';

export type DidwebvhInjectionMode = 'header' | 'signed_header' | 'protocol_native';

export interface DidwebvhConfig {
  enabled: boolean;
  auto_create: boolean;
  identity_id: string;
  did_path: string;
  injection_mode: DidwebvhInjectionMode;
}

export const DEFAULT_DIDWEBVH_CONFIG: DidwebvhConfig = {
  enabled: false,
  auto_create: true,
  identity_id: '',
  did_path: '',
  injection_mode: 'header',
};

export interface SurfaceMetaValue {
  name: string;
  description: string;
  tagsCsv: string;
  status: AgentSurface['status'];
  protocol: Protocol;
  publishToDid: boolean;
  /** When true, requests entering this surface start a fresh end-to-end trace id
   * instead of continuing one propagated by an upstream gateway. */
  terminateTraceId: boolean;
  /** Issuer / issuer this surface is owned by. Empty string = unset. */
  issuerId: string;
  /** Gateway-managed did:webvh identity injected on every outbound request. */
  didwebvh: DidwebvhConfig;
  /** True when fields shown to the user must be read-only. */
  readOnly: boolean;
  /** Whether the protocol field can still be changed. */
  protocolLocked: boolean;
  /** True for the create wizard (extra hints, no Last Activity, etc.). */
  isCreate: boolean;
  /** Optional last-activity timestamp for edit mode. */
  lastActivity?: string | null;
  /** Surface UUID; read-only display in edit mode. */
  surfaceId?: string;
  /** Alias of the named variant the canvas shows; absent while it shows the base. */
  activeVariantAlias?: string;
  /** True when that variant is the surface's default, which also answers on its route. */
  activeVariantIsDefault?: boolean;
  /** Message of the last failed save, so a panel can show it next to the field it names. */
  saveError?: string | null;
  setName: (v: string) => void;
  setDescription: (v: string) => void;
  setTagsCsv: (v: string) => void;
  setStatus: (v: AgentSurface['status']) => void;
  setProtocol: (v: Protocol) => void;
  setPublishToDid: (v: boolean) => void;
  setTerminateTraceId: (v: boolean) => void;
  setIssuerId: (v: string) => void;
  setDidwebvh: (v: DidwebvhConfig) => void;
  /** Optional callback to snapshot the current surface as a reusable template. */
  onSaveAsTemplate?: () => void;
  /** Opens the Agent Cards view. Set only while that view is offered for the surface's protocol. */
  onOpenAgentCard?: () => void;
  /** Opens the Surface view, which holds the Entry point URL and the canvas. */
  onOpenSurfaceView?: () => void;
  /** Changes whenever the saved surface changes, so card status shown beside the canvas reads again. */
  agentCardRevision?: unknown;
  /** Changes when the saved surface changes or a Refresh in the Agent Cards view succeeds, so the Managed Agent card fetch line reads again. */
  agentCardFetchRevision?: unknown;
}

const SurfaceMetaContext = createContext<SurfaceMetaValue | null>(null);

export const SurfaceMetaProvider = SurfaceMetaContext.Provider;

export function useSurfaceMeta(): SurfaceMetaValue {
  const v = useContext(SurfaceMetaContext);
  if (!v) {
    throw new Error('useSurfaceMeta must be used inside <SurfaceMetaProvider>');
  }
  return v;
}

export function useOptionalSurfaceMeta(): SurfaceMetaValue | null {
  return useContext(SurfaceMetaContext);
}
