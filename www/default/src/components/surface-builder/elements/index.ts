/**
 * Element registry — entry point.
 *
 * Importing this module registers every element definition. Consumers should
 * import `registry` from here (or directly from `./registry`).
 */

import { registry } from './registry';

import { surfaceDefinition } from './surface/definition';
import { accessPointDefinition } from './access-point/definition';
import { managedAgentDefinition } from './managed-agent/definition';
import {
  transitPointA2aDefinition,
  transitPointAp2Definition,
  transitPointMcpDefinition,
} from './transit-point/definitions';

import { policyDefinition } from './policy/definition';
import { paymentDefinition } from './payment/definition';
import { trustRecorderDefinition } from './trust-recorder/definition';
import { trustCheckDefinition } from './trust-check/definition';
import { identityDefinition } from './identity/definition';
import { networkingDefinition } from './networking/definition';
import { rateLimitDefinition } from './rate-limit/definition';
import { customMetadataDefinition } from './custom-metadata/definition';
import { metadataExtractionDefinition } from './metadata-extraction/definition';
import { extensionValidationDefinition } from './extension-validation/definition';
import { extensionRulesDefinition } from './extension-rules/definition';
import { targetVariantDefinition } from './target-variant/definition';
import { callerAuthDefinition } from './caller-auth/definition';
import { credentialDelegationDefinition } from './credential-delegation/definition';
import { workloadBindingDefinition } from './workload-binding/definition';
import { mcpToolGatingDefinition } from './mcp-tool-gating/definition';

import { npcDefinitions } from './npc/definition';
import { humanDefinition } from './human/definition';
import { callerDefinition } from './caller/definition';
import { localGatewayHopDefinition } from './local-gateway-hop/definition';
import { remoteGatewayDefinition } from './remote-gateway/definition';
import { remoteChannelDefinition } from './remote-channel/definition';

// Core (auto-created with the surface)
registry.register(surfaceDefinition);
registry.register(accessPointDefinition);
registry.register(managedAgentDefinition);
registry.register(transitPointA2aDefinition);
registry.register(transitPointMcpDefinition);
registry.register(transitPointAp2Definition);

// Policy / gating middleware
registry.register(policyDefinition);
registry.register(paymentDefinition);
registry.register(trustRecorderDefinition);
registry.register(trustCheckDefinition);
registry.register(mcpToolGatingDefinition);

// Enhancement middleware
registry.register(identityDefinition);
registry.register(networkingDefinition);
registry.register(rateLimitDefinition);
registry.register(customMetadataDefinition);
registry.register(metadataExtractionDefinition);
registry.register(extensionValidationDefinition);
registry.register(extensionRulesDefinition);
registry.register(targetVariantDefinition);
registry.register(callerAuthDefinition);
registry.register(credentialDelegationDefinition);
registry.register(workloadBindingDefinition);

// NPCs and actors
for (const npc of npcDefinitions) registry.register(npc);
registry.register(humanDefinition);
registry.register(callerDefinition);

// Synthesised fabric:// destination representation (canvas-only, never persisted)
registry.register(localGatewayHopDefinition);
registry.register(remoteGatewayDefinition);
registry.register(remoteChannelDefinition);

export { registry } from './registry';
export type { DependencyWarning } from './registry';
export { buildCanvasBlob, readCanvasSurfaceSize, readCanvasView } from './registry';
export type { CanvasBlob } from './registry';
export { buildSurfaceContext } from './surfaceContext';
export { validateSurfacePayload, hasBlockingIssues } from './validateSurface';
export type { ValidationIssue, ValidationSeverity } from './validateSurface';
export type {
  NodeDefinition,
  NodeShape,
  Protocol,
  PipelineStage,
  Cardinality,
  PaletteCategory,
  ResizeRange,
  CompatibilitySpec,
  SurfaceContext,
  FeatureDependency,
  ConfigPanelProps,
} from './types';
export * as Capabilities from './capabilities';
