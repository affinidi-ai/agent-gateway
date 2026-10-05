import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { AppButton } from './shared/AppButton';
import { FLOW_COLORS, UI_COLORS } from '../utils/uiPalette';

interface ConnectionFlow {
  source: string; // Source IP
  identity: string; // Agent identity
  target: string; // Target destination
  channelId: string;
  channelName: string;
  successCount: number;
  failedCount: number;
  faultCount: number;
  totalCount: number;
  direction: 'request' | 'response'; // Direction of the flow
}

interface FlowData {
  connections: ConnectionFlow[];
  gatewayName: string;
  gateways?: Record<string, string>; // Map of gateway ID to gateway name
  channels?: Array<{ config_id: string; name: string; target_endpoint: string }>; // Channel configurations
}

interface ChannelDetails {
  channelId: string;
  channelName: string;
  successCount: number;
  failedCount: number;
  faultCount: number;
  totalCount: number;
}

interface MetricsFlowVisualizationProps {
  data: FlowData;
}

interface NetworkNode extends d3.SimulationNodeDatum {
  id: string;
  label: string;
  value: number;
  type: 'source' | 'identity' | 'channel' | 'fabric-gateway' | 'target';
  status: 'neutral' | 'success' | 'danger' | 'warning';
  x?: number;
  y?: number;
  fx?: number | null;
  fy?: number | null;
  channelDetails?: ChannelDetails; // For channel nodes
  // Stats for all nodes
  successCount: number;
  failedCount: number;
  faultCount: number;
  totalCount: number;
}

interface NetworkLink extends d3.SimulationLinkDatum<NetworkNode> {
  source: string | NetworkNode;
  target: string | NetworkNode;
  value: number;
  label: string;
  direction?: 'request' | 'response'; // Direction for styling
}

const MetricsFlowVisualization: React.FC<MetricsFlowVisualizationProps> = ({ data }) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const hoveredNodeRef = useRef<string | null>(null);
  const hoveredLinkRef = useRef<string | null>(null);
  const [, forceUpdate] = useState({});
  const [showLegend, setShowLegend] = useState(true);
  const zoomTransformRef = useRef<d3.ZoomTransform | null>(null);
  const simulationRef = useRef<d3.Simulation<NetworkNode, NetworkLink> | null>(null);
  const isInitializedRef = useRef(false);
  const previousDataRef = useRef<string>('');
  const nodesRef = useRef<NetworkNode[]>([]);
  const linksRef = useRef<NetworkLink[]>([]);

  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return;

    const container = containerRef.current;
    const width = container.clientWidth || 800;
    const height = 800;

    // Only do full initialization once
    if (!isInitializedRef.current) {
      // Clear previous content only on first render
      d3.select(svgRef.current).selectAll('*').remove();
      isInitializedRef.current = true;
    }

    const svg = d3.select(svgRef.current);

    // Always set dimensions to ensure they're current
    svg
      .attr('width', width)
      .attr('height', height)
      .attr('viewBox', `0 0 ${width} ${height}`)
      .attr('preserveAspectRatio', 'xMidYMid meet');

    // Get or create main group
    let g = svg.select<SVGGElement>('g.main-group');
    if (g.empty()) {
      g = svg.append('g').attr('class', 'main-group');

      // Add zoom behavior only once
      const zoom = d3
        .zoom<SVGSVGElement, unknown>()
        .scaleExtent([0.5, 3])
        .on('zoom', event => {
          g.attr('transform', event.transform);
          zoomTransformRef.current = event.transform;
        });

      svg.call(zoom);

      // Restore previous zoom if exists
      if (zoomTransformRef.current) {
        svg.call(zoom.transform as any, zoomTransformRef.current);
      }
    }

    // Build nodes from connection data: Source IP → Agent Identity → Channel → Target
    const nodeMap = new Map<string, NetworkNode>();
    const links: NetworkLink[] = [];

    // Process all connections following the hierarchy
    data.connections.forEach(conn => {
      const sourceId = `source-${conn.source}`;
      const identityId = `identity-${conn.identity}`;
      const channelId = `channel-${conn.channelId}`;

      // For fabric targets, parse the URL and extract info upfront
      const isFabricGateway = conn.target.startsWith('fabric://');
      let targetId: string;
      let gatewayId: string | null = null;
      let fabricChannelName: string | null = null;
      let targetLabel = conn.target;
      let downstreamTarget: string | null = null;

      if (isFabricGateway) {
        // Parse fabric://gateway-id/channel-name
        const match = conn.target.match(/^fabric:\/\/([^/]+)(?:\/(.+))?$/);
        if (match) {
          gatewayId = match[1];
          fabricChannelName = match[2] || null;
          targetId = `gateway-${gatewayId}`; // Use gateway ID as the node ID

          // Get gateway name for display
          if (data.gateways && data.gateways[gatewayId]) {
            targetLabel = data.gateways[gatewayId];
          } else {
            // Fallback: use shortened gateway ID
            targetLabel =
              gatewayId.length > 8 ? `GW-${gatewayId.substring(0, 8)}...` : `GW-${gatewayId}`;
          }

          // Look up the channel to find its downstream target
          if (data.channels && fabricChannelName) {
            const channel = data.channels.find(ch => ch.config_id === fabricChannelName);
            if (channel && channel.target_endpoint) {
              downstreamTarget = channel.target_endpoint;
            }
          }
        } else {
          // Malformed fabric URL, use as-is
          targetId = `target-${conn.target}`;
        }
      } else {
        targetId = `target-${conn.target}`;
      }

      // Add or update source node (IP address)
      if (!nodeMap.has(sourceId)) {
        nodeMap.set(sourceId, {
          id: sourceId,
          label: conn.source.length > 25 ? conn.source.substring(0, 22) + '...' : conn.source,
          value: 0,
          type: 'source' as const,
          status: 'neutral' as const,
          successCount: 0,
          failedCount: 0,
          faultCount: 0,
          totalCount: 0,
        });
      }
      const sourceNode = nodeMap.get(sourceId)!;
      sourceNode.value += conn.totalCount;
      sourceNode.successCount += conn.successCount;
      sourceNode.failedCount += conn.failedCount;
      sourceNode.faultCount += conn.faultCount;
      sourceNode.totalCount += conn.totalCount;

      // Add or update identity node
      if (!nodeMap.has(identityId)) {
        const identityLabel = conn.identity === 'anonymous' ? 'Anonymous' : conn.identity;
        nodeMap.set(identityId, {
          id: identityId,
          label: identityLabel,
          value: 0,
          type: 'identity' as const,
          status: 'neutral' as const,
          successCount: 0,
          failedCount: 0,
          faultCount: 0,
          totalCount: 0,
        });
      }
      const identityNode = nodeMap.get(identityId)!;
      identityNode.value += conn.totalCount;
      identityNode.successCount += conn.successCount;
      identityNode.failedCount += conn.failedCount;
      identityNode.faultCount += conn.faultCount;
      identityNode.totalCount += conn.totalCount;

      // Add or update channel node
      if (!nodeMap.has(channelId)) {
        const nodeLabel = conn.channelName;

        nodeMap.set(channelId, {
          id: channelId,
          label: nodeLabel,
          value: 0,
          type: 'channel' as const,
          status: 'neutral' as const,
          successCount: 0,
          failedCount: 0,
          faultCount: 0,
          totalCount: 0,
          channelDetails: {
            channelId: conn.channelId,
            channelName: nodeLabel,
            successCount: 0,
            failedCount: 0,
            faultCount: 0,
            totalCount: 0,
          },
        });
      }
      const channelNode = nodeMap.get(channelId)!;
      channelNode.value += conn.totalCount;
      channelNode.successCount += conn.successCount;
      channelNode.failedCount += conn.failedCount;
      channelNode.faultCount += conn.faultCount;
      channelNode.totalCount += conn.totalCount;
      if (channelNode.channelDetails) {
        channelNode.channelDetails.successCount += conn.successCount;
        channelNode.channelDetails.failedCount += conn.failedCount;
        channelNode.channelDetails.faultCount += conn.faultCount;
        channelNode.channelDetails.totalCount += conn.totalCount;
      }

      // Add or update target node (GW2 for fabric connections, or final target for direct)
      // Note: targetLabel, downstreamTarget, etc. were already extracted at the top of the loop
      if (!nodeMap.has(targetId)) {
        nodeMap.set(targetId, {
          id: targetId,
          label: targetLabel.length > 25 ? targetLabel.substring(0, 22) + '...' : targetLabel,
          value: 0,
          type: isFabricGateway ? ('fabric-gateway' as const) : ('target' as const),
          status:
            conn.successCount > conn.failedCount + conn.faultCount
              ? ('success' as const)
              : conn.failedCount > 0
                ? ('danger' as const)
                : ('warning' as const),
          successCount: 0,
          failedCount: 0,
          faultCount: 0,
          totalCount: 0,
        });
      }
      const targetNode = nodeMap.get(targetId)!;
      targetNode.value += conn.totalCount;
      targetNode.successCount += conn.successCount;
      targetNode.failedCount += conn.failedCount;
      targetNode.faultCount += conn.faultCount;
      targetNode.totalCount += conn.totalCount;

      // If we have a downstream target for this fabric connection, add it as a final node
      if (downstreamTarget && !downstreamTarget.startsWith('fabric://')) {
        const downstreamId = `target-${downstreamTarget}`; // Use 'target-' prefix for consistency
        if (!nodeMap.has(downstreamId)) {
          nodeMap.set(downstreamId, {
            id: downstreamId,
            label:
              downstreamTarget.length > 25
                ? downstreamTarget.substring(0, 22) + '...'
                : downstreamTarget,
            value: 0,
            type: 'target' as const,
            status:
              conn.successCount > conn.failedCount + conn.faultCount
                ? ('success' as const)
                : conn.failedCount > 0
                  ? ('danger' as const)
                  : ('warning' as const),
            successCount: 0,
            failedCount: 0,
            faultCount: 0,
            totalCount: 0,
          });
        }
        const downstreamNode = nodeMap.get(downstreamId)!;
        downstreamNode.value += conn.totalCount;
        downstreamNode.successCount += conn.successCount;
        downstreamNode.failedCount += conn.failedCount;
        downstreamNode.faultCount += conn.faultCount;
        downstreamNode.totalCount += conn.totalCount;
      }

      // Create links based on direction
      if (conn.direction === 'request') {
        // Request: Source → Identity → Channel → Target
        const sourceToIdentity = `${sourceId}-${identityId}`;
        if (
          !links.find(
            l =>
              `${typeof l.source === 'string' ? l.source : l.source.id}-${typeof l.target === 'string' ? l.target : l.target.id}` ===
              sourceToIdentity
          )
        ) {
          links.push({
            source: sourceId,
            target: identityId,
            value: conn.totalCount,
            label: `${conn.totalCount} calls`,
            direction: 'request',
          });
        }

        const identityToChannel = `${identityId}-${channelId}`;
        if (
          !links.find(
            l =>
              `${typeof l.source === 'string' ? l.source : l.source.id}-${typeof l.target === 'string' ? l.target : l.target.id}` ===
              identityToChannel
          )
        ) {
          links.push({
            source: identityId,
            target: channelId,
            value: conn.totalCount,
            label: `${conn.totalCount} calls`,
            direction: 'request',
          });
        }

        // Channel → Target with call details
        const channelToTarget = `${channelId}-${targetId}`;
        const existingLink = links.find(
          l =>
            `${typeof l.source === 'string' ? l.source : l.source.id}-${typeof l.target === 'string' ? l.target : l.target.id}` ===
            channelToTarget
        );
        if (!existingLink) {
          links.push({
            source: channelId,
            target: targetId,
            value: conn.totalCount,
            label: `${conn.successCount}✓ ${conn.failedCount}✗ ${conn.faultCount}⚠`,
            direction: 'request',
          });
        } else {
          // Aggregate multiple connections between same channel-target pair
          existingLink.value += conn.totalCount;
        }

        // If we have a downstream target, add link from fabric gateway to downstream
        if (downstreamTarget && !downstreamTarget.startsWith('fabric://')) {
          const downstreamId = `target-${downstreamTarget}`; // Match the ID we used above
          const fabricToDownstream = `${targetId}-${downstreamId}`;
          const existingDownstreamLink = links.find(
            l =>
              `${typeof l.source === 'string' ? l.source : l.source.id}-${typeof l.target === 'string' ? l.target : l.target.id}` ===
              fabricToDownstream
          );
          if (!existingDownstreamLink) {
            links.push({
              source: targetId,
              target: downstreamId,
              value: conn.totalCount,
              label: `${conn.totalCount} calls`,
              direction: 'request',
            });
          }
        }
      } else if (conn.direction === 'response') {
        // Response: Target → Channel → Source (no identity for responses)
        const targetToChannel = `${targetId}-${channelId}-response`;
        if (
          !links.find(
            l =>
              `${typeof l.source === 'string' ? l.source : l.source.id}-${typeof l.target === 'string' ? l.target : l.target.id}` ===
              targetToChannel
          )
        ) {
          links.push({
            source: targetId,
            target: channelId,
            value: conn.totalCount,
            label: `${conn.totalCount} responses`,
            direction: 'response',
          });
        }

        const channelToSource = `${channelId}-${sourceId}-response`;
        if (
          !links.find(
            l =>
              `${typeof l.source === 'string' ? l.source : l.source.id}-${typeof l.target === 'string' ? l.target : l.target.id}` ===
              channelToSource
          )
        ) {
          links.push({
            source: channelId,
            target: sourceId,
            value: conn.totalCount,
            label: `${conn.totalCount} responses`,
            direction: 'response',
          });
        }
      }
    });

    const nodes: NetworkNode[] = Array.from(nodeMap.values());

    // Initialize all node positions to center before simulation
    const centerX = width / 2;
    const centerY = height / 2;
    nodes.forEach(node => {
      node.x = centerX + (Math.random() - 0.5) * 50; // Small random offset to help them separate
      node.y = centerY + (Math.random() - 0.5) * 50;
    });

    // Check if topology has changed (nodes/links structure, not just values)
    const currentTopology = JSON.stringify({
      nodeIds: nodes.map(n => n.id).sort(),
      linkPairs: links
        .map(
          l =>
            `${typeof l.source === 'string' ? l.source : l.source.id}-${typeof l.target === 'string' ? l.target : l.target.id}`
        )
        .sort(),
    });
    const topologyChanged = previousDataRef.current !== currentTopology;
    previousDataRef.current = currentTopology;

    // If topology hasn't changed, just update values without recreating DOM
    if (!topologyChanged && nodesRef.current.length > 0) {
      // Calculate max value for radius scaling
      const maxValue = Math.max(...nodes.map(n => n.value), 1);
      const radiusScale = d3.scaleSqrt().domain([0, maxValue]).range([20, 60]);

      const getNodeColor = (node: NetworkNode): string => {
        // Color by node type
        if (node.type === 'source') return FLOW_COLORS.source;
        if (node.type === 'identity') return FLOW_COLORS.identity;
        if (node.type === 'channel') return FLOW_COLORS.channel;
        if (node.type === 'fabric-gateway') return FLOW_COLORS.fabricGateway;

        // For target nodes, use status colors
        switch (node.status) {
          case 'success':
            return UI_COLORS.success;
          case 'danger':
            return UI_COLORS.danger;
          case 'warning':
            return UI_COLORS.warning;
          default:
            return UI_COLORS.primary;
        }
      };

      // Update node values and stats
      nodes.forEach(newNode => {
        const existingNode = nodesRef.current.find(n => n.id === newNode.id);
        if (existingNode) {
          existingNode.value = newNode.value;
          existingNode.status = newNode.status;
          existingNode.label = newNode.label;
          existingNode.successCount = newNode.successCount;
          existingNode.failedCount = newNode.failedCount;
          existingNode.faultCount = newNode.faultCount;
          existingNode.totalCount = newNode.totalCount;
        }
      });

      // Update link values
      links.forEach(newLink => {
        const linkId = `${typeof newLink.source === 'string' ? newLink.source : newLink.source.id}-${typeof newLink.target === 'string' ? newLink.target : newLink.target.id}`;
        const existingLink = linksRef.current.find(l => {
          const existingId = `${typeof l.source === 'string' ? l.source : l.source.id}-${typeof l.target === 'string' ? l.target : l.target.id}`;
          return existingId === linkId;
        });
        if (existingLink) {
          existingLink.value = newLink.value;
          existingLink.label = newLink.label;
        }
      });

      // Update visual elements without recreating
      const nodeGroups = g
        .select('.nodes')
        .selectAll<SVGGElement, NetworkNode>('g')
        .data(nodesRef.current);

      // Update circles
      nodeGroups
        .select('circle')
        .transition()
        .duration(300)
        .attr('r', (d: NetworkNode) => radiusScale(d.value))
        .attr('fill', (d: NetworkNode) => getNodeColor(d));

      // Update status arcs
      nodeGroups.each(function (d: NetworkNode) {
        const nodeGroup = d3.select(this);
        const radius = radiusScale(d.value);
        const arcWidth = 6;
        const outerRadius = radius + arcWidth + 2;
        const innerRadius = radius + 2;

        // Remove old arcs
        nodeGroup.selectAll('.status-arc').remove();

        // Recreate arcs with updated stats
        if (d.totalCount > 0) {
          const arcGenerator = d3.arc<any>();
          const successPct = d.successCount / d.totalCount;
          const failedPct = d.failedCount / d.totalCount;
          const faultPct = d.faultCount / d.totalCount;

          let currentAngle = -Math.PI / 2;

          if (successPct > 0) {
            const endAngle = currentAngle + successPct * 2 * Math.PI;
            nodeGroup
              .insert('path', ':first-child')
              .attr('class', 'status-arc success-arc')
              .attr(
                'd',
                arcGenerator({
                  innerRadius,
                  outerRadius,
                  startAngle: currentAngle,
                  endAngle,
                })
              )
              .attr('fill', UI_COLORS.success)
              .attr('opacity', 0.8);
            currentAngle = endAngle;
          }

          if (faultPct > 0) {
            const endAngle = currentAngle + faultPct * 2 * Math.PI;
            nodeGroup
              .insert('path', ':first-child')
              .attr('class', 'status-arc fault-arc')
              .attr(
                'd',
                arcGenerator({
                  innerRadius,
                  outerRadius,
                  startAngle: currentAngle,
                  endAngle,
                })
              )
              .attr('fill', UI_COLORS.warning)
              .attr('opacity', 0.8);
            currentAngle = endAngle;
          }

          if (failedPct > 0) {
            const endAngle = currentAngle + failedPct * 2 * Math.PI;
            nodeGroup
              .insert('path', ':first-child')
              .attr('class', 'status-arc failed-arc')
              .attr(
                'd',
                arcGenerator({
                  innerRadius,
                  outerRadius,
                  startAngle: currentAngle,
                  endAngle,
                })
              )
              .attr('fill', UI_COLORS.danger)
              .attr('opacity', 0.8);
          }
        }
      });

      // Update value text only (not labels)
      nodeGroups
        .selectAll<SVGTextElement, NetworkNode>('text.node-value')
        .text((d: NetworkNode) => String(d.value));

      g.select('.links')
        .selectAll<SVGLineElement, NetworkLink>('line')
        .data(linksRef.current)
        .transition()
        .duration(300)
        .attr('stroke-width', 2)
        .attr('stroke', (d: NetworkLink) => {
          const targetNode = nodesRef.current.find(
            n => n.id === (typeof d.target === 'string' ? d.target : d.target.id)
          );
          return targetNode ? getNodeColor(targetNode) : UI_COLORS.neutral;
        });

      return; // Skip full rebuild - preserves hover state!
    }

    // Store for next comparison
    nodesRef.current = nodes;
    linksRef.current = links;

    // Clear only the content groups for full rebuild
    g.selectAll('.links, .nodes, .defs-markers').remove();

    // Color mapping
    const getNodeColor = (node: NetworkNode): string => {
      // Color by node type
      if (node.type === 'source') return FLOW_COLORS.source;
      if (node.type === 'identity') return FLOW_COLORS.identity;
      if (node.type === 'channel') return FLOW_COLORS.channel;
      if (node.type === 'fabric-gateway') return FLOW_COLORS.fabricGateway;

      // For target nodes, use status colors
      switch (node.status) {
        case 'success':
          return UI_COLORS.success;
        case 'danger':
          return UI_COLORS.danger;
        case 'warning':
          return UI_COLORS.warning;
        default:
          return UI_COLORS.primary;
      }
    };

    // Calculate node radius based on value
    const maxValue = Math.max(...nodes.map(n => n.value), 1);
    const radiusScale = d3.scaleSqrt().domain([0, maxValue]).range([20, 60]);

    // Stop previous simulation if exists
    if (simulationRef.current) {
      simulationRef.current.stop();
    }

    // Create force simulation with left-to-right flow
    // Position nodes horizontally based on their type in the request-response flow
    const simulation = d3
      .forceSimulation<NetworkNode>(nodes)
      .force(
        'link',
        d3
          .forceLink<NetworkNode, NetworkLink>(links)
          .id(d => d.id)
          .distance(250)
          .strength(0.3)
      )
      .force('charge', d3.forceManyBody().strength(-800))
      .force(
        'collision',
        d3.forceCollide<NetworkNode>().radius(d => radiusScale(d.value) + 30)
      )
      .force(
        'x',
        d3
          .forceX((d: NetworkNode) => {
            // Left to right flow: Source (Agent) → Identity → Channel (GW1) → Fabric Gateway (GW2) → Target
            const margin = 100;
            const step = (width - margin * 2) / 4; // 5 positions: 0, 1, 2, 3, 4
            if (d.type === 'source') return margin; // Position 0: Agent initiators (leftmost)
            if (d.type === 'identity') return margin + step; // Position 1: Agent identities
            if (d.type === 'channel') return margin + step * 2; // Position 2: First gateway (GW1)
            if (d.type === 'fabric-gateway') return margin + step * 3; // Position 3: Fabric target gateway (GW2)
            if (d.type === 'target') return margin + step * 4; // Position 4: Final target (rightmost)
            return width / 2;
          })
          .strength(0.6)
      )
      .force('y', d3.forceY(height / 2).strength(0.05));

    simulationRef.current = simulation;

    // Create defs for filters
    let defs = svg.select<SVGDefsElement>('defs');
    if (defs.empty()) {
      defs = svg.append('defs');
    }

    // Create links
    const link = g
      .append('g')
      .attr('class', 'links')
      .selectAll('line')
      .data(links)
      .enter()
      .append('line')
      .attr('stroke-width', 2)
      .attr('stroke', (d: NetworkLink) => {
        // Response links are lighter/different color
        if (d.direction === 'response') {
          return UI_COLORS.neutralMuted;
        }
        const targetNode = nodes.find(
          n => n.id === (typeof d.target === 'string' ? d.target : d.target.id)
        );
        return targetNode ? getNodeColor(targetNode) : UI_COLORS.neutral;
      })
      .attr('stroke-opacity', (d: NetworkLink) => (d.direction === 'response' ? 0.3 : 0.4))
      .attr('stroke-dasharray', (d: NetworkLink) => (d.direction === 'response' ? '5,5' : '0'))
      .on('mouseenter', function (event, d: any) {
        const linkId = `${typeof d.source === 'string' ? d.source : d.source.id}-${typeof d.target === 'string' ? d.target : d.target.id}`;
        hoveredLinkRef.current = linkId;
        forceUpdate({});
        d3.select(this).attr('stroke-opacity', 0.8).attr('stroke-width', 3);
      })
      .on('mouseleave', function (event, d: any) {
        hoveredLinkRef.current = null;
        forceUpdate({});
        d3.select(this).attr('stroke-opacity', 0.4).attr('stroke-width', 2);
      });

    // Create node groups
    const node = g
      .append('g')
      .attr('class', 'nodes')
      .selectAll('g')
      .data(nodes)
      .enter()
      .append('g')
      .attr('class', 'node')
      .call(
        d3
          .drag<any, NetworkNode>()
          .on('start', (event, d) => {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
          })
          .on('drag', (event, d) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on('end', (event, d) => {
            if (!event.active) simulation.alphaTarget(0);
            // Keep nodes fixed where user places them
            // d.fx and d.fy remain set, preventing snap-back
          })
      );

    // Add glow filter
    const filter = defs
      .append('filter')
      .attr('id', 'glow')
      .attr('x', '-50%')
      .attr('y', '-50%')
      .attr('width', '200%')
      .attr('height', '200%');

    filter.append('feGaussianBlur').attr('stdDeviation', '4').attr('result', 'coloredBlur');

    const feMerge = filter.append('feMerge');
    feMerge.append('feMergeNode').attr('in', 'coloredBlur');
    feMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    // Create arc generator for status indicators
    const arcGenerator = d3.arc<any>();

    // Add status arcs around nodes (showing success/failure/fault percentages)
    node.each(function (d: NetworkNode) {
      const nodeGroup = d3.select(this);
      const radius = radiusScale(d.value);
      const arcWidth = 6; // Width of the arc ring
      const outerRadius = radius + arcWidth + 2;
      const innerRadius = radius + 2;

      if (d.totalCount > 0) {
        const successPct = d.successCount / d.totalCount;
        const failedPct = d.failedCount / d.totalCount;
        const faultPct = d.faultCount / d.totalCount;

        let currentAngle = -Math.PI / 2; // Start at top (12 o'clock)

        // Success arc (green)
        if (successPct > 0) {
          const endAngle = currentAngle + successPct * 2 * Math.PI;
          nodeGroup
            .append('path')
            .attr('class', 'status-arc success-arc')
            .attr(
              'd',
              arcGenerator({
                innerRadius,
                outerRadius,
                startAngle: currentAngle,
                endAngle,
              })
            )
            .attr('fill', UI_COLORS.success)
            .attr('opacity', 0.8);
          currentAngle = endAngle;
        }

        // Fault arc (yellow/warning)
        if (faultPct > 0) {
          const endAngle = currentAngle + faultPct * 2 * Math.PI;
          nodeGroup
            .append('path')
            .attr('class', 'status-arc fault-arc')
            .attr(
              'd',
              arcGenerator({
                innerRadius,
                outerRadius,
                startAngle: currentAngle,
                endAngle,
              })
            )
            .attr('fill', UI_COLORS.warning)
            .attr('opacity', 0.8);
          currentAngle = endAngle;
        }

        // Failed arc (red)
        if (failedPct > 0) {
          const endAngle = currentAngle + failedPct * 2 * Math.PI;
          nodeGroup
            .append('path')
            .attr('class', 'status-arc failed-arc')
            .attr(
              'd',
              arcGenerator({
                innerRadius,
                outerRadius,
                startAngle: currentAngle,
                endAngle,
              })
            )
            .attr('fill', UI_COLORS.danger)
            .attr('opacity', 0.8);
        }
      }
    });

    // Add circles to nodes
    node
      .append('circle')
      .attr('r', (d: NetworkNode) => radiusScale(d.value))
      .attr('fill', (d: NetworkNode) => getNodeColor(d))
      .attr('stroke', 'rgba(255, 255, 255, 0.55)')
      .attr('stroke-width', 0.5)
      .style('filter', 'url(#glow)')
      .style('cursor', 'grab')
      .on('mouseenter', function (event, d: any) {
        hoveredNodeRef.current = d.id;
        forceUpdate({});
        d3.select(this)
          .transition()
          .duration(200)
          .attr('r', radiusScale(d.value) * 1.2)
          .attr('stroke-width', 5);
      })
      .on('mouseleave', function (event, d: any) {
        hoveredNodeRef.current = null;
        forceUpdate({});
        d3.select(this)
          .transition()
          .duration(600)
          .attr('r', radiusScale(d.value))
          .attr('stroke-width', 3);
      });

    // Add labels to nodes (positioned below the circle)
    node
      .append('text')
      .attr('class', 'node-label')
      .text((d: NetworkNode) => d.label)
      .attr('text-anchor', 'middle')
      .attr('dy', (d: NetworkNode) => radiusScale(d.value) + 24) // Position below circle
      .attr('font-size', '14px')
      .attr('font-weight', 'bold')
      .attr('fill', '#DDD')
      .attr('pointer-events', 'none');

    // Add type badges using Font Awesome icons
    node
      .append('text')
      .attr('class', 'fa-solid')
      .text((d: NetworkNode) => {
        if (d.type === 'source') return '\uf109'; // fa-laptop (source device)
        if (d.type === 'identity') return '\uf505'; // fa-user-shield (identity/auth)
        if (d.type === 'channel') return '\uf519'; // fa-broadcast-tower (channel/proxy GW1)
        if (d.type === 'fabric-gateway') return '\uf6ff'; // fa-network-wired (fabric gateway GW2)
        if (d.type === 'target') return '\uf233'; // fa-server (target endpoint)
        return '\uf0c1'; // fa-link
      })
      .attr('text-anchor', 'middle')
      .attr('dy', (d: NetworkNode) => -radiusScale(d.value) * 0.15)
      .attr('font-size', (d: NetworkNode) => radiusScale(d.value) * 0.5)
      .attr('font-family', 'Font Awesome 6 Free')
      .attr('font-weight', '900')
      .attr('fill', '#fff')
      .attr('opacity', 0.9)
      .attr('pointer-events', 'none');

    // Add value count below the icon
    node
      .append('text')
      .attr('class', 'node-value')
      .text((d: NetworkNode) => d.value)
      .attr('text-anchor', 'middle')
      .attr('dy', (d: NetworkNode) => radiusScale(d.value) * 0.3)
      .attr('font-size', (d: NetworkNode) => radiusScale(d.value) * 0.35)
      .attr('font-weight', 'bold')
      .attr('fill', '#fff')
      .attr('opacity', 0.95)
      .attr('pointer-events', 'none');

    // Update positions on each tick
    simulation.on('tick', () => {
      link
        .attr('x1', (d: any) => d.source.x)
        .attr('y1', (d: any) => d.source.y)
        .attr('x2', (d: any) => d.target.x)
        .attr('y2', (d: any) => d.target.y);

      node.attr('transform', (d: NetworkNode) => `translate(${d.x},${d.y})`);
    });

    // Run simulation for initial layout then slow it down
    simulation.alpha(1).restart();
    for (let i = 0; i < 300; ++i) simulation.tick();
    simulation.alpha(0);

    // Cleanup function
    return () => {
      if (simulationRef.current) {
        simulationRef.current.stop();
      }
    };
  }, [data]);

  // Separate effect for window resize to avoid recreating everything
  useEffect(() => {
    if (!containerRef.current) return;

    const handleResize = () => {
      // Force re-render on resize
      isInitializedRef.current = false;
    };

    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  return (
    <div
      ref={containerRef}
      className="metrics-flow-viz"
      style={{ width: '100%', position: 'relative' }}
    >
      <svg ref={svgRef} style={{ width: '100%', display: 'block', background: '#1a1a2e' }}></svg>
      {(hoveredNodeRef.current || hoveredLinkRef.current) && (
        <div
          className="position-absolute bg-dark text-white border rounded shadow-lg p-3"
          style={{
            top: '60px',
            right: '20px',
            maxWidth: '320px',
            zIndex: 10,
            opacity: 0.95,
          }}
        >
          {hoveredNodeRef.current &&
            (() => {
              const node = nodesRef.current.find(n => n.id === hoveredNodeRef.current);
              return (
                <>
                  <div className="font-weight-bold mb-2">
                    {hoveredNodeRef.current.startsWith('source-') && (
                      <>
                        <i className="fas fa-laptop me-1"></i> Source IP
                      </>
                    )}
                    {hoveredNodeRef.current.startsWith('identity-') && (
                      <>
                        <i className="fas fa-user-shield me-1"></i> Agent Identity
                      </>
                    )}
                    {hoveredNodeRef.current.startsWith('channel-') && (
                      <>
                        <i className="fas fa-broadcast-tower me-1"></i> Channel
                      </>
                    )}
                    {hoveredNodeRef.current.startsWith('target-') && (
                      <>
                        <i className="fas fa-server me-1"></i> Target
                      </>
                    )}
                  </div>
                  <small>
                    {hoveredNodeRef.current.startsWith('source-') && (
                      <>
                        <strong>Source IP: {hoveredNodeRef.current.replace('source-', '')}</strong>
                        <br />
                        Originating IP address making requests
                      </>
                    )}
                    {hoveredNodeRef.current.startsWith('identity-') && (
                      <>
                        <strong>Identity: {hoveredNodeRef.current.replace('identity-', '')}</strong>
                        <br />
                        {hoveredNodeRef.current.includes('anonymous')
                          ? 'Anonymous connection (no identity provided)'
                          : 'Authenticated agent identity'}
                      </>
                    )}
                    {hoveredNodeRef.current.startsWith('channel-') && node?.channelDetails && (
                      <>
                        <strong>Channel: {node.channelDetails.channelName}</strong>
                        <br />
                        <strong>ID:</strong> {node.channelDetails.channelId}
                        <br />
                        <div className="mt-2">
                          <strong>Statistics:</strong>
                          <br />✓ Success: {node.channelDetails.successCount}
                          <br />✗ Failed: {node.channelDetails.failedCount}
                          <br />⚠ Faults: {node.channelDetails.faultCount}
                          <br />
                          📊 Total: {node.channelDetails.totalCount}
                        </div>
                      </>
                    )}
                    {hoveredNodeRef.current.startsWith('source-') && (
                      <>
                        <strong>Source IP: {hoveredNodeRef.current.replace('source-', '')}</strong>
                        <br />
                        Originating agent making requests through the channel
                      </>
                    )}
                    {hoveredNodeRef.current.startsWith('target-') && (
                      <>
                        <strong>Target: {hoveredNodeRef.current.replace('target-', '')}</strong>
                        <br />
                        Destination endpoint receiving requests
                      </>
                    )}
                  </small>
                </>
              );
            })()}
          {hoveredLinkRef.current && !hoveredNodeRef.current && (
            <>
              <div className="font-weight-bold mb-2">
                <i className="fas fa-arrow-right me-1"></i> Connection Flow
              </div>
              <small>Shows the flow of requests through the system</small>
            </>
          )}
        </div>
      )}

      {/* Legend for Request vs Response flows */}
      {showLegend && (
        <div
          className="shadow-lg"
          style={{
            position: 'absolute',
            bottom: '20px',
            right: '20px',
            padding: '16px',
            maxWidth: '320px',
            fontSize: '0.9rem',
            backgroundColor: 'rgba(33, 37, 41, 0.92)',
            borderRadius: '8px',
            border: '1px solid rgba(255, 255, 255, 0.2)',
          }}
        >
          <div className="d-flex justify-content-between align-items-center mb-3">
            <div className="font-weight-bold text-white" style={{ fontSize: '1rem' }}>
              Flow Types
            </div>
            <button
              onClick={() => setShowLegend(false)}
              className="btn btn-sm btn-link text-white p-0"
              style={{ fontSize: '0.8rem', opacity: 0.8 }}
              title="Hide legend"
            >
              <i className="fas fa-times"></i>
            </button>
          </div>
          <div className="mb-2">
            <svg width="30" height="2" style={{ verticalAlign: 'middle', marginRight: '8px' }}>
              <line x1="0" y1="1" x2="30" y2="1" stroke="#5dade2" strokeWidth="4" />
            </svg>
            <span className="text-white">
              <strong>Request</strong>
            </span>
            <div
              className="ms-4"
              style={{ fontSize: '0.8rem', color: 'rgba(255, 255, 255, 0.75)' }}
            >
              Source → Identity → Channel → Target
            </div>
          </div>
          <div>
            <svg width="30" height="2" style={{ verticalAlign: 'middle', marginRight: '8px' }}>
              <line
                x1="0"
                y1="1"
                x2="30"
                y2="1"
                stroke="var(--gray-400)"
                strokeWidth="4"
                strokeDasharray="5,5"
              />
            </svg>
            <span className="text-white">
              <strong>Response</strong>
            </span>
            <div
              className="ms-4"
              style={{ fontSize: '0.8rem', color: 'rgba(255, 255, 255, 0.75)' }}
            >
              Target → Channel → Source (no identity tracking)
            </div>
          </div>
        </div>
      )}

      {/* Toggle button when legend is hidden */}
      {!showLegend && (
        <AppButton
          variant="secondary"
          size="sm"
          onClick={() => setShowLegend(true)}
          className="shadow"
          style={{
            position: 'absolute',
            bottom: '20px',
            right: '20px',
          }}
          title="Show legend"
          iconStart={<i className="fas fa-info-circle" aria-hidden="true"></i>}
        >
          Legend
        </AppButton>
      )}
    </div>
  );
};

export default MetricsFlowVisualization;
