export type FlowMode = 'arm' | 'thumb' | null;

export interface FlowNode {
  id: number;
  addr: number;
  size: number;
  bytes: Uint8Array;
  mode: FlowMode;
  stageId: number | null;
  hits: number;
  firstStep: number;
  lastStep: number;
}

export interface FlowEdge {
  fromId: number;
  toId: number;
  hits: number;
  /** destination step of the first observed traversal */
  firstStep: number;
  lastStep: number;
}

export interface FlowGraph {
  nodes: FlowNode[];
  edges: FlowEdge[];
  truncated: boolean;
}

export const FLOW_NODE_CAP = 4096;
export const FLOW_EDGE_CAP = 8192;

function byteKey(bytes: Uint8Array): string {
  let key = '';
  for (const byte of bytes) key += String.fromCharCode(byte);
  return key;
}

/** Aggregates observed instruction transfers, including post-trace-cap execution. */
export class FlowCollector {
  private readonly nodes: FlowNode[] = [];
  private readonly edges: FlowEdge[] = [];
  private readonly nodeIds = new Map<string, number>();
  private readonly edgeIds = new Map<string, number>();
  private previousId: number | null = null;
  private truncated = false;

  constructor(
    private readonly nodeCap = FLOW_NODE_CAP,
    private readonly edgeCap = FLOW_EDGE_CAP,
  ) {}

  record(step: number, addr: number, size: number, bytes: Uint8Array, mode: FlowMode, stageId: number | null): void {
    const key = `${addr}:${size}:${mode ?? '-'}:${stageId ?? '-'}:${byteKey(bytes)}`;
    let id = this.nodeIds.get(key);
    if (id === undefined) {
      if (this.nodes.length >= this.nodeCap) {
        this.truncated = true;
        this.previousId = null;
        return;
      }
      id = this.nodes.length;
      this.nodes.push({ id, addr, size, bytes: Uint8Array.from(bytes), mode, stageId, hits: 0, firstStep: step, lastStep: step });
      this.nodeIds.set(key, id);
    }
    const node = this.nodes[id]!;
    node.hits++;
    node.lastStep = step;

    if (this.previousId !== null) {
      const edgeKey = `${this.previousId}:${id}`;
      let edgeId = this.edgeIds.get(edgeKey);
      if (edgeId === undefined) {
        if (this.edges.length >= this.edgeCap) this.truncated = true;
        else {
          edgeId = this.edges.length;
          this.edges.push({ fromId: this.previousId, toId: id, hits: 0, firstStep: step, lastStep: step });
          this.edgeIds.set(edgeKey, edgeId);
        }
      }
      if (edgeId !== undefined) {
        const edge = this.edges[edgeId]!;
        edge.hits++;
        edge.lastStep = step;
      }
    }
    this.previousId = id;
  }

  result(): FlowGraph {
    return { nodes: this.nodes, edges: this.edges, truncated: this.truncated };
  }
}

export function isFlowTransfer(from: FlowNode, to: FlowNode): boolean {
  return to.addr !== from.addr + from.size || to.mode !== from.mode || to.stageId !== from.stageId;
}

export function flowEdgeLabels(from: FlowNode, to: FlowNode): string[] {
  const labels: string[] = [];
  if (to.stageId !== from.stageId) labels.push('stage hop');
  if (to.mode !== from.mode && to.mode !== null && from.mode !== null) labels.push(`${from.mode} → ${to.mode}`);
  if (to.addr !== from.addr + from.size) labels.push(to.addr <= from.addr ? 'back edge' : 'branch');
  if (!labels.length) labels.push('fallthrough');
  return labels;
}
