import type { EmuResult } from './emu';
import type { FlowNode } from './flow';
import { toHex } from './hex';

export const SCENARIO_CAP = 8;
type FlowKeys = { nodes: string[]; edges: Set<string>; path: string[] };
const flowKeyCache = new WeakMap<EmuResult, FlowKeys>();

export function parseScenarioArgs(raw: string, archId: string): bigint[] {
  const tokens = raw.trim().split(/[\s,;]+/).filter(Boolean);
  if (!tokens.length) throw new Error('enter at least one argument value');
  if (tokens.length > SCENARIO_CAP) throw new Error(`limit scenarios to ${SCENARIO_CAP} values`);
  const mask = archId === 'x86-64' || archId === 'arm64' ? 0xffffffffffffffffn : 0xffffffffn;
  return tokens.map((token) => {
    try { return BigInt(token) & mask; }
    catch { throw new Error(`invalid argument value: ${token}`); }
  });
}

function stageFingerprint(result: EmuResult, id: number | null): string {
  if (id === null) return 'none';
  const stage = result.stages[id];
  if (!stage) return 'missing';
  // Stage numbers depend on discovery order. Hash the captured page instead.
  let hash = 0xcbf29ce484222325n;
  for (const byte of stage.snapshot) hash = BigInt.asUintN(64, (hash ^ BigInt(byte)) * 0x100000001b3n);
  return `${stage.origin}:${stage.pageBase}:${stage.snapshot.length}:${hash.toString(16)}`;
}

export function flowKeys(result: EmuResult): FlowKeys {
  const cached = flowKeyCache.get(result);
  if (cached) return cached;
  const stages = new Map<number | null, string>();
  const key = (node: FlowNode): string => {
    if (!stages.has(node.stageId)) stages.set(node.stageId, stageFingerprint(result, node.stageId));
    return `${node.addr}:${node.size}:${node.mode ?? '-'}:${toHex(node.bytes)}:${stages.get(node.stageId)}`;
  };
  const nodes = result.flow.nodes.map(key);
  const edges = new Set(result.flow.edges.map((edge) => `${nodes[edge.fromId]}→${nodes[edge.toId]}`));
  const path = result.flow.path.map((id) => nodes[id] ?? `missing:${id}`);
  const keys = { nodes, edges, path };
  flowKeyCache.set(result, keys);
  return keys;
}

export interface ScenarioComparison {
  newEdges: number;
  totalEdges: number;
  firstDifferentStep: number | null;
  commonSteps: number;
  prefixLimited: boolean;
}

export function compareScenario(
  baseline: EmuResult,
  current: EmuResult,
  previouslySeen: ReadonlySet<string>,
): ScenarioComparison {
  const left = flowKeys(baseline).path;
  const right = flowKeys(current);
  const common = Math.min(left.length, right.path.length);
  let different = 0;
  while (different < common && left[different] === right.path[different]) different++;
  const prefixLimited = different === common && (
    (left.length === right.path.length && (baseline.flow.pathTruncated || current.flow.pathTruncated))
    || (left.length < right.path.length && baseline.flow.pathTruncated)
    || (right.path.length < left.length && current.flow.pathTruncated)
  );
  return {
    newEdges: [...right.edges].filter((edge) => !previouslySeen.has(edge)).length,
    totalEdges: right.edges.size,
    firstDifferentStep: different < common || (!prefixLimited && left.length !== right.path.length) ? different + 1 : null,
    commonSteps: different,
    prefixLimited,
  };
}
