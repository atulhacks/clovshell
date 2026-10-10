import { describe, expect, it } from 'vitest';
import { FlowCollector, flowEdgeLabels, isFlowTransfer } from '../flow';

describe('FlowCollector', () => {
  it('aggregates repeated transfers without losing first and last steps', () => {
    const flow = new FlowCollector();
    const a = Uint8Array.of(0x90);
    const b = Uint8Array.of(0xeb, 0xfd);
    flow.record(1, 0x1000, 1, a, null, 0);
    flow.record(2, 0x1001, 2, b, null, 0);
    flow.record(3, 0x1000, 1, a, null, 0);
    flow.record(4, 0x1001, 2, b, null, 0);
    const graph = flow.result();
    expect(graph.nodes).toHaveLength(2);
    expect(graph.path).toEqual([0, 1, 0, 1]);
    expect(graph.pathTruncated).toBe(false);
    expect(graph.nodes.map((node) => node.hits)).toEqual([2, 2]);
    expect(graph.nodes[1]).toMatchObject({ firstStep: 2, lastStep: 4 });
    expect(graph.edges).toEqual([
      { fromId: 0, toId: 1, hits: 2, firstStep: 2, lastStep: 4 },
      { fromId: 1, toId: 0, hits: 1, firstStep: 3, lastStep: 3 },
    ]);
    expect(isFlowTransfer(graph.nodes[0]!, graph.nodes[1]!)).toBe(false);
    expect(flowEdgeLabels(graph.nodes[1]!, graph.nodes[0]!)).toEqual(['back edge']);
  });

  it('separates the same address by bytes, ISA mode, and stage', () => {
    const flow = new FlowCollector();
    flow.record(1, 0x1000, 2, Uint8Array.of(0, 0xbf), 'thumb', 0);
    flow.record(2, 0x1000, 2, Uint8Array.of(1, 0xbf), 'thumb', 0);
    flow.record(3, 0x1000, 2, Uint8Array.of(1, 0xbf), 'arm', 0);
    flow.record(4, 0x1000, 2, Uint8Array.of(1, 0xbf), 'thumb', 1);
    const graph = flow.result();
    expect(graph.nodes).toHaveLength(4);
    expect(flowEdgeLabels(graph.nodes[2]!, graph.nodes[3]!)).toEqual(['stage hop', 'arm → thumb', 'back edge']);
  });

  it('bounds nodes and edges without fabricating a bridge across omitted code', () => {
    const flow = new FlowCollector(2, 1);
    flow.record(1, 0x1000, 1, Uint8Array.of(0x90), null, null);
    flow.record(2, 0x1001, 1, Uint8Array.of(0x90), null, null);
    flow.record(3, 0x1002, 1, Uint8Array.of(0x90), null, null);
    flow.record(4, 0x1000, 1, Uint8Array.of(0x90), null, null);
    flow.record(5, 0x1001, 1, Uint8Array.of(0x90), null, null);
    const graph = flow.result();
    expect(graph.truncated).toBe(true);
    expect(graph.nodes.map((node) => node.hits)).toEqual([2, 2]);
    expect(graph.edges).toEqual([{ fromId: 0, toId: 1, hits: 2, firstStep: 2, lastStep: 5 }]);
  });

  it('labels an instruction path that exceeds its capture limit', () => {
    const flow = new FlowCollector();
    for (let step = 1; step <= 8193; step++) flow.record(step, 0x1000, 1, Uint8Array.of(0x90), null, 0);
    expect(flow.result().path).toHaveLength(8192);
    expect(flow.result().pathTruncated).toBe(true);
  });
});
