// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Evidence-grounded attack-chain stitching.
 *
 * Links findings where one finding's `chain_enables` artifact appears in
 * another finding's `chain_prerequisites`. Only explicit artifact matches form
 * an edge — there is no speculative chaining. Chains are ranked by the maximum
 * CVSS score of any node, ties broken by longer chain length.
 */

import type { AttackChain, ComputedFinding } from './types.js';

export function buildChains(findings: ComputedFinding[]): AttackChain[] {
  if (findings.length < 2) return [];

  // Build adjacency: u -> v when an artifact u.enables ∈ v.prerequisites.
  const adjacency = new Map<string, Set<string>>();
  for (const u of findings) {
    const targets = new Set<string>();
    for (const v of findings) {
      if (u.id === v.id) continue;
      const links = u.chain_enables.some((tag) => v.chain_prerequisites.includes(tag));
      if (links) targets.add(v.id);
    }
    adjacency.set(u.id, targets);
  }

  const byId = new Map(findings.map((f) => [f.id, f]));

  // A finding is a chain *start* if no other finding enables its prerequisites
  // (i.e. nothing points to it), or it has no prerequisites at all.
  const hasIncoming = new Set<string>();
  for (const targets of adjacency.values()) {
    for (const t of targets) hasIncoming.add(t);
  }
  const starts = findings.filter((f) => !hasIncoming.has(f.id));

  const chains: AttackChain[] = [];

  const walk = (path: string[]): void => {
    const lastId = path[path.length - 1]!;
    const next = adjacency.get(lastId) ?? new Set<string>();
    const unvisitedNext = [...next].filter((id) => !path.includes(id)); // guard cycles

    if (unvisitedNext.length === 0) {
      // Terminal: emit if it's a real chain (≥ 2 nodes).
      if (path.length >= 2) {
        const nodes = path.map((id) => {
          const f = byId.get(id)!;
          return { id: f.id, label: f.title };
        });
        const maxScore = Math.max(...path.map((id) => byId.get(id)!.cvss_score));
        chains.push({ nodes, maxScore });
      }
      return;
    }

    for (const nextId of unvisitedNext) {
      walk([...path, nextId]);
    }
  };

  for (const start of starts) {
    walk([start.id]);
  }

  // Rank: highest max node score first, then longer chains.
  chains.sort((a, b) => {
    if (b.maxScore !== a.maxScore) return b.maxScore - a.maxScore;
    return b.nodes.length - a.nodes.length;
  });

  return chains;
}
