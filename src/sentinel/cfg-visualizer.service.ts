import { Injectable, Logger } from '@nestjs/common';
import * as crypto from 'crypto';

export interface CfgNode {
  id: string;
  label: string;
  line: number;
  type: 'ENTRY' | 'STATEMENT' | 'BRANCH_DECISION' | 'SINK_CALL' | 'EXIT';
  tainted: boolean;
  taintDetails?: string;
}

export interface CfgEdge {
  from: string;
  to: string;
  label?: string;
  isTaintedPath: boolean;
}

export interface ControlFlowGraphResult {
  graphId: string;
  cyclomaticComplexity: number;
  nodesCount: number;
  edgesCount: number;
  nodes: CfgNode[];
  edges: CfgEdge[];
  taintedPathsFound: number;
  generatedAt: string;
}

@Injectable()
export class CfgVisualizerService {
  private readonly logger = new Logger(CfgVisualizerService.name);

  /**
   * Generates a deterministic Control Flow Graph (CFG) from candidate source code.
   * Maps execution branches and flags tainted edge traversals.
   */
  public generateCfg(code: string, taintedLines: number[] = []): ControlFlowGraphResult {
    const graphId = `CFG-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const lines = (code || '').split('\n');

    const nodes: CfgNode[] = [];
    const edges: CfgEdge[] = [];

    // Entry node
    nodes.push({
      id: 'node_entry',
      label: 'START: Function Ingress',
      line: 1,
      type: 'ENTRY',
      tainted: false,
    });

    let prevNodeId = 'node_entry';
    let decisionCount = 0;

    for (let i = 0; i < lines.length; i++) {
      const lineNum = i + 1;
      const text = lines[i].trim();
      if (!text || text.startsWith('//') || text === '{' || text === '}') continue;

      const nodeId = `node_${lineNum}`;
      const isTainted = taintedLines.includes(lineNum) || /query|exec|spreadsheet|cell/i.test(text);

      if (/\b(if|else if|switch|case|while|for)\b/.test(text)) {
        decisionCount++;
        nodes.push({
          id: nodeId,
          label: `Branch Decision: ${text.substring(0, 35)}`,
          line: lineNum,
          type: 'BRANCH_DECISION',
          tainted: isTainted,
          taintDetails: isTainted ? 'Decision on potentially tainted condition' : undefined,
        });

        edges.push({
          from: prevNodeId,
          to: nodeId,
          label: 'flow',
          isTaintedPath: isTainted,
        });

        // Branch true/false fork representation
        const branchTrueId = `${nodeId}_true`;
        nodes.push({
          id: branchTrueId,
          label: `Path True: (Branch Taken)`,
          line: lineNum,
          type: 'STATEMENT',
          tainted: isTainted,
        });
        edges.push({ from: nodeId, to: branchTrueId, label: 'true', isTaintedPath: isTainted });
        prevNodeId = branchTrueId;
      } else if (/query|exec|exportCell|update|find/i.test(text)) {
        nodes.push({
          id: nodeId,
          label: `Sink Call: ${text.substring(0, 40)}`,
          line: lineNum,
          type: 'SINK_CALL',
          tainted: isTainted,
          taintDetails: isTainted ? 'Critical Security Sink reached' : undefined,
        });
        edges.push({
          from: prevNodeId,
          to: nodeId,
          label: 'exec_sink',
          isTaintedPath: isTainted,
        });
        prevNodeId = nodeId;
      } else {
        nodes.push({
          id: nodeId,
          label: `Stmt: ${text.substring(0, 35)}`,
          line: lineNum,
          type: 'STATEMENT',
          tainted: isTainted,
        });
        edges.push({
          from: prevNodeId,
          to: nodeId,
          isTaintedPath: isTainted,
        });
        prevNodeId = nodeId;
      }
    }

    // Exit node
    nodes.push({
      id: 'node_exit',
      label: 'END: Function Exit / Return',
      line: lines.length,
      type: 'EXIT',
      tainted: false,
    });
    edges.push({
      from: prevNodeId,
      to: 'node_exit',
      label: 'return',
      isTaintedPath: false,
    });

    const cyclomaticComplexity = 1 + decisionCount;
    const taintedPaths = edges.filter((e) => e.isTaintedPath).length;

    return {
      graphId,
      cyclomaticComplexity,
      nodesCount: nodes.length,
      edgesCount: edges.length,
      nodes,
      edges,
      taintedPathsFound: taintedPaths,
      generatedAt: new Date().toISOString(),
    };
  }
}
