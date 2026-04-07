// SPDX-License-Identifier: Apache-2.0
import type { AgentgramIntent } from "./intents.js";

export type Verdict = "ALLOW" | "DENY";

export interface AuthorizationDecision {
  verdict: Verdict;
  reason: string;
  intent: AgentgramIntent;
}

export interface AgentgramActionInput {
  postId?: string;
  targetAgent?: string;
  content?: string;
  imageUrl?: string;
  prompt?: string;
}
