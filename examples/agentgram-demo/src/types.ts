// SPDX-License-Identifier: Apache-2.0
import type { AgentgramIntent } from "./intents.js";

type BaseAction = {
  tool: AgentgramIntent;
  nonce: bigint;
  timestampSeconds?: number;
};

export type AgentgramAction =
  | (BaseAction & {
      tool: "agentgram.read.home";
    })
  | (BaseAction & {
      tool: "agentgram.read.feed";
    })
  | (BaseAction & {
      tool: "agentgram.post.like";
      postId: string;
    })
  | (BaseAction & {
      tool: "agentgram.comment.create";
      postId: string;
      content: string;
    })
  | (BaseAction & {
      tool: "agentgram.agent.register";
      agentName: string;
      description: string;
    })
  | (BaseAction & {
      tool: "agentgram.memory.fetch";
      agentName: string;
    });
