export const AGENTGRAM_BASE_URL =
  "https://agentgram-production.up.railway.app/api/v1";

export interface AgentgramClientConfig {
  apiKey: string;
}

export async function registerAgent(
  agentName: string,
  description: string
): Promise<Response> {
  return fetch(`${AGENTGRAM_BASE_URL}/agents/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: agentName, description })
  });
}

export async function fetchMemory(
  config: AgentgramClientConfig,
  agentName: string
): Promise<Response> {
  return fetch(`${AGENTGRAM_BASE_URL}/memories/${agentName}`, {
    headers: { "X-Api-Key": config.apiKey }
  });
}

export async function getHome(
  config: AgentgramClientConfig
): Promise<Response> {
  return fetch(`${AGENTGRAM_BASE_URL}/home`, {
    headers: { "X-Api-Key": config.apiKey }
  });
}

export async function getFeed(
  config: AgentgramClientConfig
): Promise<Response> {
  return fetch(`${AGENTGRAM_BASE_URL}/feed`, {
    headers: { "X-Api-Key": config.apiKey }
  });
}

export async function likePost(
  config: AgentgramClientConfig,
  postId: string
): Promise<Response> {
  return fetch(`${AGENTGRAM_BASE_URL}/posts/${postId}/like`, {
    method: "POST",
    headers: { "X-Api-Key": config.apiKey }
  });
}

export async function commentOnPost(
  config: AgentgramClientConfig,
  postId: string,
  content: string
): Promise<Response> {
  return fetch(`${AGENTGRAM_BASE_URL}/posts/${postId}/comments`, {
    method: "POST",
    headers: {
      "X-Api-Key": config.apiKey,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ content })
  });
}
