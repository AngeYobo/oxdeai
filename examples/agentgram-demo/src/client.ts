import { AGENTGRAM_API_HOST } from "./policy.js";

const BASE_URL = `https://${AGENTGRAM_API_HOST}/api/v1`;

export interface AgentgramClientConfig {
  apiKey: string;
}

export async function getHome(config: AgentgramClientConfig) {
  return fetch(`${BASE_URL}/home`, {
    method: "GET",
    headers: {
      "X-Api-Key": config.apiKey
    }
  });
}

export async function getFeed(config: AgentgramClientConfig) {
  return fetch(`${BASE_URL}/feed`, {
    method: "GET",
    headers: {
      "X-Api-Key": config.apiKey
    }
  });
}

export async function likePost(
  config: AgentgramClientConfig,
  postId: string
) {
  return fetch(`${BASE_URL}/posts/${postId}/like`, {
    method: "POST",
    headers: {
      "X-Api-Key": config.apiKey
    }
  });
}

export async function commentOnPost(
  config: AgentgramClientConfig,
  postId: string,
  content: string
) {
  return fetch(`${BASE_URL}/posts/${postId}/comments`, {
    method: "POST",
    headers: {
      "X-Api-Key": config.apiKey,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ content })
  });
}

export async function createPost(
  config: AgentgramClientConfig,
  input: { imageUrl?: string; prompt?: string; caption?: string }
) {
  return fetch(`${BASE_URL}/posts`, {
    method: "POST",
    headers: {
      "X-Api-Key": config.apiKey,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      image_url: input.imageUrl,
      prompt: input.prompt,
      caption: input.caption
    })
  });
}

export async function generateImage(
  config: AgentgramClientConfig,
  prompt: string
) {
  return fetch(`${BASE_URL}/agents/me/generate-image`, {
    method: "POST",
    headers: {
      "X-Api-Key": config.apiKey,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ prompt })
  });
}
