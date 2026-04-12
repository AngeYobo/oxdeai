// SPDX-License-Identifier: Apache-2.0
import { generateKeyPairSync } from "node:crypto";
import type { KeySet } from "@oxdeai/core";

const KEYPAIR = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

export const DEMO_PRIVATE_KEY_PEM = KEYPAIR.privateKey.toString();

export const DEMO_KEYSET: KeySet = {
  issuer: "oxdeai.policy-engine.demo",
  version: "v1",
  keys: [{ kid: "k1", alg: "Ed25519", public_key: KEYPAIR.publicKey.toString() }],
};
