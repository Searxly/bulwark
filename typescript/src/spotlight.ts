/**
 * Stage 3 — spotlighting (Hines et al., Microsoft, 2024).
 *
 * Makes untrusted content unmistakably *data*: delimit it with a random nonce
 * boundary, optionally data-mark it (spaces → marker), or base64-encode it.
 */

import type { SpotlightResult } from "./types.js";

export const DEFAULT_MARKER = "▁"; // ▁ LOWER ONE EIGHTH BLOCK — reads as a space marker
export const DEFAULT_TAG = "untrusted_content";

function randomHex(nBytes = 9): string {
  const buf = new Uint8Array(nBytes);
  if (typeof globalThis.crypto?.getRandomValues === "function") {
    globalThis.crypto.getRandomValues(buf);
  } else {
    for (let i = 0; i < nBytes; i++) buf[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function makeNonce(nBytes = 9): string {
  return randomHex(nBytes);
}

export function delimit(text: string, nonce?: string, tag: string = DEFAULT_TAG): { wrapped: string; nonce: string } {
  const n = nonce ?? makeNonce();
  const open = `<${tag} data-nonce="${n}">`;
  const close = `</${tag} data-nonce="${n}">`;
  return { wrapped: `${open}\n${text}\n${close}`, nonce: n };
}

export function datamark(text: string, marker: string = DEFAULT_MARKER): string {
  return text.split(" ").join(marker);
}

export function encodeBase64(text: string): string {
  if (typeof Buffer !== "undefined") return Buffer.from(text, "utf-8").toString("base64");
  const bytes = new TextEncoder().encode(text);
  let bin = "";
  bytes.forEach((b) => {
    bin += String.fromCharCode(b);
  });
  // eslint-disable-next-line no-undef
  return btoa(bin);
}

export interface SpotlightOptions {
  methods?: string[];
  nonce?: string;
  marker?: string;
  tag?: string;
}

export function spotlight(text: string, opts: SpotlightOptions = {}): SpotlightResult {
  const { methods = ["delimit"], nonce, marker = DEFAULT_MARKER, tag = DEFAULT_TAG } = opts;
  const applied: string[] = [];
  let content = text;
  let usedMarker: string | undefined;
  let base64Encoded = false;

  if (methods.includes("base64")) {
    content = encodeBase64(content);
    base64Encoded = true;
    applied.push("base64");
  } else if (methods.includes("datamark")) {
    content = datamark(content, marker);
    usedMarker = marker;
    applied.push("datamark");
  }

  const d = delimit(content, nonce, tag);
  applied.push("delimit");

  return {
    content: d.wrapped,
    nonce: d.nonce,
    methods: applied,
    marker: usedMarker,
    base64Encoded,
  };
}
