export interface Env {
  AI: Ai;
  AQX_AI_INTERNAL_TOKEN: string;
}

const MODEL = "@cf/meta/llama-3.1-8b-instruct";
const POLICY = `You are AQX's conservative review safety classifier.
Allow respectful criticism, complaints, negative opinions and disagreement.
Flag only clear threats, targeted hate, harassment, sexual exploitation,
fraud/scams, spam, illegal promotion, or exposed highly sensitive personal data.
Ambiguous, quoted, reclaimed, contextual or uncertain content must be human_review.
Return only JSON: {"decision":"publish|reject|human_review","confidence":0-1,
"categories":["..."],"rationale":"short explanation"}.
Do not infer violations from negative sentiment alone.`;

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

function authorized(request: Request, env: Env): boolean {
  const supplied = request.headers.get("authorization") || "";
  const expected = env.AQX_AI_INTERNAL_TOKEN || "";
  if (expected.length < 32 || !supplied.startsWith("Bearer ")) return false;
  const a = supplied.slice(7);
  if (a.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

function safeDecision(raw: any) {
  const decision = ["publish", "reject", "human_review"].includes(raw?.decision)
    ? raw.decision : "human_review";
  const confidence = Number.isFinite(Number(raw?.confidence))
    ? Math.max(0, Math.min(1, Number(raw.confidence))) : 0;
  if (decision === "publish") {
    return { decision: "human_review", confidence, categories: raw?.categories || [],
      rationale: "Automatic publication is disabled pending AQX validation.",
      publish_allowed: false };
  }
  if (decision === "reject" && confidence < 0.98) {
    return { decision: "human_review", confidence, categories: raw?.categories || [],
      rationale: "Potential violation requires human confirmation.",
      publish_allowed: false };
  }
  return { decision, confidence, categories: Array.isArray(raw?.categories) ? raw.categories : [],
    rationale: String(raw?.rationale || "Model returned no rationale").slice(0, 500),
    publish_allowed: false };
}

function parseModelJson(value: unknown): any {
  if (typeof value === "object" && value !== null) {
    const v = value as any;
    if (typeof v.response === "string") value = v.response;
    else return v;
  }
  const text = String(value ?? "").trim().replace(/^\`\`\`(?:json)?\s*/i, "").replace(/\`\`\`$/, "");
  const start = text.indexOf("{"), end = text.lastIndexOf("}");
  if (start < 0 || end <= start) throw new Error("INVALID_MODEL_JSON");
  return JSON.parse(text.slice(start, end + 1));
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/health") {
      return json({ service: "AQX AI Engine", status: "ok", inference: "Workers AI",
        model: MODEL, auto_publish: false });
    }
    if (request.method !== "POST" ||
        !["/v1/analyze", "/v1/chat/completions"].includes(url.pathname)) {
      return json({ error: "NOT_FOUND" }, 404);
    }
    if (!authorized(request, env)) return json({ error: "UNAUTHORIZED" }, 401);

    let body: any;
    try { body = await request.json(); } catch { return json({ error: "INVALID_JSON" }, 400); }
    let input = "";
    if (url.pathname === "/v1/analyze") input = String(body?.text || "");
    else {
      const messages = Array.isArray(body?.messages) ? body.messages : [];
      input = messages.map((m: any) => String(m?.content || "")).join("\n");
    }
    if (!input.trim()) return json({ error: "TEXT_REQUIRED" }, 400);
    if (input.length > 12000) return json({ error: "TEXT_TOO_LARGE", max_chars: 12000 }, 413);

    try {
      const result = await env.AI.run(MODEL, {
        messages: [
          { role: "system", content: POLICY },
          { role: "user", content: input },
        ],
        max_tokens: 300,
        temperature: 0,
      });
      const decision = safeDecision(parseModelJson(result));
      if (url.pathname === "/v1/analyze") return json({ ...decision, model: MODEL });
      return json({
        id: "aqx-" + crypto.randomUUID(),
        object: "chat.completion",
        choices: [{ index: 0, message: { role: "assistant", content: JSON.stringify(decision) },
          finish_reason: "stop" }],
        model: MODEL,
      });
    } catch {
      return json({ error: "AI_INFERENCE_FAILED", decision: "human_review",
        publish_allowed: false }, 503);
    }
  },
};
