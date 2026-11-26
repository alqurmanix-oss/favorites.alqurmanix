import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const KEY = (() => {
  const raw = Deno.env.get("SUPABASE_SECRET_KEYS");
  if (raw) { try { return JSON.parse(raw).default; } catch {} }
  return Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
})();
const db = createClient(SUPABASE_URL, KEY, { auth: { persistSession: false, autoRefreshToken: false } });
const ID_URL = "https://fkiokwwztbyztleeuwks.supabase.co";
const DEFAULT_ORIGIN = "https://favorites.alqurmanix.com";

class ApiError extends Error { constructor(message: string, public status = 400) { super(message); } }
const cors = (req: Request) => {
  const origin = req.headers.get("origin") || DEFAULT_ORIGIN;
  let allowed = false;
  try {
    const u = new URL(origin);
    const webOrigin = u.protocol === "https:" &&
      (u.hostname === "alqurmanix.com" || u.hostname.endsWith(".alqurmanix.com")) &&
      !u.port;
    // Browser extensions use isolated origins. Their requests still require the
    // high-entropy guest bearer token; no cookie-based credentials are enabled.
    const extensionOrigin =
      (u.protocol === "chrome-extension:" && /^[a-p]{32}$/.test(u.hostname) && !u.port) ||
      (u.protocol === "moz-extension:" && /^[0-9a-f-]{16,64}$/i.test(u.hostname) && !u.port);
    allowed = webOrigin || extensionOrigin;
  } catch {}
  return {
    "Access-Control-Allow-Origin": allowed ? origin : "null",
    "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-aqx-session, x-aqx-guest-token",
    "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
    "Vary": "Origin"
  };
};
const out = (req: Request, data: unknown, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { ...cors(req), "Content-Type": "application/json", "Cache-Control": "no-store" }
});

// Human review administration reuses the existing AQX Central Admin session.
// No static admin token is exposed to Blogger or accepted from the browser.
const CENTRAL_ADMIN_URL = "https://fkiokwwztbyztleeuwks.supabase.co/functions/v1/aqx-central-admin/v1/session/check";
const CENTRAL_ADMIN_PUBLISHABLE_KEY = "sb_publishable_4DCXObCqPUoNnI8ANOo8dA_nRAg0y5_";
async function requireCentralAdmin(req: Request) {
  const authorization = req.headers.get("authorization") || "";
  if (!/^Bearer\s+\S+$/i.test(authorization)) throw new ApiError("REVIEW_ADMIN_SESSION_REQUIRED", 401);
  let response: Response;
  try {
    response = await fetch(CENTRAL_ADMIN_URL, {
      method: "POST",
      headers: {
        "apikey": CENTRAL_ADMIN_PUBLISHABLE_KEY,
        "Authorization": authorization,
        "Content-Type": "application/json"
      },
      body: "{}",
      cache: "no-store"
    });
  } catch {
    throw new ApiError("CENTRAL_ADMIN_UNAVAILABLE", 503);
  }
  const result = await response.json().catch(() => ({}));
  if (!response.ok || result.success !== true || result.allowed !== true) {
    const status = response.status === 401 || response.status === 403 ? response.status : 503;
    throw new ApiError(status === 401 ? "REVIEW_ADMIN_SESSION_INVALID" :
      status === 403 ? "REVIEW_ADMIN_NOT_AUTHORIZED" : "CENTRAL_ADMIN_UNAVAILABLE", status);
  }
  return result.admin || {};
}
const hex = (b: Uint8Array) => Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
const hash = async (s: string) => hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s))));
const hmacHash = async (s: string) => {
  const pepper = Deno.env.get("AQX_FAVORITES_RATE_SALT") || KEY;
  const cryptoKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(pepper), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(s))));
};
async function enforceLibrarySyncRateLimit(req: Request, guestId: string) {
  const forwarded = req.headers.get("cf-connecting-ip") || req.headers.get("x-forwarded-for") || req.headers.get("x-real-ip") || "unknown";
  const ip = forwarded.split(",")[0].trim().toLowerCase() || "unknown";
  const salt = Deno.env.get("AQX_FAVORITES_RATE_SALT") || KEY;
  const ipKey = await hash(salt + "|library-sync-ip|" + ip);
  const guestKey = await hash(salt + "|library-sync-guest|" + guestId);
  const [ipLimit, guestLimit] = await Promise.all([
    db.rpc("aqx_favorites_consume_rate_limit", { p_key_hash_hex: ipKey, p_limit: 10, p_window_seconds: 900 }),
    db.rpc("aqx_favorites_consume_rate_limit", { p_key_hash_hex: guestKey, p_limit: 5, p_window_seconds: 900 })
  ]);
  if (ipLimit.error) throw ipLimit.error;
  if (guestLimit.error) throw guestLimit.error;
  if (ipLimit.data !== true || guestLimit.data !== true) throw new ApiError("LIBRARY_SYNC_RATE_LIMITED", 429);
};
async function recordGuestAuthFailure(req: Request) {
  const forwarded = req.headers.get("cf-connecting-ip") || req.headers.get("x-forwarded-for") || req.headers.get("x-real-ip") || "unknown";
  const ip = forwarded.split(",")[0].trim().toLowerCase() || "unknown";
  const parts = ip.split(".");
  const network = parts.length === 4 ? parts.slice(0, 3).join(".") + ".0/24" : (ip.includes(":") ? ip.split(":").slice(0, 4).join(":") + "::/64" : "unknown");
  const salt = Deno.env.get("AQX_FAVORITES_RATE_SALT") || KEY;
  const ipKey = await hash(salt + "|guest-auth-ip|" + ip);
  const netKey = await hash(salt + "|guest-auth-net|" + network);
  const [ipLimit, netLimit] = await Promise.all([
    db.rpc("aqx_favorites_consume_rate_limit", { p_key_hash_hex: ipKey, p_limit: 20, p_window_seconds: 900 }),
    db.rpc("aqx_favorites_consume_rate_limit", { p_key_hash_hex: netKey, p_limit: 120, p_window_seconds: 3600 })
  ]);
  if (ipLimit.error) throw ipLimit.error;
  if (netLimit.error) throw netLimit.error;
  if (ipLimit.data !== true || netLimit.data !== true) throw new ApiError("GUEST_RATE_LIMITED", 429);
};
const token = () => {
  const b = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};
function urlValue(value: unknown) {
  if (typeof value !== "string" || value.length > 2048) throw new ApiError("invalid_url");
  let u: URL;
  try { u = new URL(value.trim()); } catch { throw new ApiError("invalid_url"); }
  if (!["http:", "https:"].includes(u.protocol) || u.username || u.password) throw new ApiError("invalid_url");
  u.hash = ""; u.hostname = u.hostname.toLowerCase(); u.searchParams.sort();
  const v = u.toString();
  return { url: v, normalized_url: v.replace(/\/$/, "") };
}
async function account(req: Request) {
  const access = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  const session = req.headers.get("x-aqx-session") || "";
  if (!access || session.length < 30) throw new ApiError("AQX_SESSION_REQUIRED", 401);
  const origin = req.headers.get("origin") || DEFAULT_ORIGIN;
  const check = await fetch(ID_URL + "/functions/v1/aqx-favorites-auth/verify", {
    method: "POST",
    headers: { Authorization: "Bearer " + access, "x-aqx-session": session, Origin: origin, "Content-Type": "application/json" },
    body: "{}"
  });
  const state = await check.json().catch(() => ({}));
  if (!check.ok || state.valid !== true || typeof state.user_id !== "string") throw new ApiError("AQX_SESSION_INVALID", 401);

  return { owner_type: "account", owner_id: state.user_id };
}
async function guest(req: Request) {
  const raw = req.headers.get("x-aqx-guest-token") || "";
  if (raw.length < 8 || raw.length > 256) {
    await recordGuestAuthFailure(req);
    throw new ApiError("GUEST_SESSION_INVALID", 401);
  }
  let { data, error } = await db.from("aqx_favorites_guest_sessions").select("guest_id,status,expires_at")
    .eq("token_hash_hex", await hash(raw)).maybeSingle();
  if (error) throw error;
  if (!data) {
    const recoveryHash = await hmacHash(raw);
    const recoveryLookup = await db.from("aqx_favorites_guest_sessions").select("guest_id,status,expires_at")
      .eq("recovery_key_hash_hex", recoveryHash).maybeSingle();
    if (recoveryLookup.error) throw recoveryLookup.error;
    data = recoveryLookup.data;
  }
  let deviceId: string | null = null;
  if (!data) {
    const deviceLookup = await db.from("aqx_favorites_guest_devices")
      .select("id,guest_id").eq("device_token_hash_hex", await hash(raw))
      .is("revoked_at", null).maybeSingle();
    if (deviceLookup.error) throw deviceLookup.error;
    if (deviceLookup.data) {
      deviceId = deviceLookup.data.id;
      const sessionLookup = await db.from("aqx_favorites_guest_sessions")
        .select("guest_id,status,expires_at").eq("guest_id", deviceLookup.data.guest_id).maybeSingle();
      if (sessionLookup.error) throw sessionLookup.error;
      data = sessionLookup.data;
    }
  }
  if (!data || data.status !== "active" || new Date(data.expires_at).getTime() < Date.now()) {
    await recordGuestAuthFailure(req);
    throw new ApiError("GUEST_SESSION_INVALID", 401);
  }
  const activityAt = new Date();
  await db.from("aqx_favorites_guest_sessions").update({
    last_activity_at: activityAt.toISOString(),
    expires_at: new Date(activityAt.getTime() + 180 * 86400000).toISOString()
  }).eq("guest_id", data.guest_id);
  if (deviceId) {
    await db.from("aqx_favorites_guest_devices").update({last_seen_at:activityAt.toISOString()}).eq("id",deviceId);
  }
  return { owner_type: "guest", owner_id: data.guest_id };
}
async function mergeGuestForAccount(req: Request, accountOwner: any) {
  const rawGuestToken = req.headers.get("x-aqx-guest-token") || "";
  if (!rawGuestToken) return null;
  if (rawGuestToken.length < 8 || rawGuestToken.length > 256) throw new ApiError("GUEST_SESSION_REQUIRED", 401);
  const tokenHash = await hash(rawGuestToken);
  let { data: guestSession, error: guestSessionError } = await db.from("aqx_favorites_guest_sessions")
    .select("guest_id,status,expires_at,merged_into_account_id")
    .eq("token_hash_hex", tokenHash).maybeSingle();
  if (guestSessionError) throw guestSessionError;
  if (!guestSession) {
    const recoveryLookup = await db.from("aqx_favorites_guest_sessions")
      .select("guest_id,status,expires_at,merged_into_account_id")
      .eq("recovery_key_hash_hex", await hmacHash(rawGuestToken)).maybeSingle();
    if (recoveryLookup.error) throw recoveryLookup.error;
    guestSession = recoveryLookup.data;
  }
  if (!guestSession) {
    const deviceLookup = await db.from("aqx_favorites_guest_devices")
      .select("guest_id").eq("device_token_hash_hex", tokenHash).is("revoked_at", null).maybeSingle();
    if (deviceLookup.error) throw deviceLookup.error;
    if (deviceLookup.data) {
      const sessionLookup = await db.from("aqx_favorites_guest_sessions")
        .select("guest_id,status,expires_at,merged_into_account_id")
        .eq("guest_id", deviceLookup.data.guest_id).maybeSingle();
      if (sessionLookup.error) throw sessionLookup.error;
      guestSession = sessionLookup.data;
    }
  }
  if (!guestSession) throw new ApiError("GUEST_SESSION_INVALID", 401);
  if (guestSession.status === "merged") {
    if (guestSession.merged_into_account_id === accountOwner.owner_id) {
      return { success: true, already_merged: true };
    }
    throw new ApiError("GUEST_SESSION_ALREADY_MERGED", 409);
  }
  if (guestSession.status !== "active" || new Date(guestSession.expires_at).getTime() <= Date.now()) {
    throw new ApiError("GUEST_SESSION_INVALID", 401);
  }
  const { data: mergeResult, error: mergeError } = await db.rpc("aqx_favorites_merge_guest_v2", {
    p_guest_id: guestSession.guest_id,
    p_account_id: accountOwner.owner_id
  });
  if (mergeError) throw mergeError;
  return mergeResult;
}
async function owner(req: Request, accountOnly = false) {
  if (/^Bearer\s+/i.test(req.headers.get("authorization") || "")) {
    const accountOwner = await account(req);
    await mergeGuestForAccount(req, accountOwner);
    return accountOwner;
  }
  if (accountOnly) throw new ApiError("AQX_ACCOUNT_REQUIRED", 401);
  return await guest(req);
}
async function collectionId(o: any, name: string) {
  if (!name) return null;
  const { data, error } = await db.from("aqx_favorites_collections").select("id,name").eq("owner_type", o.owner_type).eq("owner_id", o.owner_id).is("deleted_at", null);
  if (error) throw error;
  const found = (data || []).find((x: any) => x.name.toLowerCase() === name.toLowerCase());
  if (found) return found.id;
  const created = await db.from("aqx_favorites_collections").insert({ ...o, name }).select("id").single();
  if (created.error) {
    if (created.error.code === "23505") return await collectionId(o, name);
    throw created.error;
  }
  return created.data.id;
}
async function event(o: any, type: string, itemId: string | null = null, details: any = {}) {
  const { error } = await db.from("aqx_favorites_events").insert({ ...o, event_type: type, item_id: itemId, details });
  if (error) console.error("favorites_event", error.message);
}

async function planFor(o: any) {
  if (o.owner_type === "account") {
    const { data: sub, error: se } = await db.from("aqx_favorites_subscriptions")
      .select("id,plan_id,status,billing_interval,currency,amount_minor,current_period_end,cancel_at_period_end")
      .eq("account_id", o.owner_id).in("status", ["active","trialing"])
      .or("current_period_end.is.null,current_period_end.gt." + new Date().toISOString())
      .order("created_at", { ascending: false }).limit(1).maybeSingle();
    if (se) throw se;
    if (sub) {
      const { data: plan, error: pe } = await db.from("aqx_favorites_plans")
        .select("id,code,name,description,limits,features").eq("id", sub.plan_id).eq("is_active", true).maybeSingle();
      if (pe) throw pe;
      if (plan) return { plan, subscription: sub };
    }
  }
  const { data: free, error } = await db.from("aqx_favorites_plans")
    .select("id,code,name,description,limits,features").eq("code","free").eq("is_active",true).single();
  if (error) throw error;
  return { plan: free, subscription: null };
}
async function assertCapacity(o: any, metric: string, table: string, add = 1) {
  const { plan } = await planFor(o);
  const limit = Number(plan.limits?.[metric] ?? 0);
  if (limit < 0) return;
  const { count, error } = await db.from(table).select("id", { count:"exact", head:true })
    .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).is("deleted_at",null);
  if (error) throw error;
  if ((count || 0) + add > limit) throw new ApiError("PLAN_LIMIT_REACHED:" + metric, 402);
}
async function categoryById(o: any, id: string | null) {
  if (!id) return null;
  const { data, error } = await db.from("aqx_favorites_categories").select("id")
    .eq("id",id).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).is("deleted_at",null).maybeSingle();
  if (error) throw error;
  if (!data) throw new ApiError("CATEGORY_NOT_FOUND",404);
  return data.id;
}

async function requireFeature(o: any, feature: string) {
  const { plan } = await planFor(o);
  if (plan.features?.[feature] !== true) throw new ApiError("PLAN_FEATURE_NOT_INCLUDED:" + feature, 402);
  return plan;
}
async function ownedItem(o: any, id: string) {
  const { data, error } = await db.from("aqx_favorites_items").select("*")
    .eq("id",id).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).is("deleted_at",null).maybeSingle();
  if (error) throw error;
  if (!data) throw new ApiError("FAVORITE_NOT_FOUND",404);
  return data;
}


const ARCHIVE_BUCKET = "aqx-favorites-archives";
const ARCHIVE_UA = "AQXFavoritesArchive/1.0 (+https://alqurmanix.com/crawler-policy)";
function archiveSafeUrl(raw:string):URL {
  if(raw.length>4096) throw new Error("url_too_long");
  const u=new URL(raw);
  if(!["http:","https:"].includes(u.protocol)||u.username||u.password) throw new Error("unsupported_url");
  const h=u.hostname.toLowerCase().replace(/^\[|\]$/g,"");
  if(!h||h==="localhost"||h.endsWith(".localhost")||h.endsWith(".local")||h.endsWith(".internal")) throw new Error("private_host");
  if(h.includes(":")||/^\d{1,3}(?:\.\d{1,3}){3}$/.test(h)) throw new Error("ip_literal_blocked");
  u.hash="";
  return u;
}
function archivePrivateV4(ip:string):boolean {
  const p=ip.split(".").map(Number); if(p.length!==4||p.some(x=>!Number.isInteger(x)||x<0||x>255)) return true;
  const [a,b]=p;
  return a===0||a===10||a===127||a>=224||(a===100&&b>=64&&b<=127)||(a===169&&b===254)||
    (a===172&&b>=16&&b<=31)||(a===192&&(b===168||b===0||(b===88&&p[2]===99)))||
    (a===198&&(b===18||b===19||b===51))||(a===203&&b===0);
}
function archivePrivateV6(ip:string):boolean {
  const x=ip.toLowerCase();
  return !(x.startsWith("2")||x.startsWith("3"))||x.startsWith("2001:db8")||x.startsWith("2002:");
}
async function archiveAssertPublicHost(u:URL) {
  let found=false;
  try { for(const ip of await Deno.resolveDns(u.hostname,"A")) { found=true; if(archivePrivateV4(ip)) throw new Error("private_address_blocked"); } }
  catch(e) { if(String(e).includes("private_address_blocked")) throw e; }
  try { for(const ip of await Deno.resolveDns(u.hostname,"AAAA")) { found=true; if(archivePrivateV6(ip)) throw new Error("private_address_blocked"); } }
  catch(e) { if(String(e).includes("private_address_blocked")) throw e; }
  if(!found) throw new Error("dns_resolution_failed");
}
async function archiveRobotsAllows(u:URL):Promise<boolean> {
  await archiveAssertPublicHost(u);
  const robotsUrl=new URL("/robots.txt",u.origin);
  let res:Response;
  try { res=await fetch(robotsUrl,{headers:{"User-Agent":ARCHIVE_UA},redirect:"error",signal:AbortSignal.timeout(7000)}); }
  catch { throw new Error("robots_unreachable"); }
  if(res.status===404) return true;
  if(res.status===401||res.status===403||res.status===429||res.status>=500) return false;
  if(!res.ok) return true;
  const text=(await res.text()).slice(0,100000);
  const groups:{agents:string[];rules:{allow:boolean;path:string}[]}[]=[];
  let current:{agents:string[];rules:{allow:boolean;path:string}[]}|null=null;
  for(const raw of text.split(/\r?\n/)){
    const line=raw.replace(/#.*$/,"").trim(); if(!line) continue;
    const m=line.match(/^([^:]+):\s*(.*)$/); if(!m) continue;
    const key=m[1].toLowerCase(),value=m[2].trim();
    if(key==="user-agent"){
      if(!current||current.rules.length){current={agents:[],rules:[]};groups.push(current);}
      current.agents.push(value.toLowerCase());
    } else if((key==="allow"||key==="disallow")&&current&&value){
      current.rules.push({allow:key==="allow",path:value});
    }
  }
  const uaGroups=groups.filter(g=>g.agents.some(a=>a==="aqxfavoritesarchive"||a==="*"));
  const path=u.pathname+u.search;
  const rules=uaGroups.flatMap(g=>g.rules).filter(r=>path.startsWith(r.path)).sort((a,b)=>b.path.length-a.path.length);
  return !rules.length||rules[0].allow;
}
function archiveDecode(s:string):string {
  return s.replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos|nbsp);/gi,(_m,x)=>{
    const v=String(x).toLowerCase();
    if(v.startsWith("#x")){try{return String.fromCodePoint(parseInt(v.slice(2),16));}catch{return " ";}}
    if(v.startsWith("#")){try{return String.fromCodePoint(parseInt(v.slice(1),10));}catch{return " ";}}
    return ({amp:"&",lt:"<",gt:">",quot:'"',apos:"'",nbsp:" "} as Record<string,string>)[v]||" ";
  });
}
function archiveText(html:string,max=350000):string {
  const body=html.match(/<body\b[^>]*>([\s\S]*?)<\/body>/i)?.[1]||html;
  return archiveDecode(body.replace(/<(script|style|noscript|svg|canvas|iframe|nav|footer|header|form|button)\b[^>]*>[\s\S]*?<\/\1>/gi," ")
    .replace(/<!--[\s\S]*?-->/g," ").replace(/<(br|p|div|li|h[1-6]|section|article)\b[^>]*>/gi,"\n")
    .replace(/<[^>]+>/g," ").replace(/[ \t\u00a0]+/g," ").replace(/\n\s*/g,"\n").trim()).slice(0,max);
}
function archiveMeta(html:string,key:string):string|null {
  for(const tag of html.match(/<meta\b[^>]*>/gi)||[]){
    const n=(tag.match(/\b(?:name|property)\s*=\s*["']([^"']+)["']/i)?.[1]||"").toLowerCase();
    if(n===key.toLowerCase()) return tag.match(/\bcontent\s*=\s*["']([^"']*)["']/i)?.[1]||null;
  }
  return null;
}
async function archiveFetch(start:URL) {
  let current=start;
  for(let n=0;n<=5;n++){
    await archiveAssertPublicHost(current);
    if(!await archiveRobotsAllows(current)) throw new Error("robots_denied");
    const res=await fetch(current,{headers:{"User-Agent":ARCHIVE_UA,"Accept":"text/html,application/xhtml+xml;q=0.9"},
      redirect:"manual",signal:AbortSignal.timeout(18000)});
    if([301,302,303,307,308].includes(res.status)){
      const loc=res.headers.get("location"); if(!loc) throw new Error("redirect_without_location");
      current=archiveSafeUrl(new URL(loc,current).toString()); continue;
    }
    if(!res.ok) throw new Error("http_"+res.status);
    const ct=(res.headers.get("content-type")||"").toLowerCase();
    if(!ct.includes("text/html")&&!ct.includes("application/xhtml+xml")) throw new Error("unsupported_content_type:"+ct.slice(0,80));
    const len=Number(res.headers.get("content-length")||0); if(len>1024*1024) throw new Error("page_too_large");
    const reader=res.body?.getReader(); if(!reader) throw new Error("empty_body");
    const chunks:Uint8Array[]=[];let size=0;
    while(true){const part=await reader.read();if(part.done)break;size+=part.value.length;
      if(size>1024*1024){await reader.cancel();throw new Error("page_too_large");}chunks.push(part.value);}
    const bytes=new Uint8Array(size);let offset=0;for(const c of chunks){bytes.set(c,offset);offset+=c.length;}
    const html=new TextDecoder().decode(bytes);
    const title=archiveDecode(html.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i)?.[1]||"").replace(/<[^>]+>/g," ").trim().slice(0,300);
    const h1=archiveDecode(html.match(/<h1\b[^>]*>([\s\S]*?)<\/h1>/i)?.[1]||"").replace(/<[^>]+>/g," ").trim().slice(0,300);
    const canonicalRaw=html.match(/<link\b[^>]*rel=["'][^"']*canonical[^"']*["'][^>]*>/i)?.[0]?.match(/\bhref=["']([^"']+)["']/i)?.[1]||"";
    let canonical:string|null=null;try{canonical=canonicalRaw?new URL(archiveDecode(canonicalRaw),current).toString():current.toString();}catch{canonical=current.toString();}
    return {bytes,html,finalUrl:current.toString(),status:res.status,contentType:ct,
      title:title||h1||archiveMeta(html,"og:title")||null,
      description:archiveMeta(html,"description")||archiveMeta(html,"og:description"),
      canonical,language:html.match(/<html\b[^>]*\blang=["']([^"']+)["']/i)?.[1]||null};
  }
  throw new Error("redirect_limit");
}
async function processArchiveJob(job:any) {
  const payload=job.input_payload||{},archiveId=String(payload.archive_id||"");
  const {data:archive,error:archiveReadError}=await db.from("aqx_favorites_archives").select("*")
    .eq("id",archiveId).eq("owner_type",job.owner_type).eq("owner_id",job.owner_id).maybeSingle();
  if(archiveReadError){
    await db.from("aqx_favorites_processing_jobs").update({status:"failed",locked_at:null,locked_by:null,last_error:String(archiveReadError).slice(0,500),updated_at:new Date().toISOString()}).eq("id",job.id);
    throw archiveReadError;
  }
  if(!archive){
    await db.from("aqx_favorites_processing_jobs").update({status:"failed",locked_at:null,locked_by:null,last_error:"archive_record_not_found",updated_at:new Date().toISOString()}).eq("id",job.id);
    return {job_id:job.id,status:"failed",error:"archive_record_not_found"};
  }
  const {data:item,error:itemError}=await db.from("aqx_favorites_items").select("id,url,title")
    .eq("id",job.item_id).eq("owner_type",job.owner_type).eq("owner_id",job.owner_id).is("deleted_at",null).maybeSingle();
  if(itemError){
    await db.from("aqx_favorites_processing_jobs").update({status:"failed",locked_at:null,locked_by:null,last_error:String(itemError).slice(0,500),updated_at:new Date().toISOString()}).eq("id",job.id);
    throw itemError;
  }
  if(!item){
    await db.from("aqx_favorites_archives").update({capture_status:"failed",last_error:"favorite_item_not_found",updated_at:new Date().toISOString()}).eq("id",archiveId);
    await db.from("aqx_favorites_processing_jobs").update({status:"failed",locked_at:null,locked_by:null,last_error:"favorite_item_not_found",updated_at:new Date().toISOString()}).eq("id",job.id);
    return {job_id:job.id,status:"failed",error:"favorite_item_not_found"};
  }
  await db.from("aqx_favorites_archives").update({capture_status:"capturing",last_error:null,updated_at:new Date().toISOString()})
    .eq("id",archiveId).eq("owner_type",job.owner_type).eq("owner_id",job.owner_id);
  try{
    const result=await archiveFetch(archiveSafeUrl(item.url));
    const extracted=archiveText(result.html);
    const pageTitle=result.title||item.title||"";
    const excerpt=extracted.slice(0,1200);
    const digest=await crypto.subtle.digest("SHA-256",result.bytes);
    const contentHash=Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,"0")).join("");
    if(archive.content_hash && archive.content_storage_path && archive.content_hash!==contentHash){
      const {error:versionError}=await db.from("aqx_favorites_archive_versions").upsert({
        archive_id:archiveId,owner_type:job.owner_type,owner_id:job.owner_id,
        source_url:archive.source_url,canonical_url:archive.canonical_url,page_title:archive.page_title,
        excerpt:archive.excerpt,content_storage_path:archive.content_storage_path,content_hash:archive.content_hash,
        word_count:archive.word_count||0,mime_type:archive.mime_type,http_status:archive.http_status,
        captured_at:archive.captured_at||new Date().toISOString(),
        metadata:{preserved_before_refresh:true,previous_metadata:archive.metadata||{}}
      },{onConflict:"archive_id,content_hash",ignoreDuplicates:true});
      if(versionError) throw versionError;
    }
    const storagePath=job.owner_type+"/"+job.owner_id+"/"+archiveId+"/"+contentHash+".html";
    const {error:uploadError}=await db.storage.from(ARCHIVE_BUCKET).upload(storagePath,new Blob([result.bytes],{type:"text/html"}),
      {contentType:"text/html",upsert:true,cacheControl:"3600"});
    if(uploadError) throw uploadError;
    const {error:updateError}=await db.from("aqx_favorites_archives").update({
      source_url:item.url,canonical_url:result.canonical,page_title:pageTitle,excerpt,extracted_text:extracted,
      content_storage_path:storagePath,content_hash:contentHash,word_count:(extracted.match(/[\p{L}\p{N}]+/gu)||[]).length,
      language_code:result.language,mime_type:result.contentType,http_status:result.status,
      capture_status:"ready",captured_at:new Date().toISOString(),last_error:null,
      metadata:{final_url:result.finalUrl,description:result.description,storage_bucket:ARCHIVE_BUCKET,content_hash:contentHash}
    }).eq("id",archiveId).eq("owner_type",job.owner_type).eq("owner_id",job.owner_id);
    if(updateError) throw updateError;
    await db.from("aqx_favorites_processing_jobs").update({status:"completed",output_payload:{archive_id:archiveId,content_hash:contentHash,word_count:(extracted.match(/[\p{L}\p{N}]+/gu)||[]).length},locked_at:null,locked_by:null,last_error:null,updated_at:new Date().toISOString()}).eq("id",job.id);
    return {job_id:job.id,archive_id:archiveId,status:"ready",bytes:result.bytes.length,words:(extracted.match(/[\p{L}\p{N}]+/gu)||[]).length};
  }catch(e){
    const message=String(e).slice(0,500);
    const terminal=/robots_denied|private_|ip_literal|unsupported_url|unsupported_content_type|archive_record_not_found|favorite_item_not_found/.test(message);
    const retry=job.attempts<job.max_attempts&&!terminal;
    const delay=Math.min(3600,60*Math.pow(2,Math.max(0,job.attempts-1)));
    await db.from("aqx_favorites_archives").update({capture_status:retry?"queued":"failed",last_error:message,updated_at:new Date().toISOString()})
      .eq("id",archiveId).eq("owner_type",job.owner_type).eq("owner_id",job.owner_id);
    await db.from("aqx_favorites_processing_jobs").update({
      status:retry?"queued":"failed",run_after:new Date(Date.now()+delay*1000).toISOString(),
      locked_at:null,locked_by:null,last_error:message,updated_at:new Date().toISOString()
    }).eq("id",job.id);
    return {job_id:job.id,archive_id:archiveId,status:retry?"retrying":"failed",error:message};
  }
}

function normalizeReviewText(value:string):string {
  return String(value||"").toLowerCase()
    .normalize("NFKC")
    .replace(/[\u064B-\u065F\u0670\u0640]/g,"")
    .replace(/[أإآ]/g,"ا").replace(/ى/g,"ي")
    .replace(/[^\p{L}\p{N}@.+:/\s_-]/gu," ")
    .replace(/\s+/g," ").trim();
}
function analyzeReviewWithRules(comment:string,rating:number) {
  const text=normalizeReviewText(comment);
  const labels:string[]=[];
  const severe:RegExp[]=[
    /(?:ه|ح)?قتلك|سوف اقتلك|سأقتلك|سوف اؤذيك|هأذيك|هأضربك|هدمرك|هدبحك|هفجر(?:ك|كم)/u,
    /i will kill you|i['’]?ll kill you|i am going to kill you|i will hurt you|i will rape you|death threat/u,
    /(?:يا\s*)?(?:كلب|حيوان|خنزير|شرموط|قحبه|منيوك|كس امك|ابن الكلب)(?:\s|$)/u,
    /\b(?:nigger|faggot|kike|spic)\b/u,
    /انتم\s*(?:قذرون|حشرات|لا تستحقون الحياة)|كل(?:كم)?\s*(?:لا تستحقون|يجب قتلكم)/u
  ];
  for(const pattern of severe) if(pattern.test(text)) {
    labels.push("abuse_or_threat");
    return {decision:"reject",reason:"يتضمن النص إساءة مباشرة أو تهديدًا واضحًا يخالف قواعد المجتمع.",labels};
  }
  const hasEmail=/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i.test(comment);
  const hasPhone=/(?:\+?20|0)?1[0125][0-9]{8}\b|(?:\+?\d[\d\s().-]{8,}\d)/.test(comment);
  const hasLink=/(?:https?:\/\/|www\.|t\.me\/|wa\.me\/)/i.test(comment);
  if(hasEmail||hasPhone) labels.push("possible_personal_contact_data");
  if(hasLink) labels.push("external_link_or_promotion");
  if(/(?:واتساب|واتس اب|تليجرام|تلجرام|راسلني|تواصل معي|اتصل بي|خصم حصري|كود خصم|اشتر الان|اربح مجانا|استثمار مضمون|whatsapp|telegram|contact me|buy now|promo code|guaranteed profit|free money)/i.test(text)) labels.push("possible_promotion_or_spam");
  if(/(.)\1{5,}/u.test(text)||/\b(\p{L}{2,})(?:\s+\1){2,}\b/iu.test(text)) labels.push("repetitive_content");
  const words=text.split(/\s+/u).filter(Boolean);
  if(!text||words.length<2||text.length<8) labels.push("insufficient_review_detail");
  if(hasEmail||hasPhone||hasLink||labels.includes("possible_promotion_or_spam")||labels.includes("repetitive_content")||labels.includes("insufficient_review_detail")) {
    return {decision:"review",reason:"يحتاج هذا التقييم إلى مراجعة بشرية بسبب بيانات تواصل أو رابط أو نمط ترويجي أو قلة تفاصيل.",labels};
  }
  // A low rating or negative opinion is not a violation. It remains eligible for publication.
  return {decision:"publish",reason:"اجتاز التقييم فحوص قواعد AQX الداخلية للنص.",labels:["rule_engine_checked","text_only_checked"]};
}
async function ensureAqxOfficialReply(review:any) {
  if (!review || review.status !== "published" || review.aqx_reply) return review;
  const { data: reply, error: replyError } = await db.rpc("aqx_favorites_generate_official_reply", {
    p_rating: Number(review.rating || 3), p_comment: String(review.comment || "")
  });
  if (replyError) throw replyError;
  const now = new Date().toISOString();
  const { data: updated, error: updateError } = await db.from("aqx_favorites_app_reviews")
    .update({ aqx_reply: reply, aqx_reply_at: now, aqx_reply_engine: "aqx_internal_rules" })
    .eq("id", review.id).eq("status", "published").is("aqx_reply", null)
    .select("*").maybeSingle();
  if (updateError) throw updateError;
  return updated || review;
}

async function moderateExistingFavoritesReview(saved:any) {
  if(!saved||saved.ai_reviewed_at) return saved;
  const {data:media,error:mediaError}=await db.from("aqx_favorites_app_review_media").select("id").eq("review_id",saved.id);
  if(mediaError) return saved;
  const result=analyzeReviewWithRules(String(saved.comment||""),Number(saved.rating||0));
  const hasMedia=(media||[]).length>0;
  const decision=hasMedia&&result.decision==="publish"?"review":result.decision;
  const labels=Array.from(new Set([...result.labels,...(hasMedia?["attachment_requires_human_review"]:[])]));
  const reason=hasMedia?"المرفقات تحتاج فحصًا بشريًا؛ محرك القواعد لا يدّعي فهم الصور أو التسجيلات.":result.reason;
  const status=decision==="publish"?"published":decision==="reject"?"hidden":"pending";
  const now=new Date().toISOString();
  const {data,error}=await db.from("aqx_favorites_app_reviews").update({
    status,published_at:status==="published"?now:null,moderation_reason:reason,
    moderation_labels:labels,ai_reviewed_at:now
  }).eq("id",saved.id).select("id,rating,comment,status,moderation_reason,moderation_labels,ai_reviewed_at,likes_count,created_at,updated_at").single();
  if(error) throw error;
  const withReply = status === "published" ? await ensureAqxOfficialReply(data) : data;
  await reviewAudit(saved.id,null,"rules_reviewed",decision,reason,labels,{engine:"aqx_internal_rules",has_media:hasMedia});
  if(decision!=="publish") await notifyReviewEscalation(saved.id,reason,hasMedia?"high":"normal",decision);
  return withReply;
}

const REVIEW_MEDIA_BUCKET = "aqx-favorites-review-media";
async function reviewAudit(reviewId:string|null, mediaId:string|null, action:string, decision:string|null, reason:string, labels:any[] = [], metadata:any = {}) {
  const {error}=await db.from("aqx_favorites_review_moderation_audit").insert({
    review_id:reviewId,media_id:mediaId,actor_type:"system",action,decision,reason,
    labels,metadata
  });
  if(error) console.error("review audit insert failed",error.message);
}
async function sendReviewTelegram(message:string):Promise<boolean> {
  const botToken=Deno.env.get("AQX_REVIEW_TELEGRAM_BOT_TOKEN")||Deno.env.get("TELEGRAM_BOT_TOKEN")||"";
  const chatId=Deno.env.get("AQX_REVIEW_TELEGRAM_CHAT_ID")||Deno.env.get("TELEGRAM_CHAT_ID")||"";
  if(!botToken||!chatId) { console.warn("AQX Favorites Telegram secrets missing"); return false; }
  try {
    const res=await fetch("https://api.telegram.org/bot"+botToken+"/sendMessage",{
      method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({chat_id:chatId,text:message.slice(0,3900),disable_web_page_preview:true}),
      signal:AbortSignal.timeout(10000)
    });
    const payload=await res.json().catch(()=>({}));
    if(!res.ok||payload.ok!==true) throw new Error(String(payload.description||"TELEGRAM_SEND_FAILED"));
    return true;
  } catch(e) { console.error("AQX Favorites Telegram delivery failed",String(e)); return false; }
}
async function getReviewTelegramDetails(reviewId:string) {
  const {data:review,error}=await db.from("aqx_favorites_app_reviews").select("id,owner_type,rating,comment,status,moderation_reason,moderation_labels,created_at").eq("id",reviewId).maybeSingle();
  if(error||!review) return null;
  const {data:media}=await db.from("aqx_favorites_app_review_media").select("media_type,mime_type,size_bytes,moderation_status").eq("review_id",reviewId);
  return {review,media:media||[]};
}
async function notifyReviewEscalation(reviewId:string,reason:string,priority="normal",aiDecision="review") {
  const {data:existingEsc,error:existingEscError}=await db.from("aqx_favorites_review_escalations")
    .select("id").eq("review_id",reviewId).eq("status","open")
    .order("created_at",{ascending:false}).limit(1).maybeSingle();
  if(existingEscError) { console.error("review escalation lookup failed",existingEscError.message); return; }
  if(existingEsc?.id) return;
  const {data:esc,error}=await db.from("aqx_favorites_review_escalations")
    .insert({review_id:reviewId,reason,priority,telegram_next_attempt_at:new Date().toISOString()})
    .select("id").single();
  if(error) { console.error("review escalation insert failed",error.message); return; }
  const details=await getReviewTelegramDetails(reviewId);
  const review=details?.review; const media=details?.media||[];
  const mediaSummary=media.length?media.map((m:any)=>String(m.media_type||"attachment")+" ("+String(m.mime_type||"unknown")+", "+Math.ceil(Number(m.size_bytes||0)/1024)+" KB)").join("\n"):"لا توجد مرفقات";
  const labels=Array.isArray(review?.moderation_labels)&&review.moderation_labels.length?review.moderation_labels.join("، "):"لا توجد تصنيفات";
  const message=[
    "🚨 AQX Favorites | نتيجة محرك قواعد AQX الداخلي",
    "جهة المراجعة: محرك القواعد الداخلي AQX",
    "قرار محرك القواعد: "+(aiDecision==="reject"?"رفض بسبب مخالفة":aiDecision==="review"?"تحويل للمراجعة البشرية":aiDecision==="pending_unavailable"?"تعذر الفحص — معلّق":aiDecision==="pending_error"?"فشل الفحص — معلّق":"قرار آخر"),
    "الحالة: "+(aiDecision==="reject"?"مرفوض لمخالفة":aiDecision==="review"?"يتطلب مراجعة بشرية":"معلّق ولم يُنشر"),
    "الأولوية: "+priority,
    "معرّف المراجعة: "+reviewId,
    "نوع المستخدم: "+(review?.owner_type==="guest"?"ضيف":"حساب AQX"),
    "التقييم: "+(review?.rating??"غير متاح")+"/5",
    "نص المراجعة:",String(review?.comment||"بدون تعليق").slice(0,900),
    "نتيجة فحص قواعد AQX:",String(reason||review?.moderation_reason||"غير متاحة").slice(0,900),
    "تصنيفات قواعد الفحص: "+labels,
    "المرفقات ("+media.length+"):",mediaSummary.slice(0,500),
    "تاريخ الإرسال: "+(review?.created_at||"غير متاح"),
    "لوحة الإدارة: https://admin.alqurmanix.com/p/blog-page_362.html?m=1"
  ].join("\n");
  const sent=await sendReviewTelegram(message);
  const attemptedAt=new Date().toISOString();
  await db.from("aqx_favorites_review_escalations").update({
    telegram_sent_at:sent?attemptedAt:null,
    telegram_attempts:1,
    telegram_last_attempt_at:attemptedAt,
    telegram_next_attempt_at:new Date(Date.now()+(sent?30:5)*60*1000).toISOString(),
    telegram_last_error:sent?null:"initial_telegram_delivery_failed"
  }).eq("id",esc.id);
}

async function processDueReviewTelegramReminders(limit=20) {
  const {data:due,error}=await db.rpc("aqx_favorites_claim_due_review_escalations",{p_limit:limit});
  if(error) throw error;
  const results:any[]=[];
  for(const escalation of due||[]) {
    const details=await getReviewTelegramDetails(escalation.review_id);
    const review=details?.review;
    if(!review || !["pending","hidden"].includes(String(review.status))) {
      await db.from("aqx_favorites_review_escalations").update({
        status:"resolved_review_no_longer_pending",
        resolved_at:new Date().toISOString(),
        telegram_lock_until:null
      }).eq("id",escalation.id).eq("status","open");
      results.push({escalation_id:escalation.id,status:"resolved_not_pending"});
      continue;
    }
    const media=details?.media||[];
    const mediaSummary=media.length?media.map((m:any)=>String(m.media_type||"attachment")+" ("+String(m.mime_type||"unknown")+", "+Math.ceil(Number(m.size_bytes||0)/1024)+" KB)").join("\n"):"لا توجد مرفقات";
    const labels=Array.isArray(review.moderation_labels)&&review.moderation_labels.length?review.moderation_labels.join("، "):"لا توجد تصنيفات";
    const nextAttempt=Number(escalation.telegram_attempts||0)+1;
    const message=[
      "🔔 تذكير متكرر | AQX Favorites",
      "⚠️ ما زالت هذه المراجعة تنتظر قرار المراجع البشري.",
      "رقم التذكير: "+nextAttempt,
      "الأولوية: "+String(escalation.priority||"normal"),
      "معرّف المراجعة: "+String(escalation.review_id),
      "نوع المستخدم: "+(review.owner_type==="guest"?"ضيف":"حساب AQX"),
      "التقييم: "+(review.rating??"غير متاح")+"/5",
      "نص المراجعة:",String(review.comment||"بدون تعليق").slice(0,900),
      "سبب الإحالة:",String(escalation.reason||review.moderation_reason||"غير محدد").slice(0,900),
      "تصنيفات الفحص: "+labels,
      "المرفقات ("+media.length+"):",mediaSummary.slice(0,500),
      "الحالة الحالية: "+String(review.status),
      "لوحة الإدارة: https://admin.alqurmanix.com/p/blog-page_362.html?m=1",
      "سيستمر التذكير كل 30 دقيقة حتى تسجيل القرار البشري."
    ].join("\n");
    const sent=await sendReviewTelegram(message);
    const attemptedAt=new Date().toISOString();
    const update={telegram_attempts:nextAttempt,telegram_last_attempt_at:attemptedAt,
      telegram_next_attempt_at:new Date(Date.now()+(sent?30:5)*60*1000).toISOString(),
      telegram_last_error:sent?null:"telegram_delivery_failed",telegram_lock_until:null};
    const {error:updateError}=await db.from("aqx_favorites_review_escalations")
      .update(update).eq("id",escalation.id).eq("status","open");
    if(updateError) console.error("review reminder state update failed",updateError.message);
    await reviewAudit(escalation.review_id,null,sent?"telegram_review_reminder_sent":"telegram_review_reminder_failed",
      "review",sent?"تم إرسال تذكير المراجعة المتكرر عبر Telegram.":"تعذر إرسال التذكير؛ ستتم إعادة المحاولة قريبًا.",
      ["telegram_reminder",sent?"sent":"failed"],
      {escalation_id:escalation.id,attempt:nextAttempt,engine:"aqx_telegram_reminder_worker"});
    results.push({escalation_id:escalation.id,status:sent?"sent":"retry_scheduled",attempt:nextAttempt});
  }
  return {claimed:(due||[]).length,results};
}

async function notifyReviewHumanDecision(reviewId:string,decision:string,reason:string,admin:any) {
  const details=await getReviewTelegramDetails(reviewId);
  const review=details?.review; const media=details?.media||[];
  const message=[
    "📋 AQX Favorites | قرار المراجعة البشرية",
    "النتيجة: "+(decision==="publish"?"تمت الموافقة والنشر":"تم رفض المراجعة"),
    "معرّف المراجعة: "+reviewId,
    "المدير: "+String(admin?.email||admin?.user_email||"مدير مصرح له"),
    "نوع المستخدم: "+(review?.owner_type==="guest"?"ضيف":"حساب AQX"),
    "التقييم: "+(review?.rating??"غير متاح")+"/5",
    "نص المراجعة:",String(review?.comment||"بدون تعليق").slice(0,900),
    "سبب القرار البشري:",String(reason||"غير محدد").slice(0,700),
    "عدد المرفقات: "+media.length,
    "الحالة النهائية: "+(decision==="publish"?"published":"hidden"),
    "وقت القرار: "+new Date().toISOString(),
    "لوحة الإدارة: https://admin.alqurmanix.com/p/blog-page_362.html?m=1"
  ].join("\n");
  return await sendReviewTelegram(message);
}

async function moderateStoredReviewWithRules(reviewId:string) {
  const {data:review,error:reviewError}=await db.from("aqx_favorites_app_reviews")
    .select("id,owner_type,owner_id,rating,comment,status,moderation_reason,moderation_labels,ai_reviewed_at,likes_count,created_at,updated_at")
    .eq("id",reviewId).maybeSingle();
  if(reviewError||!review) throw new Error("REVIEW_NOT_FOUND");
  const {data:mediaRows,error:mediaError}=await db.from("aqx_favorites_app_review_media")
    .select("id,media_type,storage_path,mime_type,size_bytes,moderation_status")
    .eq("review_id",reviewId);
  if(mediaError) throw mediaError;

  const result=analyzeReviewWithRules(String(review.comment||""),Number(review.rating||0));
  const media=mediaRows||[];
  const hasMedia=media.length>0;
  const decision=hasMedia&&result.decision==="publish"?"review":result.decision;
  const labels=Array.from(new Set([
    ...result.labels,
    "aqx_internal_rules",
    ...(hasMedia?["attachment_requires_human_review"]:[])
  ])).slice(0,12);
  const reason=hasMedia&&decision==="review"
    ?"النص اجتاز/لم يحسمه الفحص القاعدي، لكن الصور والتسجيلات لا يمكن تحليل محتواها بمحرك القواعد؛ المراجعة البشرية مطلوبة."
    :result.reason;
  const status=decision==="publish"?"published":decision==="reject"?"hidden":"pending";
  const now=new Date().toISOString();

  const {data:updated,error:updateError}=await db.from("aqx_favorites_app_reviews")
    .update({status,published_at:status==="published"?now:null,moderation_reason:reason,moderation_labels:labels,ai_reviewed_at:now})
    .eq("id",reviewId)
    .select("id,owner_type,owner_id,rating,comment,status,moderation_reason,moderation_labels,ai_reviewed_at,likes_count,created_at,updated_at").single();
  if(updateError) throw updateError;

  for(const item of media) {
    await db.from("aqx_favorites_app_review_media").update({
      moderation_status:"pending",
      moderation_reason:"يتطلب هذا المرفق مراجعة بشرية؛ لم يتم ادعاء تحليله آليًا.",
      ai_analyzed_at:null
    }).eq("id",item.id).eq("review_id",reviewId);
    await reviewAudit(reviewId,item.id,"attachment_held_for_human_review","review",
      "محرك القواعد لا يستطيع فحص المحتوى المرئي أو الصوتي للمرفق.",["attachment_requires_human_review"],
      {media_type:item.media_type,mime_type:item.mime_type,size_bytes:item.size_bytes,engine:"aqx_internal_rules"});
  }
  const withReply = status === "published" ? await ensureAqxOfficialReply(updated) : updated;
  await reviewAudit(reviewId,null,"review_moderated_by_rules",decision,reason,labels,
    {media_count:media.length,engine:"aqx_internal_rules",negative_opinion_allowed:true});
  if(decision!=="publish") await notifyReviewEscalation(reviewId,reason,decision==="review"?"high":"normal",decision);
  return withReply;
}

async function moderateReviewSubmission(req:Request, saved:any, attachments:any[]) {
  let totalUploadBytes=0;
  for(const item of attachments) {
    const mediaType=String(item.media_type||"");
    const mime=String(item.mime_type||"").toLowerCase().split(";")[0].trim();
    const allowed=mediaType==="image"
      ? ["image/jpeg","image/png","image/webp"].includes(mime)
      : ["audio/webm","audio/ogg","audio/mpeg","audio/mp4","audio/wav"].includes(mime);
    if(!allowed) throw new ApiError("REVIEW_MEDIA_TYPE_NOT_ALLOWED");
    const max=mediaType==="image"?Math.floor(1.5*1024*1024):3*1024*1024;
    if(typeof item.base64!=="string"||item.base64.length>Math.ceil(max*4/3)+16) throw new ApiError("REVIEW_MEDIA_TOO_LARGE");
    const bytes=Uint8Array.from(atob(item.base64.replace(/^data:[^,]+,/,"")),c=>c.charCodeAt(0));
    if(!bytes.length||bytes.length>max) throw new ApiError("REVIEW_MEDIA_TOO_LARGE");
    totalUploadBytes+=bytes.length;
    if(totalUploadBytes>3*1024*1024) throw new ApiError("REVIEW_MEDIA_TOTAL_TOO_LARGE");
    const ext=mime.split("/")[1].replace("jpeg","jpg").replace("mpeg","mp3");
    const path=saved.id+"/"+crypto.randomUUID()+"."+ext;
    const {error:uploadError}=await db.storage.from(REVIEW_MEDIA_BUCKET).upload(path,bytes,{contentType:mime,upsert:false});
    if(uploadError) throw uploadError;
    const {data:media,error:mediaError}=await db.from("aqx_favorites_app_review_media").insert({
      review_id:saved.id,owner_type:saved.owner_type,owner_id:saved.owner_id,
      media_type:mediaType,storage_path:path,mime_type:mime,size_bytes:bytes.length,
      moderation_status:"pending"
    }).select("id,media_type,storage_path,mime_type,size_bytes").single();
    if(mediaError) throw mediaError;
  }
  const finalReview=await moderateStoredReviewWithRules(saved.id);
  if(!finalReview) throw new Error("AQX_REVIEW_RULE_MODERATION_RETURNED_EMPTY");
  return finalReview;
}


function detectArchiveLanguage(text:string):string {
  const arabic=(text.match(/[\u0600-\u06FF]/g)||[]).length;
  const latin=(text.match(/[A-Za-z]/g)||[]).length;
  return arabic>latin?"ar":latin>0?"en":"und";
}
function archiveTokens(text:string):string[] {
  const stop=new Set(("the and for with from that this have has was were are is into about after before over under بين من في على الى إلى عن مع هذا هذه ذلك التي الذي كما حيث كان كانت يكون يتم وقد ثم أو او و في من على الى عن مع هو هي هم نحن انت انتم انا ما لا لم لن قد كل بعض جدا اكثر أقل عند لدى خلال بسبب حول ضد ضمن also using use used not but their they them your you our his her its it as an a of to in by or be can will would should may might we i he she").split(/\s+/));
  return normalizeReviewText(text).split(/[^\p{L}\p{N}]+/u).filter(x=>x.length>=3&&!stop.has(x));
}
function analyzeArchiveLocally(operation:string,archive:any) {
  const text=String(archive.extracted_text||"").slice(0,50000);
  const sentences=text.split(/(?<=[.!?؟؛])\s+|\n+/u).map(x=>x.trim()).filter(x=>x.length>=35);
  const language=detectArchiveLanguage(text);
  const tokens=archiveTokens(text);
  const freq=new Map<string,number>();
  for(const token of tokens) freq.set(token,(freq.get(token)||0)+1);
  const keywords=[...freq.entries()].sort((a,b)=>b[1]-a[1]).slice(0,12).map(x=>x[0]);
  if(operation==="summarize") {
    const selected=sentences.slice(0,Math.min(5,sentences.length)).map(x=>x.slice(0,500));
    return {summary:selected.slice(0,3).join(" "),key_points:selected,language,method:"extractive_rules"};
  }
  if(operation==="classify") {
    const catalog=[
      {category:"technology",terms:["technology","software","computer","digital","تقنية","برمجيات","حاسوب","رقمي","ذكاء اصطناعي"]},
      {category:"education",terms:["education","school","university","student","تعليم","مدرسة","جامعة","طالب","دراسة"]},
      {category:"health",terms:["health","medical","doctor","hospital","medicine","صحة","طبي","طبيب","مستشفى","دواء"]},
      {category:"finance",terms:["finance","bank","investment","market","money","مال","بنك","استثمار","تمويل","اقتصاد"]},
      {category:"travel",terms:["travel","hotel","tourism","flight","سفر","فندق","سياحة","رحلة","طيران"]},
      {category:"food",terms:["food","restaurant","recipe","meal","طعام","مطعم","وصفة","وجبة","طبخ"]},
      {category:"sports",terms:["sport","football","match","player","رياضة","كرة","مباراة","لاعب","بطولة"]},
      {category:"business",terms:["company","business","customer","service","شركة","أعمال","عميل","خدمة","مؤسسة"]},
      {category:"law",terms:["law","legal","court","lawyer","قانون","قضائي","محكمة","محامي","تشريع"]},
      {category:"science",terms:["science","research","study","experiment","علم","بحث","دراسة","تجربة","علمي"]},
      {category:"entertainment",terms:["movie","music","artist","game","فيلم","موسيقى","فنان","لعبة","ترفيه"]}
    ];
    const scored=catalog.map(c=>({category:c.category,score:c.terms.reduce((n,t)=>n+(text.toLowerCase().includes(t.toLowerCase())?1:0),0)}))
      .filter(x=>x.score>0).sort((a,b)=>b.score-a.score);
    return {categories:scored.slice(0,5).map(x=>x.category),topics:keywords.slice(0,10),language,method:"keyword_rules",category_scores:scored.slice(0,5)};
  }
  if(operation==="extract_entities") {
    const entities:any[]=[];
    const add=(name:string,type:string,context:string)=>{const clean=name.trim().slice(0,180);if(clean&& !entities.some(x=>x.name.toLowerCase()===clean.toLowerCase()))entities.push({name:clean,type,context:context.slice(0,240)});};
    for(const m of text.matchAll(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi)) add(m[0],"email",m[0]);
    for(const m of text.matchAll(/https?:\/\/[^\s<>"')]+/gi)) {try{add(new URL(m[0]).hostname,"website",m[0]);}catch{}}
    for(const m of text.matchAll(/#[\p{L}\p{N}_]{2,}/gu)) add(m[0],"hashtag",m[0]);
    for(const m of text.matchAll(/\b(?:19|20)\d{2}\b/g)) add(m[0],"year",m[0]);
    for(const m of text.matchAll(/\b[A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,}){0,2}\b/g)) add(m[0],"named_term",m[0]);
    for(const m of text.matchAll(/(?:شركة|مؤسسة|جامعة|مدينة|دولة|وزارة|منظمة|مستشفى)\s+([\u0600-\u06FF]{2,}(?:\s+[\u0600-\u06FF]{2,}){0,2})/gu)) add(m[1],"named_term",m[0]);
    return {entities:entities.slice(0,100),keywords:keywords.slice(0,15),language,method:"pattern_rules",limitations:"استخراج الكيانات نمطي ومحافظ وقد يفوّت أسماء أو يلتقط أسماء عامة؛ لا يُعد فهمًا دلاليًا."};
  }
  if(operation==="link_knowledge") {
    const proposals:any[]=[];
    const patterns=[
      {re:/([\u0600-\u06FF]{2,}(?:\s+[\u0600-\u06FF]{2,}){0,2})\s+(?:تقع في|يقع في|مقرها في|مقره في|تأسست في|جزء من|تابعة ل|تابع ل)\s+([\u0600-\u06FF]{2,}(?:\s+[\u0600-\u06FF]{2,}){0,2})/gu,predicate:"related_to",relation_type:"explicit_relation"},
      {re:/([A-Z][A-Za-z0-9&.-]*(?:\s+[A-Z][A-Za-z0-9&.-]*){0,2})\s+(?:is located in|is based in|headquartered in|was founded in|is part of|is a subsidiary of)\s+([A-Z][A-Za-z0-9&.-]*(?:\s+[A-Z][A-Za-z0-9&.-]*){0,2})/g,predicate:"related_to",relation_type:"explicit_relation"}
    ];
    for(const p of patterns) for(const m of text.matchAll(p.re)) {
      const evidence=String(m[0]).slice(0,400);
      if(!proposals.some(x=>x.evidence_quote===evidence)) proposals.push({
        subject_label:String(m[1]).trim(),predicate:p.predicate,object_label:String(m[2]).trim(),
        polarity:"positive",relation_type:p.relation_type,
        rationale:"اقتراح علاقة مبني على نمط لغوي صريح؛ يتطلب اعتمادًا لاحقًا.",
        evidence_quote:evidence,confidence:0.62
      });
      if(proposals.length>=20) break;
    }
    return {proposals,topics:keywords.slice(0,10),language,method:"explicit_pattern_rules",auto_approved:false};
  }
  throw new Error("unsupported_internal_analysis_operation");
}

async function detectCountryCode(req: Request): Promise<string | null> {
  const headerCode = (req.headers.get("cf-ipcountry") || req.headers.get("x-vercel-ip-country") || req.headers.get("x-country-code") || "").trim().toUpperCase();
  if (/^[A-Z]{2}$/.test(headerCode) && headerCode !== "XX") return headerCode;

  const rawIp = req.headers.get("cf-connecting-ip") || req.headers.get("x-real-ip") || req.headers.get("x-forwarded-for") || "";
  const ip = rawIp.split(",")[0].trim();
  if (!ip || ip.length > 64 || /^(unknown|::1|127\.)/i.test(ip) || /^(10\.|192\.168\.|169\.254\.)/.test(ip) || /^172\.(1[6-9]|2[0-9]|3[01])\./.test(ip)) return null;

  try {
    const response = await fetch("https://ipwho.is/" + encodeURIComponent(ip) + "?fields=success,country_code", {
      headers: { "Accept": "application/json" },
      signal: AbortSignal.timeout(4500)
    });
    if (response.ok) {
      const result = await response.json();
      const code = String(result?.country_code || "").toUpperCase();
      if (result?.success === true && /^[A-Z]{2}$/.test(code) && code !== "XX") return code;
    }
  } catch (error) {
    console.warn("AQX review country lookup failed", error);
  }
  return null;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors(req) });
  try {
    const path = new URL(req.url).pathname.replace(/\/+$/, "");
    if (req.method === "GET" && path.endsWith("/health")) {
      const { error } = await db.from("aqx_favorites_items").select("id", { head: true, count: "exact" });
      if (error) throw error;
      return out(req, { ok: true, engine: "AQX Favorites", version: "1.0.0", database: "connected" });
    }

    if (req.method === "GET" && path.endsWith("/community")) {
      const o = await owner(req);
      const requestUrl = new URL(req.url);
      const offset = Math.max(0, Math.min(1000000, Number.parseInt(requestUrl.searchParams.get("offset") || "0", 10) || 0));
      const limit = Math.max(1, Math.min(30, Number.parseInt(requestUrl.searchParams.get("limit") || "20", 10) || 20));
      const sort = requestUrl.searchParams.get("sort") === "popular" ? "popular" : "latest";
      const { data: pageData, error: pageError } = await db.rpc("aqx_favorites_community_page", {
        p_offset: offset, p_limit: limit + 1, p_sort: sort
      });
      if (pageError) throw pageError;
      const hasMore = (pageData || []).length > limit;
      const rows = (pageData || []).slice(0, limit);
      const ids = rows.map((r:any) => r.id);
      let mine = new Map<string,string>();
      let reactionCounts = new Map<string,Record<string,number>>();
      if (ids.length) {
        const [{ data: mineRows, error: mineError }, { data: countsRows, error: countsError }] = await Promise.all([
          db.from("aqx_favorites_app_review_likes").select("review_id,reaction_type").in("review_id", ids)
            .eq("owner_type", o.owner_type).eq("owner_id", o.owner_id),
          db.rpc("aqx_favorites_public_review_reaction_stats", { p_review_ids: ids })
        ]);
        if (mineError) throw mineError;
        if (countsError) throw countsError;
        mine = new Map((mineRows || []).map((x:any) => [x.review_id, x.reaction_type || "like"]));
        for (const x of countsRows || []) {
          const counts = reactionCounts.get(x.review_id) || {};
          counts[x.reaction_type] = Number(x.reaction_count || 0);
          reactionCounts.set(x.review_id, counts);
        }
      }
      const { data: statsData, error: statsError } = await db.rpc("aqx_favorites_public_review_stats");
      if (statsError) throw statsError;
      const stats = Array.isArray(statsData) ? statsData[0] : statsData;
      const { data: countryStats, error: countryStatsError } = await db.rpc("aqx_favorites_public_review_country_stats");
      if (countryStatsError) throw countryStatsError;
      const {data:approvedMedia,error:approvedMediaError}=ids.length?await db.from("aqx_favorites_app_review_media")
        .select("id,review_id,media_type,mime_type,storage_path").in("review_id",ids).eq("moderation_status","approved"):{data:[],error:null};
      if(approvedMediaError) throw approvedMediaError;
      const mediaLinks=await Promise.all((approvedMedia||[]).map(async (m:any)=>{
        const {data:signed}=await db.storage.from(REVIEW_MEDIA_BUCKET).createSignedUrl(m.storage_path,180);
        return {id:m.id,review_id:m.review_id,media_type:m.media_type,mime_type:m.mime_type,preview_url:signed?.signedUrl||null};
      }));
      return out(req, {
        ok: true, sort, offset, limit, has_more: hasMore, next_offset: offset + rows.length,
        stats: stats || { total_reviews: 0, average_rating: 0, rating_1: 0, rating_2: 0, rating_3: 0, rating_4: 0, rating_5: 0 },
        countries: countryStats || [],
        reviews: rows.map((r:any) => ({
          id:r.id,rating:r.rating,comment:r.comment,likes_count:r.likes_count,country_code:r.country_code,
          published_at:r.published_at,created_at:r.created_at,updated_at:r.updated_at,
          aqx_reply:r.aqx_reply||null,aqx_reply_at:r.aqx_reply_at||null,reaction_total:Number(r.reaction_total||0),
          can_react: !(r.owner_type === o.owner_type && r.owner_id === o.owner_id),
          my_reaction: mine.get(r.id) || null,reaction_counts: reactionCounts.get(r.id) || {},
          liked: mine.get(r.id) === "like",media:mediaLinks.filter((m:any)=>m.review_id===r.id)
        }))
      });
    }

        if (req.method === "POST" && path.endsWith("/reaction") && path.includes("/reviews/")) {
      const o = await owner(req);
      const reviewId = path.split("/").filter(Boolean).slice(-2)[0];
      if (!/^[0-9a-f-]{36}$/i.test(reviewId)) throw new ApiError("INVALID_REVIEW_ID");
      const body = await req.json().catch(() => ({}));
      const allowed = new Set(["like","love","angry","laugh","sad","dislike"]);
      const requested = String(body.reaction_type || "");
      if (!allowed.has(requested)) throw new ApiError("INVALID_REACTION_TYPE");
      const { data: review, error: reviewError } = await db.from("aqx_favorites_app_reviews")
        .select("id,owner_type,owner_id,status").eq("id", reviewId).eq("status", "published").maybeSingle();
      if (reviewError) throw reviewError;
      if (!review) throw new ApiError("REVIEW_NOT_FOUND", 404);
      if (review.owner_type === o.owner_type && review.owner_id === o.owner_id)
        throw new ApiError("CANNOT_REACT_TO_OWN_REVIEW", 409);
      const { data: existing, error: existingError } = await db.from("aqx_favorites_app_review_likes")
        .select("id,reaction_type").eq("review_id", reviewId).eq("owner_type", o.owner_type).eq("owner_id", o.owner_id).maybeSingle();
      if (existingError) throw existingError;
      let selected: string | null = requested;
      if (existing?.reaction_type === requested) {
        const { error } = await db.from("aqx_favorites_app_review_likes").delete().eq("id", existing.id);
        if (error) throw error;
        selected = null;
      } else if (existing) {
        const { error } = await db.from("aqx_favorites_app_review_likes").update({ reaction_type: requested }).eq("id", existing.id);
        if (error) throw error;
      } else {
        const { error } = await db.from("aqx_favorites_app_review_likes").insert({
          review_id: reviewId,owner_type:o.owner_type,owner_id:o.owner_id,reaction_type:requested
        });
        if (error && error.code !== "23505") throw error;
        if (error?.code === "23505") {
          const { error: retryError } = await db.from("aqx_favorites_app_review_likes")
            .update({ reaction_type: requested }).eq("review_id",reviewId).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id);
          if (retryError) throw retryError;
        }
      }
      const { data: reactionRows, error: reactionError } = await db.from("aqx_favorites_app_review_likes")
        .select("reaction_type").eq("review_id", reviewId);
      if (reactionError) throw reactionError;
      const counts: Record<string,number> = {};
      for (const x of reactionRows || []) counts[x.reaction_type || "like"] = (counts[x.reaction_type || "like"] || 0) + 1;
      const likesCount = counts.like || 0;
      const { error: updateError } = await db.from("aqx_favorites_app_reviews").update({ likes_count: likesCount }).eq("id", reviewId);
      if (updateError) throw updateError;
      return out(req, { ok: true, my_reaction: selected, reaction_counts: counts, likes_count: likesCount });
    }

    if (req.method === "POST" && path.endsWith("/like") && path.includes("/reviews/")) {
      const o = await owner(req);
      const reviewId = path.split("/").filter(Boolean).slice(-2)[0];
      if (!/^[0-9a-f-]{36}$/i.test(reviewId)) throw new ApiError("INVALID_REVIEW_ID");
      const { data: review, error: reviewError } = await db.from("aqx_favorites_app_reviews")
        .select("id,owner_type,owner_id,status").eq("id", reviewId).eq("status", "published").maybeSingle();
      if (reviewError) throw reviewError;
      if (!review) throw new ApiError("REVIEW_NOT_FOUND", 404);
      if (review.owner_type === o.owner_type && review.owner_id === o.owner_id)
        throw new ApiError("CANNOT_LIKE_OWN_REVIEW", 409);
      const { data: existing, error: existingError } = await db.from("aqx_favorites_app_review_likes")
        .select("id").eq("review_id", reviewId).eq("owner_type", o.owner_type).eq("owner_id", o.owner_id).maybeSingle();
      if (existingError) throw existingError;
      let liked = false;
      if (existing) {
        const { error } = await db.from("aqx_favorites_app_review_likes").delete().eq("id", existing.id);
        if (error) throw error;
      } else {
        const { error } = await db.from("aqx_favorites_app_review_likes").insert({ review_id: reviewId, owner_type: o.owner_type, owner_id: o.owner_id, reaction_type:"like" });
        if (error && error.code !== "23505") throw error;
        liked = true;
      }
      const { count, error: countError } = await db.from("aqx_favorites_app_review_likes")
        .select("id", { count:"exact", head:true }).eq("review_id", reviewId).eq("reaction_type","like");
      if (countError) throw countError;
      const likesCount = count || 0;
      const { error: updateError } = await db.from("aqx_favorites_app_reviews").update({ likes_count: likesCount }).eq("id", reviewId);
      if (updateError) throw updateError;
      return out(req, { ok: true, liked, likes_count: likesCount });
    }


    if (req.method === "GET" && path.endsWith("/admin/items")) {
      await requireCentralAdmin(req);
      const u = new URL(req.url);
      const limit = Math.max(1, Math.min(100, Number.parseInt(u.searchParams.get("limit") || "50", 10) || 50));
      const offset = Math.max(0, Math.min(10000000, Number.parseInt(u.searchParams.get("offset") || "0", 10) || 0));
      const ownerType = u.searchParams.get("owner_type");
      const search = (u.searchParams.get("q") || "").trim().slice(0, 120).replace(/[%,()]/g, " ");
      let query = db.from("aqx_favorites_items")
        .select("id,owner_type,owner_id,title,url,item_type,created_at,updated_at,deleted_at,metadata", { count: "exact" })
        .order("created_at", { ascending: false })
        .range(offset, offset + limit - 1);
      if (ownerType === "guest" || ownerType === "account") query = query.eq("owner_type", ownerType);
      if (u.searchParams.get("status") === "active") query = query.is("deleted_at", null);
      if (u.searchParams.get("status") === "archived") query = query.not("deleted_at", "is", null);
      if (search) query = query.or("title.ilike.%"+search+"%,url.ilike.%"+search+"%");
      const { data, error, count } = await query;
      if (error) throw error;
      const [allCount, activeCount, archivedCount, guestCount, accountCount] = await Promise.all([
        db.from("aqx_favorites_items").select("id", { count: "exact", head: true }),
        db.from("aqx_favorites_items").select("id", { count: "exact", head: true }).is("deleted_at", null),
        db.from("aqx_favorites_items").select("id", { count: "exact", head: true }).not("deleted_at", "is", null),
        db.from("aqx_favorites_items").select("id", { count: "exact", head: true }).eq("owner_type", "guest"),
        db.from("aqx_favorites_items").select("id", { count: "exact", head: true }).eq("owner_type", "account")
      ]);
      const countError = allCount.error || activeCount.error || archivedCount.error || guestCount.error || accountCount.error;
      if (countError) throw countError;
      return out(req, {
        ok: true,
        items: (data || []).map((item:any) => ({
          ...item,
          source_domain: (() => { try { return new URL(item.url).hostname; } catch { return null; } })()
        })),
        total_matching: count || 0,
        offset,
        limit,
        totals: {
          all: allCount.count || 0,
          active: activeCount.count || 0,
          archived: archivedCount.count || 0,
          guest: guestCount.count || 0,
          account: accountCount.count || 0
        }
      });
    }

    if (req.method === "GET" && path.endsWith("/admin/reviews")) {
      const admin = await requireCentralAdmin(req);
      // One-time recovery for reviews held by the previous moderation path before
      // the shared AQX AI review worker was wired in.
      const {data:legacyPending,error:legacyPendingError}=await db.from("aqx_favorites_app_reviews")
        .select("id").eq("status","pending").is("ai_reviewed_at",null)
        .order("created_at",{ascending:true}).limit(1);
      if(legacyPendingError) throw legacyPendingError;
      if(legacyPending?.length) {
        await moderateStoredReviewWithRules(legacyPending[0].id);
      }
      const {data,error}=await db.from("aqx_favorites_app_reviews")
        .select("id,rating,comment,status,moderation_reason,moderation_labels,created_at,updated_at")
        .in("status",["pending","hidden"]).order("updated_at",{ascending:false}).limit(200);
      if(error) throw error;
      const ids=(data||[]).map((r:any)=>r.id);
      const {data:media,error:mediaError}=ids.length?await db.from("aqx_favorites_app_review_media")
        .select("id,review_id,media_type,mime_type,size_bytes,moderation_status,moderation_reason,transcript,storage_path,created_at")
        .in("review_id",ids):{data:[],error:null};
      if(mediaError) throw mediaError;
      const mediaWithLinks=await Promise.all((media||[]).map(async (m:any)=>{
        const {data:signed}=await db.storage.from(REVIEW_MEDIA_BUCKET).createSignedUrl(m.storage_path,180);
        return {...m,preview_url:signed?.signedUrl||null,storage_path:undefined};
      }));
      const {data:escalations,error:escError}=ids.length?await db.from("aqx_favorites_review_escalations")
        .select("id,review_id,reason,priority,status,telegram_sent_at,created_at")
        .in("review_id",ids).order("created_at",{ascending:false}):{data:[],error:null};
      if(escError) throw escError;
      return out(req,{ok:true,reviews:data||[],media:mediaWithLinks,escalations:escalations||[]});
    }
    if(req.method==="POST" && path.includes("/admin/reviews/") && path.endsWith("/decision")) {
      const admin = await requireCentralAdmin(req);
      const reviewId=path.split("/").filter(Boolean).slice(-2)[0];
      if(!/^[0-9a-f-]{36}$/i.test(reviewId)) throw new ApiError("INVALID_REVIEW_ID");
      const body=await req.json().catch(()=>({}));
      const decision=String(body.decision||"");
      if(!["publish","reject"].includes(decision)) throw new ApiError("INVALID_ADMIN_DECISION");
      const status=decision==="publish"?"published":"hidden";
      const {data:review,error}=await db.from("aqx_favorites_app_reviews").update({
        status,published_at:status==="published"?new Date().toISOString():null,
        moderation_reason:String(body.reason||"قرار مراجعة بشرية").slice(0,500)
      }).eq("id",reviewId).select("id,status,moderation_reason").single();
      if(error) throw error;
      await db.from("aqx_favorites_app_review_media").update({
        moderation_status:decision==="publish"?"approved":"rejected",
        moderation_reason:review.moderation_reason
      }).eq("review_id",reviewId);
      const telegramNotified=await notifyReviewHumanDecision(reviewId,decision,review.moderation_reason,admin);
      await db.from("aqx_favorites_review_moderation_audit").insert({
        review_id:reviewId,actor_type:"human",action:"human_override",decision,
        reason:review.moderation_reason,metadata:{source:"aqx_central_admin_session",admin_user_id:admin.user_id||admin.user?.id||null,admin_email:admin.email||null,telegram_notified:telegramNotified}
      });
      await db.from("aqx_favorites_review_escalations").update({
        status:"resolved_human",resolved_at:new Date().toISOString()
      }).eq("review_id",reviewId).eq("status","open");
      return out(req,{ok:true,review,telegram_notified:telegramNotified});
    }
    if ((req.method === "GET" || req.method === "POST") && path.endsWith("/reviews")) {
      const o = await owner(req);
      if (req.method === "GET") {
        const { data, error } = await db.from("aqx_favorites_app_reviews")
          .select("id,rating,comment,status,moderation_reason,moderation_labels,ai_reviewed_at,likes_count,created_at,updated_at")
          .eq("owner_type", o.owner_type).eq("owner_id", o.owner_id).maybeSingle();
        if (error) throw error;
        let media:any[]=[];
        if(data){
          const {data:ownedMedia,error:ownedMediaError}=await db.from("aqx_favorites_app_review_media")
            .select("id,media_type,mime_type,size_bytes,moderation_status,moderation_reason,transcript,storage_path")
            .eq("review_id",data.id).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id);
          if(ownedMediaError) throw ownedMediaError;
          media=await Promise.all((ownedMedia||[]).map(async(m:any)=>{
            const {data:signed}=await db.storage.from(REVIEW_MEDIA_BUCKET).createSignedUrl(m.storage_path,180);
            return {...m,preview_url:signed?.signedUrl||null,storage_path:undefined};
          }));
        }
        return out(req, { ok: true, review: data ? {...data,media} : null });
      }
      const body = await req.json().catch(() => ({}));
      const rating = Number(body.rating);
      const comment = typeof body.comment === "string" ? body.comment.trim() : "";
      const attachments=Array.isArray(body.attachments)?body.attachments:[];
      if (!Number.isInteger(rating) || rating < 1 || rating > 5) throw new ApiError("INVALID_APP_RATING");
      if (comment.length > 1200) throw new ApiError("APP_REVIEW_TOO_LONG");
      if(attachments.length>3) throw new ApiError("REVIEW_MEDIA_LIMIT");
      const countryCode = await detectCountryCode(req);
      const { data: saved, error } = await db.from("aqx_favorites_app_reviews").upsert({
        owner_type:o.owner_type,owner_id:o.owner_id,rating,comment,country_code:countryCode,
        status:"pending",published_at:null,moderation_reason:"جارٍ الفحص الآلي للنص والمرفقات",
        moderation_labels:[],ai_reviewed_at:null,updated_at:new Date().toISOString()
      },{onConflict:"owner_type,owner_id"})
        .select("id,owner_type,owner_id,rating,comment,status,moderation_reason,moderation_labels,ai_reviewed_at,likes_count,created_at,updated_at").single();
      if(error) throw error;
      const {data:oldMedia}=await db.from("aqx_favorites_app_review_media")
        .select("id,storage_path").eq("review_id",saved.id)
        .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id);
      if(oldMedia?.length){
        await db.storage.from(REVIEW_MEDIA_BUCKET).remove(oldMedia.map((m:any)=>m.storage_path));
        await db.from("aqx_favorites_app_review_media").delete()
          .eq("review_id",saved.id).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id);
      }
      let finalReview:any;
      try {
        finalReview=await moderateReviewSubmission(req,saved,attachments);
      } catch(moderationError) {
        const reason="تعذر إكمال الفحص الآلي؛ المحتوى محجوز ولن يُنشر. "+String(moderationError).slice(0,260);
        await db.from("aqx_favorites_app_reviews").update({status:"pending",published_at:null,moderation_reason:reason,ai_reviewed_at:null}).eq("id",saved.id);
        await notifyReviewEscalation(saved.id,reason,"critical","pending_error");
        await reviewAudit(saved.id,null,"moderation_failed","pending",reason);
        const {data:held}=await db.from("aqx_favorites_app_reviews")
          .select("id,rating,comment,status,moderation_reason,moderation_labels,ai_reviewed_at,likes_count,created_at,updated_at")
          .eq("id",saved.id).single();
        finalReview=held||{...saved,status:"pending",moderation_reason:reason};
      }
      const {data:finalMedia}=await db.from("aqx_favorites_app_review_media")
        .select("id,media_type,mime_type,size_bytes,moderation_status,moderation_reason,transcript,storage_path")
        .eq("review_id",saved.id).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id);
      const mediaWithLinks=await Promise.all((finalMedia||[]).map(async(m:any)=>{
        const {data:signed}=await db.storage.from(REVIEW_MEDIA_BUCKET).createSignedUrl(m.storage_path,180);
        return {...m,preview_url:signed?.signedUrl||null,storage_path:undefined};
      }));
      await event(o,"app_review_submitted",null,{rating,moderation_status:finalReview.status,media_count:attachments.length});
      return out(req,{ok:true,review:{...finalReview,media:mediaWithLinks},moderation:finalReview.ai_reviewed_at?"completed":"pending"},201);
    }

    if(req.method==="POST" && path.endsWith("/worker/review-reminders")){
      const schedulerToken=req.headers.get("x-aqx-crawler-key")||"";
      const bearer=(req.headers.get("authorization")||"").replace(/^Bearer\s+/i,"");
      let authorized=bearer.length>0 && (bearer===KEY||bearer===(Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")||""));
      if(!authorized && schedulerToken){
        const {data,error}=await db.rpc("aqx_verify_link_crawler_scheduler_token",{p_token:schedulerToken});
        authorized=!error&&data===true;
      }
      if(!authorized) throw new ApiError("WORKER_UNAUTHORIZED",401);
      const body=await req.json().catch(()=>({}));
      const limit=Math.max(1,Math.min(50,Number(body?.limit||20)));
      const result=await processDueReviewTelegramReminders(limit);
      return out(req,{ok:true,worker:"aqx_favorites_review_telegram_reminders",repeat_interval_minutes:30,retry_after_failure_minutes:5,...result});
    }

    if(req.method==="POST" && path.endsWith("/worker/ai/review")){
      const schedulerToken=req.headers.get("x-aqx-crawler-key")||"";
      const bearer=(req.headers.get("authorization")||"").replace(/^Bearer\\s+/i,"");
      let authorized=bearer.length>0 && (bearer===KEY||bearer===(Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")||""));
      if(!authorized && schedulerToken){
        const {data,error}=await db.rpc("aqx_verify_link_crawler_scheduler_token",{p_token:schedulerToken});
        authorized=!error&&data===true;
      }
      if(!authorized) throw new ApiError("WORKER_UNAUTHORIZED",401);
      const body=await req.json().catch(()=>({}));
      const reviewId=typeof body?.review_id==="string"?body.review_id:"";
      if(!/^[0-9a-f-]{36}$/i.test(reviewId)) throw new ApiError("REVIEW_ID_INVALID");
      const review=await moderateStoredReviewWithRules(reviewId);
      return out(req,{ok:true,review,moderation:review?.ai_reviewed_at?"completed":"pending"});
    }

    if(req.method==="POST" && (path.endsWith("/worker/ai")||path.endsWith("/worker/analyze"))){
      const schedulerToken=req.headers.get("x-aqx-crawler-key")||"";
      const bearer=(req.headers.get("authorization")||"").replace(/^Bearer\\s+/i,"");
      let authorized=bearer.length>0 && (bearer===KEY||bearer===(Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")||""));
      if(!authorized && schedulerToken){
        const {data,error}=await db.rpc("aqx_verify_link_crawler_scheduler_token",{p_token:schedulerToken});
        authorized=!error&&data===true;
      }
      if(!authorized) throw new ApiError("WORKER_UNAUTHORIZED",401);
      const limit=Math.max(1,Math.min(5,Number((await req.json().catch(()=>({}))).limit||3)));
      const types=["ai_summarize","ai_classify","ai_extract_entities","ai_link_knowledge"];
      const results:any[]=[];
      for(const jobType of types){
        const remaining=Math.max(0,limit-results.length);
        if(!remaining) break;
        const {data:jobs,error}=await db.rpc("aqx_favorites_claim_processing_jobs",{p_limit:remaining,p_job_type:jobType});
        if(error) throw error;
        for(const job of jobs||[]){
          try{
            const payload=job.input_payload||{};
            const {data:archive,error:archiveError}=await db.from("aqx_favorites_archives")
              .select("id,extracted_text,content_hash,page_title,source_url")
              .eq("id",payload.archive_id).eq("owner_type",job.owner_type).eq("owner_id",job.owner_id)
              .eq("capture_status","ready").is("deleted_at",null).maybeSingle();
            if(archiveError) throw archiveError;
            if(!archive||!archive.extracted_text) throw new Error("ready_archive_content_missing");
            if(payload.content_hash && archive.content_hash!==payload.content_hash) throw new Error("source_content_changed_requeue_required");
            const operation=jobType.replace("ai_","");
            const parsed=analyzeArchiveLocally(operation,archive);
            let proposalIngestion:any=null;
            if(operation==="link_knowledge"){
              const candidates=Array.isArray(parsed?.proposals)?parsed.proposals.slice(0,40):[];
              const normalizedSource=String(archive.extracted_text).normalize("NFKC").replace(/\\s+/g," ").trim().toLowerCase();
              const normalizeValue=(value:any,max=500)=>typeof value==="string"?value.normalize("NFKC").replace(/\\s+/g," ").trim().slice(0,max):"";
              const {data:sourceVersion,error:versionLookupError}=await db.from("aqx_favorites_archive_versions")
                .select("id").eq("archive_id",archive.id).eq("owner_type",job.owner_type)
                .eq("owner_id",job.owner_id).eq("content_hash",archive.content_hash)
                .order("version_number",{ascending:false}).limit(1).maybeSingle();
              if(versionLookupError) throw versionLookupError;
              let created=0,skipped=0;
              for(const candidate of candidates){
                const subjectLabel=normalizeValue(candidate?.subject_label);
                const predicate=normalizeValue(candidate?.predicate,120).toLowerCase().replace(/[^a-z0-9_]+/g,"_").replace(/^_+|_+$/g,"");
                const objectLabel=normalizeValue(candidate?.object_label);
                const relationType=normalizeValue(candidate?.relation_type,80).toLowerCase().replace(/[^a-z0-9_]+/g,"_").replace(/^_+|_+$/g,"");
                const polarity=candidate?.polarity;
                const evidenceQuote=normalizeValue(candidate?.evidence_quote,4000);
                const rationale=normalizeValue(candidate?.rationale,2000);
                const confidence=Number(candidate?.confidence);
                if(!subjectLabel||!predicate||!objectLabel||!relationType||!["positive","negative"].includes(polarity)||
                   !evidenceQuote||!Number.isFinite(confidence)||confidence<0||confidence>1||
                   !normalizedSource.includes(evidenceQuote.replace(/\\s+/g," ").trim().toLowerCase())){
                  skipped++;continue;
                }
                const row={
                  owner_type:job.owner_type,owner_id:job.owner_id,source_item_id:job.item_id,
                  source_archive_id:archive.id,source_archive_version_id:sourceVersion?.id||null,
                  source_content_hash:archive.content_hash,relation_type:relationType,
                  target_label:objectLabel,target_normalized:objectLabel.toLowerCase(),
                  rationale,evidence_quote:evidenceQuote,evidence_span:{},confidence,status:"proposed",
                  subject_label:subjectLabel,subject_normalized:subjectLabel.toLowerCase(),
                  predicate_normalized:predicate,object_normalized:objectLabel.toLowerCase(),polarity,
                  metadata:{ai_generated:false,provider:"aqx_internal_rules",model:null,origin_job_id:job.id,
                    prompt_version:"aqx-internal-rules-v1",source_content_hash:archive.content_hash,auto_approved:false}
                };
                const {data:inserted,error:insertError}=await db.from("aqx_favorites_knowledge_proposals")
                  .upsert(row,{onConflict:"owner_type,owner_id,source_item_id,source_content_hash,relation_type,target_normalized",ignoreDuplicates:true})
                  .select("id").maybeSingle();
                if(insertError) throw insertError;
                if(inserted?.id) created++;else skipped++;
              }
              proposalIngestion={candidates:candidates.length,created,skipped,source_archive_version_id:sourceVersion?.id||null,auto_approved:false};
              await event({owner_type:job.owner_type,owner_id:job.owner_id},"knowledge_proposals_generated",job.item_id,
                {job_id:job.id,...proposalIngestion,engine:"aqx_internal_rules"});
            }
            const {error:updateError}=await db.from("aqx_favorites_processing_jobs").update({
              status:"completed",
              output_payload:{operation,provider:"aqx_internal_rules",model:null,source_content_hash:archive.content_hash,
                rules_version:"aqx-internal-rules-v1",generated_at:new Date().toISOString(),result:parsed,proposal_ingestion:proposalIngestion},
              locked_at:null,locked_by:null,last_error:null,updated_at:new Date().toISOString()
            }).eq("id",job.id).eq("owner_type",job.owner_type).eq("owner_id",job.owner_id);
            if(updateError) throw updateError;
            results.push({job_id:job.id,status:"completed",operation,engine:"aqx_internal_rules",proposal_ingestion:proposalIngestion});
          }catch(error){
            const message=String(error).slice(0,400);
            const retry=job.attempts<job.max_attempts;
            const delay=Math.min(3600,60*Math.pow(2,Math.max(0,job.attempts-1)));
            await db.from("aqx_favorites_processing_jobs").update({
              status:retry?"queued":"failed",run_after:new Date(Date.now()+delay*1000).toISOString(),
              locked_at:null,locked_by:null,last_error:message,updated_at:new Date().toISOString()
            }).eq("id",job.id).eq("owner_type",job.owner_type).eq("owner_id",job.owner_id);
            results.push({job_id:job.id,status:retry?"retrying":"failed",error:message});
          }
        }
      }
      return out(req,{ok:true,processed:results.length,engine:"aqx_internal_rules",results});
    }
    if(req.method==="POST" && path.endsWith("/worker/archive")){
      const schedulerToken=req.headers.get("x-aqx-crawler-key")||"";
      const bearer=(req.headers.get("authorization")||"").replace(/^Bearer\\s+/i,"");
      let authorized=bearer.length>0 && (bearer===KEY||bearer===(Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")||""));
      if(!authorized && schedulerToken){
        const {data,error}=await db.rpc("aqx_verify_link_crawler_scheduler_token",{p_token:schedulerToken});
        authorized=!error&&data===true;
      }
      if(!authorized) throw new ApiError("WORKER_UNAUTHORIZED",401);
      const body=await req.json().catch(()=>({}));
      const limit=Math.max(1,Math.min(5,Number(body.limit||3)));
      const {data:jobs,error}=await db.rpc("aqx_favorites_claim_processing_jobs",{p_limit:limit,p_job_type:"capture_archive"});
      if(error) throw error;
      const results=[];
      for(const job of jobs||[]){
        try{results.push(await processArchiveJob(job));}
        catch(e){results.push({job_id:job.id,status:"worker_error",error:String(e).slice(0,300)});}
      }
      return out(req,{ok:true,claimed:(jobs||[]).length,processed:results.length,results});
    }
    if (path.endsWith("/offline") && (req.method === "GET" || req.method === "POST")) {
      const o = await owner(req);
      await requireFeature(o, "offline_library");
      if (req.method === "POST") {
        const b = await req.json().catch(() => ({}));
        if (typeof b.item_id !== "string") throw new ApiError("ITEM_ID_REQUIRED");
        const item = await ownedItem(o, b.item_id);
        const { data: archive, error: archiveError } = await db.from("aqx_favorites_archives")
          .select("id,content_storage_path,content_hash,page_title,source_url,word_count,captured_at")
          .eq("item_id", item.id).eq("owner_type", o.owner_type).eq("owner_id", o.owner_id)
          .eq("capture_status", "ready").is("deleted_at", null).maybeSingle();
        if (archiveError) throw archiveError;
        if (!archive || !archive.content_storage_path) throw new ApiError("READY_ARCHIVE_REQUIRED", 409);
        const { plan } = await planFor(o);
        const offlineLimit = Number(plan.limits?.offline_items ?? 0);
        const { count: offlineCount, error: countError } = await db.from("aqx_favorites_offline_copies")
          .select("id", { count: "exact", head: true })
          .eq("owner_type", o.owner_type).eq("owner_id", o.owner_id);
        if (countError) throw countError;
        const { data: existingOffline, error: existingError } = await db.from("aqx_favorites_offline_copies")
          .select("id").eq("owner_type", o.owner_type).eq("owner_id", o.owner_id)
          .eq("item_id", item.id).maybeSingle();
        if (existingError) throw existingError;
        if (!existingOffline && offlineLimit >= 0 && (offlineCount || 0) >= offlineLimit)
          throw new ApiError("PLAN_LIMIT_REACHED:offline_items", 402);
        const { data, error } = await db.from("aqx_favorites_offline_copies").upsert({
          owner_type: o.owner_type, owner_id: o.owner_id, item_id: item.id,
          archive_id: archive.id, status: "ready", storage_path: archive.content_storage_path,
          source_content_hash: archive.content_hash, content_hash: archive.content_hash,
          byte_size: 0, built_at: new Date().toISOString(), expires_at: null,
          last_error: null, updated_at: new Date().toISOString()
        }, { onConflict: "owner_type,owner_id,item_id" }).select("*").single();
        if (error) throw error;
        const signed = await db.storage.from(ARCHIVE_BUCKET).createSignedUrl(archive.content_storage_path, 900);
        if (signed.error) throw signed.error;
        await event(o, "offline_copy_added", item.id, { offline_copy_id: data.id });
        return out(req, { ok: true, offline_copy: data, download_url: signed.data?.signedUrl || null, expires_in_seconds: 900 }, 201);
      }
      const { data, error } = await db.from("aqx_favorites_offline_copies")
        .select("id,item_id,archive_id,status,storage_path,content_hash,source_content_hash,built_at,expires_at,updated_at")
        .eq("owner_type", o.owner_type).eq("owner_id", o.owner_id)
        .order("updated_at", { ascending: false }).limit(500);
      if (error) throw error;
      const copies = await Promise.all((data || []).map(async (entry:any) => {
        if (entry.status !== "ready" || !entry.storage_path) return { ...entry, download_url: null };
        const signed = await db.storage.from(ARCHIVE_BUCKET).createSignedUrl(entry.storage_path, 900);
        return { ...entry, download_url: signed.error ? null : signed.data?.signedUrl || null };
      }));
      return out(req, { ok: true, offline_copies: copies, count: copies.length, delivery: "signed_archive_downloads" });
    }
    if (req.method === "POST" && path.endsWith("/guest/session")) {
      const ip = req.headers.get("cf-connecting-ip") || (req.headers.get("x-forwarded-for") || "unknown").split(",")[0].trim();
      const key = await hash((Deno.env.get("AQX_FAVORITES_RATE_SALT") || "aqxf-v1") + "|" + ip);
      const limited = await db.rpc("aqx_favorites_consume_rate_limit", { p_key_hash_hex: key, p_limit: 10, p_window_seconds: 3600 });
      if (limited.error) throw limited.error;
      if (limited.data !== true) throw new ApiError("GUEST_RATE_LIMITED", 429);
      const guestId = crypto.randomUUID(), raw = token();
      const { error } = await db.from("aqx_favorites_guest_sessions").insert({
        guest_id: guestId, token_hash_hex: await hash(raw),
        user_agent: (req.headers.get("user-agent") || "").slice(0, 300),
        expires_at: new Date(Date.now() + 180 * 86400000).toISOString()
      });
      if (error) throw error;
      const o = { owner_type: "guest", owner_id: guestId };
      await event(o, "guest_session_created");
      return out(req, { ok: true, guest_id: guestId, guest_token: raw, expires_in_days: 180 }, 201);
    }
    if (req.method === "POST" && path.endsWith("/guest/recovery-key")) {
      const current = await guest(req);
      const body = await req.json().catch(() => ({}));
      const recoveryKey = typeof body.recovery_key === "string" ? body.recovery_key.trim() : "";
      const sessionToken = typeof body.session_token === "string" ? body.session_token : "";
      if (recoveryKey.length < 8 || recoveryKey.length > 32) {
        throw new ApiError("RECOVERY_KEY_LENGTH_INVALID", 400);
      }
      if (sessionToken.length < 40 || sessionToken.length > 64) {
        throw new ApiError("GUEST_SESSION_TOKEN_INVALID", 400);
      }
      const recoveryHash = await hmacHash(recoveryKey);
      const sessionHash = await hash(sessionToken);
      const { data: existingRecovery, error: recoveryError } = await db
        .from("aqx_favorites_guest_sessions").select("guest_id")
        .eq("recovery_key_hash_hex", recoveryHash).maybeSingle();
      if (recoveryError) throw recoveryError;
      if (existingRecovery && existingRecovery.guest_id !== current.owner_id) {
        throw new ApiError("RECOVERY_KEY_ALREADY_IN_USE", 409);
      }
      const { data: existingSession, error: sessionError } = await db
        .from("aqx_favorites_guest_sessions").select("guest_id")
        .eq("token_hash_hex", sessionHash).maybeSingle();
      if (sessionError) throw sessionError;
      if (existingSession && existingSession.guest_id !== current.owner_id) {
        throw new ApiError("GUEST_SESSION_TOKEN_ALREADY_IN_USE", 409);
      }
      const { error: updateError } = await db.from("aqx_favorites_guest_sessions")
        .update({ token_hash_hex: sessionHash, recovery_key_hash_hex: recoveryHash, last_activity_at: new Date().toISOString() })
        .eq("guest_id", current.owner_id).eq("status", "active");
      if (updateError?.code === "23505") throw new ApiError("RECOVERY_KEY_ALREADY_IN_USE", 409);
      if (updateError) throw updateError;
      await event(current, "guest_recovery_key_set");
      return out(req, { ok: true, recovery_key_saved: true, storage: "hmac_sha256" });
    }
    if (req.method === "POST" && path.endsWith("/guest/library-sync")) {
      const source = await guest(req);
      await enforceLibrarySyncRateLimit(req, source.owner_id);
      const body = await req.json().catch(() => ({}));
      const targetKey = typeof body.target_recovery_key === "string" ? body.target_recovery_key.trim() : "";
      if (targetKey.length < 8 || targetKey.length > 32 || !/^[A-Za-z0-9_-]+$/.test(targetKey)) {
        throw new ApiError("LIBRARY_SYNC_KEY_INVALID", 400);
      }
      const targetHash = await hmacHash(targetKey);
      const { data: target, error: targetError } = await db.from("aqx_favorites_guest_sessions")
        .select("guest_id,status,expires_at")
        .eq("recovery_key_hash_hex", targetHash).maybeSingle();
      if (targetError) throw targetError;
      if (!target || target.status !== "active" || new Date(target.expires_at).getTime() <= Date.now()) {
        throw new ApiError("LIBRARY_SYNC_TARGET_NOT_FOUND", 404);
      }
      if (target.guest_id === source.owner_id) {
        throw new ApiError("LIBRARY_SYNC_SAME_LIBRARY", 409);
      }
      const newSessionToken = token();
      const { data: merged, error: mergeError } = await db.rpc("aqx_favorites_merge_guest_to_guest", {
        p_source_guest_id: source.owner_id,
        p_target_guest_id: target.guest_id,
        p_target_recovery_hash: targetHash,
        p_new_target_token_hash: await hash(newSessionToken)
      });
      if (mergeError) {
        const message = String(mergeError.message || "");
        if (message.includes("library_sync_target_invalid")) throw new ApiError("LIBRARY_SYNC_TARGET_NOT_FOUND", 404);
        if (message.includes("library_sync_source_invalid")) throw new ApiError("LIBRARY_SYNC_SOURCE_INVALID", 409);
        if (message.includes("library_sync")) throw new ApiError("LIBRARY_SYNC_FAILED:" + message, 409);
        throw mergeError;
      }
      return out(req, {
        ok:true, merged:true, guest_id:target.guest_id,
        guest_token:newSessionToken, summary:merged
      });
    }
    if (req.method === "POST" && path.endsWith("/guest/device/trust")) {
      const current = await guest(req);
      const body = await req.json().catch(() => ({}));
      const deviceLabel = typeof body.device_label === "string" && body.device_label.trim()
        ? body.device_label.trim().slice(0, 120) : "جهاز جديد";
      const { count, error: countError } = await db.from("aqx_favorites_guest_devices")
        .select("id", {count:"exact",head:true})
        .eq("guest_id", current.owner_id).is("revoked_at", null);
      if (countError) throw countError;
      if ((count || 0) >= 20) throw new ApiError("GUEST_DEVICE_LIMIT_REACHED", 409);
      const deviceToken = token();
      const { data, error } = await db.from("aqx_favorites_guest_devices").insert({
        guest_id: current.owner_id,
        device_token_hash_hex: await hash(deviceToken),
        device_label: deviceLabel
      }).select("id,device_label,created_at,last_seen_at,trusted_at").single();
      if (error) throw error;
      await event(current, "guest_device_trusted", null, {device_id:data.id,device_label:data.device_label});
      return out(req, {ok:true,device_token:deviceToken,device:data}, 201);
    }
    if (req.method === "GET" && path.endsWith("/guest/devices")) {
      const current = await guest(req);
      const { data, error } = await db.from("aqx_favorites_guest_devices")
        .select("id,device_label,created_at,last_seen_at,trusted_at,revoked_at")
        .eq("guest_id", current.owner_id).order("last_seen_at",{ascending:false});
      if (error) throw error;
      return out(req, {ok:true,devices:data||[]});
    }
    const revokeDeviceMarker = "/guest/devices/";
    const revokeDeviceIndex = path.lastIndexOf(revokeDeviceMarker);
    const revokeDeviceId = revokeDeviceIndex >= 0 ? path.slice(revokeDeviceIndex + revokeDeviceMarker.length) : "";
    if (req.method === "DELETE" && /^[0-9a-f-]{36}$/i.test(revokeDeviceId)) {
      const current = await guest(req);
      const { data, error } = await db.from("aqx_favorites_guest_devices")
        .update({revoked_at:new Date().toISOString()})
        .eq("id",revokeDeviceId).eq("guest_id",current.owner_id)
        .is("revoked_at",null).select("id").maybeSingle();
      if (error) throw error;
      if (!data) throw new ApiError("GUEST_DEVICE_NOT_FOUND",404);
      await event(current, "guest_device_revoked", null, {device_id:data.id});
      return out(req, {ok:true,revoked:true});
    }
    if (req.method === "GET" && path.endsWith("/plans")) {
      const { data, error } = await db.from("aqx_favorites_plans").select("id,code,name,description,limits,features,sort_order")
        .eq("is_active",true).eq("is_public",true).order("sort_order");
      if (error) throw error;
      const ids = (data || []).map((x:any)=>x.id);
      const {data:prices,error:priceError}=await db.from("aqx_favorites_plan_prices")
        .select("plan_id,currency,country_code,billing_interval,amount_minor,is_active,valid_from,valid_until")
        .in("plan_id",ids).eq("is_active",true);
      if (priceError) throw priceError;
      const plans=(data||[]).map((p:any)=>({...p,prices:(prices||[]).filter((x:any)=>x.plan_id===p.id)}));
      return out(req,{ok:true,plans});
    }
    if (req.method === "GET" && path.endsWith("/subscription")) {
      const o = await owner(req), state = await planFor(o);
      return out(req,{ok:true,plan:state.plan,subscription:state.subscription,owner_type:o.owner_type});
    }
    if (req.method === "POST" && path.endsWith("/subscription/cancel")) {
      const o = await owner(req);
      if (o.owner_type !== "account") throw new ApiError("ACCOUNT_REQUIRED",403);
      const {data,error}=await db.from("aqx_favorites_subscriptions").update({
        cancel_at_period_end:true,updated_at:new Date().toISOString()
      }).eq("account_id",o.owner_id).in("status",["active","trialing"])
        .or("current_period_end.is.null,current_period_end.gt."+new Date().toISOString())
        .select("id,status,current_period_end,cancel_at_period_end").order("created_at",{ascending:false}).limit(1).maybeSingle();
      if (error) throw error;
      if (!data) throw new ApiError("ACTIVE_SUBSCRIPTION_NOT_FOUND",404);
      await event(o,"subscription_cancel_scheduled",null,{subscription_id:data.id});
      return out(req,{ok:true,subscription:data,message:"Subscription will remain active until the current period ends."});
    }
    if (req.method === "POST" && path.endsWith("/subscription/resume")) {
      const o = await owner(req);
      if (o.owner_type !== "account") throw new ApiError("ACCOUNT_REQUIRED",403);
      const {data,error}=await db.from("aqx_favorites_subscriptions").update({
        cancel_at_period_end:false,updated_at:new Date().toISOString()
      }).eq("account_id",o.owner_id).eq("cancel_at_period_end",true).in("status",["active","trialing"])
        .or("current_period_end.is.null,current_period_end.gt."+new Date().toISOString())
        .select("id,status,current_period_end,cancel_at_period_end").order("created_at",{ascending:false}).limit(1).maybeSingle();
      if (error) throw error;
      if (!data) throw new ApiError("CANCELLATION_NOT_FOUND",404);
      await event(o,"subscription_resumed",null,{subscription_id:data.id});
      return out(req,{ok:true,subscription:data});
    }
    if (req.method === "GET" && path.endsWith("/usage")) {
      const o = await owner(req), {plan,subscription}=await planFor(o);
      const specs=[["items","aqx_favorites_items"],["collections","aqx_favorites_collections"],["categories","aqx_favorites_categories"]];
      const usage:any={};
      for (const [metric,table] of specs) {
        const {count,error}=await db.from(table).select("id",{count:"exact",head:true})
          .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).is("deleted_at",null);
        if(error) throw error;
        const limit=Number(plan.limits?.[metric]??0);
        usage[metric]={used:count||0,limit,remaining:Math.max(0,limit-(count||0)),unlimited:limit<0};
      }
      return out(req,{ok:true,plan:{code:plan.code,name:plan.name},subscription,usage});
    }
    if (req.method === "GET" && path.endsWith("/saved-searches")) {
      const o = await owner(req); await requireFeature(o,"saved_searches");
      const {data,error}=await db.from("aqx_favorites_saved_searches").select("*")
        .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).is("deleted_at",null)
        .order("is_pinned",{ascending:false}).order("updated_at",{ascending:false}).limit(100);
      if(error) throw error;
      return out(req,{ok:true,saved_searches:data||[]});
    }
    if (req.method === "POST" && path.endsWith("/saved-searches")) {
      const o=await owner(req); await requireFeature(o,"saved_searches");
      const b=await req.json().catch(()=>({}));
      const name=typeof b.name==="string"?b.name.trim().slice(0,100):"";
      if(!name) throw new ApiError("SAVED_SEARCH_NAME_REQUIRED");
      await assertCapacity(o,"saved_searches","aqx_favorites_saved_searches");
      const {data,error}=await db.from("aqx_favorites_saved_searches").insert({
        ...o,name,query_text:typeof b.query_text==="string"?b.query_text.trim().slice(0,300):"",
        filters:b.filters&&typeof b.filters==="object"&&!Array.isArray(b.filters)?b.filters:{},
        is_pinned:b.is_pinned===true
      }).select("*").single();
      if(error?.code==="23505") throw new ApiError("SAVED_SEARCH_ALREADY_EXISTS",409);
      if(error) throw error;
      await event(o,"saved_search_created",null,{saved_search_id:data.id});
      return out(req,{ok:true,saved_search:data},201);
    }
    if (req.method === "GET" && path.endsWith("/reminders")) {
      const o=await owner(req); await requireFeature(o,"reminders");
      const u=new URL(req.url); let q=db.from("aqx_favorites_reminders").select("*")
        .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).is("deleted_at",null)
        .order("remind_at",{ascending:true}).limit(200);
      if(u.searchParams.get("status")) q=q.eq("status",u.searchParams.get("status"));
      if(u.searchParams.get("item_id")) q=q.eq("item_id",u.searchParams.get("item_id"));
      const {data,error}=await q;if(error) throw error;
      return out(req,{ok:true,reminders:data||[]});
    }
    if (req.method === "POST" && path.endsWith("/reminders")) {
      const o=await owner(req); await requireFeature(o,"reminders");
      const b=await req.json().catch(()=>({}));
      const remindAt=typeof b.remind_at==="string"&&!Number.isNaN(Date.parse(b.remind_at))?new Date(b.remind_at).toISOString():null;
      if(!remindAt) throw new ApiError("VALID_REMIND_AT_REQUIRED");
      let item:any=null;
      if(typeof b.item_id==="string") item=await ownedItem(o,b.item_id);
      const title=typeof b.title==="string"&&b.title.trim()?b.title.trim().slice(0,180):(item?.title||"تذكير");
      const recurrence=["none","daily","weekly","monthly"].includes(b.recurrence)?b.recurrence:"none";
      const channel=["in_app","email","all"].includes(b.delivery_channel)?b.delivery_channel:"in_app";
      await assertCapacity(o,"reminders","aqx_favorites_reminders");
      const {data,error}=await db.from("aqx_favorites_reminders").insert({
        ...o,item_id:item?.id||null,title,note:typeof b.note==="string"?b.note.trim().slice(0,1000):"",
        remind_at:remindAt,recurrence,delivery_channel:channel,
        metadata:b.metadata&&typeof b.metadata==="object"&&!Array.isArray(b.metadata)?b.metadata:{}
      }).select("*").single();
      if(error) throw error;
      await event(o,"reminder_created",item?.id||null,{reminder_id:data.id});
      return out(req,{ok:true,reminder:data},201);
    }
    if (req.method === "GET" && path.endsWith("/reading-progress")) {
      const o=await owner(req);
      const {data,error}=await db.from("aqx_favorites_reading_progress").select("*")
        .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).order("last_read_at",{ascending:false}).limit(200);
      if(error) throw error;
      return out(req,{ok:true,progress:data||[]});
    }
    if (req.method === "GET" && path.endsWith("/duplicates")) {
      const o=await owner(req);
      const {data,error}=await db.rpc("aqx_favorites_find_duplicates",{p_owner_type:o.owner_type,p_owner_id:o.owner_id});
      if(error) throw error;
      return out(req,{ok:true,groups:data||[],duplicate_groups:(data||[]).length,duplicate_items:(data||[]).reduce((n:any,x:any)=>n+Number(x.duplicate_count||0),0)});
    }
    if (req.method === "GET" && path.endsWith("/tags")) {
      const o=await owner(req);
      const {data,error}=await db.from("aqx_favorites_items").select("tags")
        .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).is("deleted_at",null).limit(5000);
      if(error) throw error;
      const counts=new Map<string,number>();
      for(const row of data||[]) for(const tag of row.tags||[]) counts.set(tag,(counts.get(tag)||0)+1);
      const tags=[...counts.entries()].map(([tag,count])=>({tag,count})).sort((a,b)=>b.count-a.count||a.tag.localeCompare(b.tag));
      return out(req,{ok:true,tags});
    }
    if (req.method === "GET" && path.endsWith("/analytics")) {
      const o=await owner(req);
      const [items,opened,completed,reminders,saved] = await Promise.all([
        db.from("aqx_favorites_items").select("id",{count:"exact",head:true}).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).is("deleted_at",null),
        db.from("aqx_favorites_items").select("id",{count:"exact",head:true}).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).not("last_opened_at","is",null).is("deleted_at",null),
        db.from("aqx_favorites_reading_progress").select("id",{count:"exact",head:true}).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).eq("completed",true),
        db.from("aqx_favorites_reminders").select("id",{count:"exact",head:true}).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).is("deleted_at",null),
        db.from("aqx_favorites_saved_searches").select("id",{count:"exact",head:true}).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).is("deleted_at",null)
      ]);
      for(const r of [items,opened,completed,reminders,saved]) if(r.error) throw r.error;
      return out(req,{ok:true,analytics:{active_items:items.count||0,opened_items:opened.count||0,completed_reading:completed.count||0,active_reminders:reminders.count||0,saved_searches:saved.count||0}});
    }
    if (req.method === "POST" && path.endsWith("/merge")) {
      const accountOwner = await account(req);
      const mergeResult = await mergeGuestForAccount(req, accountOwner);
      return out(req, mergeResult || { success: true, already_merged: false, no_guest_token: true });
    }
    if (req.method === "GET" && path.endsWith("/categories")) {
      const o = await owner(req);
      let { data,error } = await db.from("aqx_favorites_categories").select("*")
        .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).is("deleted_at",null).order("sort_order").order("name");
      if (error) throw error;
      if (!data?.length) {
        const defaults = [
          {name:"مقالات",slug:"articles",description:"المقالات والمحتوى المقروء",icon:"book-open",color:"blue",sort_order:10},
          {name:"عمل",slug:"work",description:"موارد وروابط العمل",icon:"briefcase",color:"purple",sort_order:20},
          {name:"تعلم",slug:"learning",description:"الدورات والمراجع التعليمية",icon:"graduation-cap",color:"green",sort_order:30},
          {name:"تسوق",slug:"shopping",description:"المنتجات والخدمات المراد الرجوع إليها",icon:"shopping-bag",color:"orange",sort_order:40},
          {name:"أماكن",slug:"places",description:"الأماكن والمواقع",icon:"map-pin",color:"rose",sort_order:50}
        ].map(x=>({...o,...x,is_system:true}));
        const seeded = await db.from("aqx_favorites_categories").insert(defaults).select("*");
        if (seeded.error && seeded.error.code !== "23505") throw seeded.error;
        const refreshed = await db.from("aqx_favorites_categories").select("*")
          .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).is("deleted_at",null).order("sort_order").order("name");
        if (refreshed.error) throw refreshed.error;
        data = refreshed.data || [];
      }
      return out(req,{ok:true,categories:data || []});
    }
    if (req.method === "POST" && path.endsWith("/categories")) {
      const o = await owner(req), b = await req.json().catch(()=>({}));
      const name = typeof b.name === "string" ? b.name.trim().slice(0,100) : "";
      const slug = typeof b.slug === "string" ? b.slug.trim().toLowerCase().replace(/[^a-z0-9-]/g,"-").replace(/-+/g,"-").slice(0,120) : name.toLowerCase().replace(/[^a-z0-9-]/g,"-").replace(/-+/g,"-").slice(0,120);
      if (!name || !slug) throw new ApiError("CATEGORY_NAME_REQUIRED");
      await assertCapacity(o,"categories","aqx_favorites_categories");
      const parent_id = await categoryById(o,typeof b.parent_id === "string" ? b.parent_id : null);
      const {data,error} = await db.from("aqx_favorites_categories").insert({...o,parent_id,name,slug,
        description:typeof b.description==="string"?b.description.trim().slice(0,500):"",
        icon:typeof b.icon==="string"?b.icon.slice(0,64):null,color:typeof b.color==="string"?b.color.slice(0,24):null,
        sort_order:Number.isInteger(b.sort_order)?b.sort_order:0}).select("*").single();
      if (error?.code==="23505") throw new ApiError("CATEGORY_ALREADY_EXISTS",409);
      if (error) throw error;
      await event(o,"category_created",null,{category_id:data.id,name});
      return out(req,{ok:true,category:data},201);
    }
    if (req.method === "GET" && path.endsWith("/items")) {
      const o = await owner(req), u = new URL(req.url);
      const includeDeleted = u.searchParams.get("include_deleted") === "true";
      const limit = Math.min(100, Math.max(1, Number(u.searchParams.get("limit") || 50)));
      const offset = Math.max(0, Number(u.searchParams.get("offset") || 0));
      let q = db.from("aqx_favorites_items").select("*").eq("owner_type", o.owner_type).eq("owner_id", o.owner_id);
      if (u.searchParams.get("sort") === "recent") q = q.order("created_at", { ascending: false });
      else q = q.order("is_pinned", { ascending: false }).order("created_at", { ascending: false });
      q = q.range(offset, offset + limit - 1);
      if (!includeDeleted) q = q.is("deleted_at", null);
      if (u.searchParams.get("collection_id")) q = q.eq("collection_id", u.searchParams.get("collection_id"));
      if (u.searchParams.get("category_id")) q = q.eq("category_id", u.searchParams.get("category_id"));
      if (u.searchParams.get("item_type")) q = q.eq("item_type", u.searchParams.get("item_type"));
      const searchTerm=(u.searchParams.get("q")||"").trim().slice(0,120).replace(/[^\\p{L}\\p{N}\\s-]/gu,"");
      if(searchTerm) q=q.or("title.ilike.%"+searchTerm+"%,note.ilike.%"+searchTerm+"%");
      const tag=(u.searchParams.get("tag")||"").trim().slice(0,40);
      if(tag) q=q.contains("tags",[tag]);
      if(u.searchParams.get("pinned")==="true") q=q.eq("is_pinned",true);
      if(u.searchParams.get("pinned")==="false") q=q.eq("is_pinned",false);
      const sort=u.searchParams.get("sort");
      if(sort==="oldest") q=q.order("created_at",{ascending:true});
      else if(sort==="opened") q=q.order("last_opened_at",{ascending:false,nullsFirst:false});
      else if(sort==="title") q=q.order("title",{ascending:true});
      const { data, error } = await q;
      if (error) throw error;
      return out(req, { ok: true, items: data || [], limit, offset });
    }
    if (req.method === "GET" && path.endsWith("/stats")) {
      const o = await owner(req);
      const [active, trash, collections, categories] = await Promise.all([
        db.from("aqx_favorites_items").select("id", { count: "exact", head: true }).eq("owner_type", o.owner_type).eq("owner_id", o.owner_id).is("deleted_at", null),
        db.from("aqx_favorites_items").select("id", { count: "exact", head: true }).eq("owner_type", o.owner_type).eq("owner_id", o.owner_id).not("deleted_at", "is", null),
        db.from("aqx_favorites_collections").select("id", { count: "exact", head: true }).eq("owner_type", o.owner_type).eq("owner_id", o.owner_id).is("deleted_at", null),
        db.from("aqx_favorites_categories").select("id", { count: "exact", head: true }).eq("owner_type", o.owner_type).eq("owner_id", o.owner_id).is("deleted_at", null)
      ]);
      if (active.error || trash.error || collections.error || categories.error) throw active.error || trash.error || collections.error || categories.error;
      return out(req, { ok: true, active: active.count || 0, trash: trash.count || 0, collections: collections.count || 0, categories: categories.count || 0 });
    }
    if (req.method === "POST" && path.endsWith("/items/import")) {
      const o = await owner(req), b = await req.json().catch(() => ({}));
      if (!Array.isArray(b.items) || b.items.length > 5000) throw new ApiError("INVALID_IMPORT_BATCH");
      const { plan } = await planFor(o);
      const batchLimit = Number(plan.limits?.max_import_batch ?? 0);
      if (b.items.length > batchLimit) throw new ApiError("PLAN_IMPORT_BATCH_LIMIT", 402);
      await assertCapacity(o,"items","aqx_favorites_items",b.items.length);
      let imported = 0, skipped = 0;
      for (const row of b.items) {
        try {
          const u = urlValue(row.url);
          const title = typeof row.title === "string" && row.title.trim() ? row.title.trim().slice(0,180) : new URL(u.url).hostname;
          const cid = await collectionId(o, typeof row.collection_name === "string" ? row.collection_name.trim().slice(0,80) : "");
          const { error } = await db.from("aqx_favorites_items").insert({
            ...o, ...u, title, collection_id: cid,
            item_type: ["link","article","product","service","video","image","document","place","other"].includes(row.item_type) ? row.item_type : "link",
            note: typeof row.note === "string" ? row.note.trim().slice(0,1000) : "",
            tags: Array.isArray(row.tags) ? row.tags.filter((x: any) => typeof x === "string").map((x: string) => x.trim().slice(0,40)).filter(Boolean).slice(0,20) : [],
            is_pinned: row.is_pinned === true
          });
          if (error?.code === "23505") skipped++;
          else if (error) throw error;
          else imported++;
        } catch (e) {
          if (e instanceof ApiError) skipped++;
          else throw e;
        }
      }
      await event(o, "imported", null, { imported, skipped });
      return out(req, { ok: true, imported, skipped });
    }
    if (req.method === "POST" && path.endsWith("/items")) {
      const o = await owner(req), b = await req.json().catch(() => ({})), u = urlValue(b.url);
      await assertCapacity(o,"items","aqx_favorites_items");
      const category_id = await categoryById(o,typeof b.category_id === "string" ? b.category_id : null);
      const title = typeof b.title === "string" && b.title.trim() ? b.title.trim().slice(0, 180) : new URL(u.url).hostname;
      const allowed = ["link","article","product","service","video","image","document","place","other"];
      const itemType = allowed.includes(b.item_type) ? b.item_type : "link";
      const cid = await collectionId(o, typeof b.collection_name === "string" ? b.collection_name.trim().slice(0,80) : "");
      const { data, error } = await db.from("aqx_favorites_items").insert({
        ...o, ...u, title, item_type: itemType, collection_id: cid, category_id,
        note: typeof b.note === "string" ? b.note.trim().slice(0,1000) : "",
        tags: Array.isArray(b.tags) ? [...new Set(b.tags.filter((x: any) => typeof x === "string").map((x: string) => x.trim().slice(0,40)).filter(Boolean))].slice(0,20) : [],
        is_pinned: b.is_pinned === true
      }).select("*").single();
      if (error?.code === "23505") throw new ApiError("FAVORITE_ALREADY_EXISTS", 409);
      if (error) throw error;
      await event(o, "item_created", data.id);
      return out(req, { ok: true, item: data }, 201);
    }
    if (req.method === "GET" && path.endsWith("/collections")) {
      const o = await owner(req);
      const { data, error } = await db.from("aqx_favorites_collections").select("*")
        .eq("owner_type", o.owner_type).eq("owner_id", o.owner_id).is("deleted_at", null)
        .order("sort_order").order("name");
      if (error) throw error;
      return out(req, { ok: true, collections: data || [] });
    }
    if (req.method === "POST" && path.endsWith("/collections")) {
      const o = await owner(req), b = await req.json().catch(() => ({}));
      await assertCapacity(o,"collections","aqx_favorites_collections");
      const name = typeof b.name === "string" ? b.name.trim().slice(0,80) : "";
      if (!name) throw new ApiError("COLLECTION_NAME_REQUIRED");
      const { data, error } = await db.from("aqx_favorites_collections").insert({
        ...o, name, description: typeof b.description === "string" ? b.description.trim().slice(0,500) : "",
        color: typeof b.color === "string" ? b.color.trim().slice(0,24) : "purple",
        sort_order: Number.isInteger(b.sort_order) ? b.sort_order : 0
      }).select("*").single();
      if (error?.code === "23505") throw new ApiError("COLLECTION_ALREADY_EXISTS", 409);
      if (error) throw error;
      await event(o, "collection_created", null, { collection_id: data.id, name });
      return out(req, { ok: true, collection: data }, 201);
    }


    if(req.method==="GET" && path.endsWith("/search/content")){
      const o=await owner(req);
      await requireFeature(o,"full_text_search");
      const u=new URL(req.url), q=(u.searchParams.get("q")||"").trim().slice(0,300);
      if(!q) throw new ApiError("SEARCH_QUERY_REQUIRED");
      const limit=Math.min(100,Math.max(1,Number(u.searchParams.get("limit")||30)));
      const {data,error}=await db.rpc("aqx_favorites_search_archived_content",{
        p_owner_type:o.owner_type,p_owner_id:o.owner_id,p_query:q,p_limit:limit
      });
      if(error) throw error;
      return out(req,{ok:true,query:q,results:data||[]});
    }
    const annotationParts=path.split("/").filter(Boolean);
    const annotationPos=annotationParts.lastIndexOf("annotations");
    const annotationId=annotationPos>=0?annotationParts[annotationPos+1]:"";
    if(annotationId && /^[0-9a-f-]{36}$/i.test(annotationId) && (req.method==="PATCH"||req.method==="DELETE")){
      const o=await owner(req);
      await requireFeature(o,"annotations");
      if(req.method==="DELETE"){
        const {data,error}=await db.from("aqx_favorites_annotations").delete()
          .eq("id",annotationId).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).select("id").maybeSingle();
        if(error) throw error;
        if(!data) throw new ApiError("ANNOTATION_NOT_FOUND",404);
        return out(req,{ok:true,deleted:true});
      }
      const b=await req.json().catch(()=>({})),patch:any={updated_at:new Date().toISOString()};
      if("selected_text" in b) patch.selected_text=String(b.selected_text).slice(0,8000);
      if("note_text" in b) patch.note_text=String(b.note_text).slice(0,4000);
      if("color" in b) patch.color=String(b.color).slice(0,24);
      if("anchor" in b && b.anchor && typeof b.anchor==="object" && !Array.isArray(b.anchor)) patch.anchor=b.anchor;
      const {data,error}=await db.from("aqx_favorites_annotations").update(patch)
        .eq("id",annotationId).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).select("*").maybeSingle();
      if(error) throw error;
      if(!data) throw new ApiError("ANNOTATION_NOT_FOUND",404);
      return out(req,{ok:true,annotation:data});
    }

    const claimParts=path.split("/").filter(Boolean);
    const claimPos=claimParts.lastIndexOf("claims");
    const claimId=claimPos>=0?claimParts[claimPos+1]:"";
    const claimSourceId=claimPos>=0?claimParts[claimPos+3]:"";
    if(path.endsWith("/claims") && (req.method==="GET"||req.method==="POST")){
      const o=await owner(req);
      await requireFeature(o,"evidence_ledger");
      if(req.method==="GET"){
        const u=new URL(req.url),status=u.searchParams.get("status");
        let q=db.from("aqx_favorites_evidence_claims").select("*").eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).is("deleted_at",null).order("updated_at",{ascending:false}).limit(300);
        if(status && ["unverified","supported","contested","refuted","outdated"].includes(status)) q=q.eq("verification_status",status);
        const {data,error}=await q;
        if(error) throw error;
        return out(req,{ok:true,claims:data||[]});
      }
      const b=await req.json().catch(()=>({}));
      const title=typeof b.title==="string"?b.title.trim().slice(0,180):"";
      const claimText=typeof b.claim_text==="string"?b.claim_text.trim().slice(0,4000):"";
      if(!title||!claimText) throw new ApiError("CLAIM_TITLE_AND_TEXT_REQUIRED");
      await assertCapacity(o,"evidence_claims","aqx_favorites_evidence_claims");
      const {data,error}=await db.from("aqx_favorites_evidence_claims").insert({
        owner_type:o.owner_type,owner_id:o.owner_id,title,claim_text,
        notes:typeof b.notes==="string"?b.notes.slice(0,4000):""
      }).select("*").single();
      if(error) throw error;
      return out(req,{ok:true,claim:data},201);
    }
    if(claimId && /^[0-9a-f-]{36}$/i.test(claimId) && claimParts[claimPos+2]==="sources" &&
       (req.method==="GET"||req.method==="POST")){
      const o=await owner(req);
      await requireFeature(o,"evidence_ledger");
      const claim=await db.from("aqx_favorites_evidence_claims").select("id")
        .eq("id",claimId).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).is("deleted_at",null).maybeSingle();
      if(claim.error) throw claim.error;
      if(!claim.data) throw new ApiError("CLAIM_NOT_FOUND",404);
      if(req.method==="GET"){
        const {data,error}=await db.from("aqx_favorites_claim_sources").select("*")
          .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).eq("claim_id",claimId).order("created_at",{ascending:false});
        if(error) throw error;
        return out(req,{ok:true,sources:data||[]});
      }
      const b=await req.json().catch(()=>({}));
      const itemId=typeof b.item_id==="string"?b.item_id:"";
      if(!/^[0-9a-f-]{36}$/i.test(itemId)) throw new ApiError("SOURCE_ITEM_REQUIRED");
      const item=await ownedItem(o,itemId);
      const stance=["supports","contradicts","context"].includes(b.stance)?b.stance:"context";
      let annotationId=null,excerpt=typeof b.source_excerpt==="string"?b.source_excerpt.slice(0,8000):"";
      if(typeof b.annotation_id==="string" && /^[0-9a-f-]{36}$/i.test(b.annotation_id)){
        const a=await db.from("aqx_favorites_annotations").select("id,item_id,selected_text")
          .eq("id",b.annotation_id).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).maybeSingle();
        if(a.error) throw a.error;
        if(!a.data || a.data.item_id!==itemId) throw new ApiError("ANNOTATION_NOT_FOUND",404);
        annotationId=a.data.id;
        if(!excerpt) excerpt=a.data.selected_text||"";
      }
      const {data,error}=await db.from("aqx_favorites_claim_sources").upsert({
        owner_type:o.owner_type,owner_id:o.owner_id,claim_id:claimId,item_id:itemId,annotation_id:annotationId,
        stance,source_excerpt:excerpt,source_url:item.url,
        source_content_hash:typeof b.source_content_hash==="string"?b.source_content_hash.slice(0,128):null,
        source_captured_at:b.source_captured_at && !Number.isNaN(Date.parse(b.source_captured_at))?new Date(b.source_captured_at).toISOString():null,
        notes:typeof b.notes==="string"?b.notes.slice(0,2000):""
      },{onConflict:"owner_type,owner_id,claim_id,item_id,stance"}).select("*").single();
      if(error) throw error;
      return out(req,{ok:true,source:data},201);
    }
    if(claimId && /^[0-9a-f-]{36}$/i.test(claimId) && req.method==="PATCH" && claimParts[claimPos+2]===undefined){
      const o=await owner(req);
      await requireFeature(o,"evidence_ledger");
      const b=await req.json().catch(()=>({})),patch:any={updated_at:new Date().toISOString()};
      if("title" in b){const v=String(b.title).trim().slice(0,180);if(!v) throw new ApiError("CLAIM_TITLE_REQUIRED");patch.title=v;}
      if("claim_text" in b){const v=String(b.claim_text).trim().slice(0,4000);if(!v) throw new ApiError("CLAIM_TEXT_REQUIRED");patch.claim_text=v;}
      if("verification_status" in b){
        if(!["unverified","supported","contested","refuted","outdated"].includes(b.verification_status)) throw new ApiError("INVALID_CLAIM_STATUS");
        patch.verification_status=b.verification_status;
        patch.verified_at=b.verification_status==="unverified"?null:new Date().toISOString();
      }
      if("confidence" in b){const v=Number(b.confidence);if(!Number.isFinite(v)||v<0||v>1) throw new ApiError("INVALID_CONFIDENCE");patch.confidence=v;}
      if("notes" in b) patch.notes=String(b.notes).slice(0,4000);
      const {data,error}=await db.from("aqx_favorites_evidence_claims").update(patch)
        .eq("id",claimId).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).is("deleted_at",null).select("*").maybeSingle();
      if(error) throw error;
      if(!data) throw new ApiError("CLAIM_NOT_FOUND",404);
      return out(req,{ok:true,claim:data});
    }
    if(claimId && /^[0-9a-f-]{36}$/i.test(claimId) && claimSourceId && /^[0-9a-f-]{36}$/i.test(claimSourceId) && req.method==="DELETE"){
      const o=await owner(req);
      await requireFeature(o,"evidence_ledger");
      const {data,error}=await db.from("aqx_favorites_claim_sources").delete()
        .eq("id",claimSourceId).eq("claim_id",claimId).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).select("id").maybeSingle();
      if(error) throw error;
      if(!data) throw new ApiError("CLAIM_SOURCE_NOT_FOUND",404);
      return out(req,{ok:true,deleted:true});
    }

    const parts = path.split("/").filter(Boolean);


    const graphSearchPos = parts.lastIndexOf("knowledge-graph-search");
    if (graphSearchPos >= 0 && req.method === "GET") {
      const o = await owner(req);
      const url = new URL(req.url);
      const queryText = (url.searchParams.get("q") || "").trim().replace(/[\\%_]/g, " ").slice(0, 160);
      const rawLimit = Number(url.searchParams.get("limit") || 50);
      const limit = Number.isFinite(rawLimit) ? Math.max(1, Math.min(200, Math.floor(rawLimit))) : 50;
      if (!queryText) throw new ApiError("SEARCH_QUERY_REQUIRED");

      const nodeQuery = () => db.from("aqx_favorites_knowledge_nodes").select("*")
        .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id);
      const [exact,prefix,contains] = await Promise.all([
        nodeQuery().ilike("label",queryText).limit(limit),
        nodeQuery().ilike("label",queryText+"%").limit(limit),
        nodeQuery().ilike("label","%"+queryText+"%").limit(limit)
      ]);
      if(exact.error) throw exact.error;
      if(prefix.error) throw prefix.error;
      if(contains.error) throw contains.error;
      const matched = new Map<string,any>();
      for(const n of (contains.data||[])) matched.set(n.id,{...n,match_level:"contains"});
      for(const n of (prefix.data||[])) matched.set(n.id,{...n,match_level:"prefix"});
      for(const n of (exact.data||[])) matched.set(n.id,{...n,match_level:"exact"});
      const matchedNodes=[...matched.values()].slice(0,limit);

      const canonicalIds=[...new Set(matchedNodes.map((n:any)=>n.merged_into_node_id).filter(Boolean))];
      let canonicalNodes:any[]=[];
      if(canonicalIds.length){
        const {data,error}=await db.from("aqx_favorites_knowledge_nodes").select("*")
          .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).in("id",canonicalIds);
        if(error) throw error;
        canonicalNodes=data||[];
      }
      const resolvedIds=[...new Set([...matchedNodes.map((n:any)=>n.id),...canonicalNodes.map((n:any)=>n.id)])];
      let aliasNodes:any[]=[];
      if(resolvedIds.length){
        const {data,error}=await db.from("aqx_favorites_knowledge_nodes").select("*")
          .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).in("merged_into_node_id",resolvedIds).limit(limit);
        if(error) throw error;
        aliasNodes=data||[];
      }
      const allNodes=new Map<string,any>();
      for(const n of [...matchedNodes,...canonicalNodes,...aliasNodes]) allNodes.set(n.id,n);
      const nodeIds=[...allNodes.keys()];
      let edges:any[]=[];
      if(nodeIds.length){
        const {data,error}=await db.from("aqx_favorites_knowledge_edges")
          .select("*,target_node:aqx_favorites_knowledge_nodes(*)")
          .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id)
          .is("deleted_at",null).eq("lifecycle_status","active").in("target_node_id",nodeIds)
          .order("created_at",{ascending:false}).limit(limit);
        if(error) throw error;
        edges=data||[];
      }
      const sourceIds=[...new Set(edges.map((e:any)=>e.source_item_id).filter(Boolean))];
      const freshness=new Map<string,string>();
      if(sourceIds.length){
        const {data,error}=await db.from("aqx_favorites_archives").select("item_id,content_hash")
          .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).in("item_id",sourceIds).is("deleted_at",null);
        if(error) throw error;
        for(const a of (data||[])) freshness.set(a.item_id,a.content_hash||"");
      }
      edges=edges.map((edge:any)=>({...edge,
        source_freshness:!edge.source_content_hash?"unverifiable"
          :!freshness.has(edge.source_item_id)?"archive_unavailable"
          :freshness.get(edge.source_item_id)===edge.source_content_hash?"current":"source_changed"
      }));
      return out(req,{
        ok:true,query:queryText,
        nodes:[...allNodes.values()],matched_nodes:matchedNodes,
        canonical_nodes:canonicalNodes,alias_nodes:aliasNodes,
        edges,node_count:allNodes.size,edge_count:edges.length,limit,
        retrieval_levels:["exact","prefix","contains","canonical_entity","merged_aliases"]
      });
    }

    const graphPos = parts.lastIndexOf("knowledge-graph");
    if (graphPos >= 0 && req.method === "GET") {
      const o = await owner(req);
      const url = new URL(req.url);
      const rawLimit = Number(url.searchParams.get("limit") || 200);
      const limit = Number.isFinite(rawLimit) ? Math.max(1, Math.min(500, Math.floor(rawLimit))) : 200;
      const sourceItemId = url.searchParams.get("source_item_id");
      if (sourceItemId && !/^[0-9a-f-]{36}$/i.test(sourceItemId)) throw new ApiError("INVALID_SOURCE_ITEM_ID");

      let edgeQuery = db.from("aqx_favorites_knowledge_edges")
        .select("*,target_node:aqx_favorites_knowledge_nodes(*)")
        .eq("owner_type", o.owner_type).eq("owner_id", o.owner_id)
        .is("deleted_at", null).eq("lifecycle_status","active").order("created_at", { ascending: false }).limit(limit);
      if (sourceItemId) edgeQuery = edgeQuery.eq("source_item_id", sourceItemId);

      const { data: edges, error: edgeError } = await edgeQuery;
      if (edgeError) throw edgeError;

      const graphSourceIds = [...new Set((edges || []).map((edge: any) => edge.source_item_id).filter(Boolean))];
      let graphFreshness = new Map<string, string>();
      if (graphSourceIds.length) {
        const { data: currentArchives, error: freshnessError } = await db.from("aqx_favorites_archives")
          .select("item_id,content_hash,capture_status")
          .eq("owner_type", o.owner_type).eq("owner_id", o.owner_id)
          .in("item_id", graphSourceIds).is("deleted_at", null);
        if (freshnessError) throw freshnessError;
        for (const archive of (currentArchives || [])) {
          graphFreshness.set(archive.item_id, archive.content_hash || "");
        }
      }
      const enrichedEdges = (edges || []).map((edge: any) => ({
        ...edge,
        source_freshness: !edge.source_content_hash ? "unverifiable"
          : !graphFreshness.has(edge.source_item_id) ? "archive_unavailable"
          : graphFreshness.get(edge.source_item_id) === edge.source_content_hash ? "current" : "source_changed"
      }));

      let nodeQuery = db.from("aqx_favorites_knowledge_nodes")
        .select("*").eq("owner_type", o.owner_type).eq("owner_id", o.owner_id)
        .order("updated_at", { ascending: false }).limit(limit);
      const { data: nodes, error: nodeError } = await nodeQuery;
      if (nodeError) throw nodeError;

      return out(req, {
        ok: true, nodes: nodes || [], edges: enrichedEdges,
        node_count: (nodes || []).length, edge_count: enrichedEdges.length,
        limit, source_item_id: sourceItemId || null
      });
    }

    const edgePos = parts.lastIndexOf("knowledge-edges");
    if (edgePos >= 0) {
      const o = await owner(req);
      const edgeId = parts[edgePos + 1] || "";
      const action = parts[edgePos + 2] || "";
      if (edgeId && /^[0-9a-f-]{36}$/i.test(edgeId) && action === "history" && req.method === "GET") {
        const {data:base,error:baseError}=await db.from("aqx_favorites_knowledge_edges")
          .select("id,source_item_id,owner_type,owner_id")
          .eq("id",edgeId).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).maybeSingle();
        if(baseError) throw baseError;
        if(!base) throw new ApiError("KNOWLEDGE_EDGE_NOT_FOUND",404);
        const {data:rows,error}=await db.from("aqx_favorites_knowledge_edges").select("*")
          .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).eq("source_item_id",base.source_item_id)
          .order("valid_from",{ascending:true}).limit(500);
        if(error) throw error;
        const byId=new Map((rows||[]).map((x:any)=>[x.id,x]));
        const chain=new Set<string>([edgeId]);
        let changed=true;
        while(changed){
          changed=false;
          for(const x of (rows||[])){
            if(chain.has(x.id) && x.superseded_by_edge_id && !chain.has(x.superseded_by_edge_id)){
              chain.add(x.superseded_by_edge_id); changed=true;
            }
            if(x.superseded_by_edge_id && chain.has(x.superseded_by_edge_id) && !chain.has(x.id)){
              chain.add(x.id); changed=true;
            }
          }
        }
        const history=[...chain].map(id=>byId.get(id)).filter(Boolean);
        return out(req,{ok:true,edge_id:edgeId,history,history_count:history.length});
      }
      if (edgeId && /^[0-9a-f-]{36}$/i.test(edgeId) && !action && req.method === "PATCH") {
        const b=await req.json().catch(()=>({}));
        const status=String(b.status||"");
        if(!["superseded","retracted"].includes(status)) throw new ApiError("INVALID_EDGE_TRANSITION");
        const replacementId=status==="superseded" ? String(b.replacement_edge_id||"") : null;
        if(status==="superseded" && !/^[0-9a-f-]{36}$/i.test(replacementId||"")) throw new ApiError("REPLACEMENT_EDGE_REQUIRED");
        const {data,error}=await db.rpc("aqx_favorites_transition_knowledge_edge",{
          p_owner_type:o.owner_type,p_owner_id:o.owner_id,p_edge_id:edgeId,
          p_lifecycle_status:status,p_replacement_edge_id:replacementId
        });
        if(error){
          const message=String(error.message||"");
          if(message.includes("NOT_FOUND")) throw new ApiError("KNOWLEDGE_EDGE_NOT_FOUND",404);
          if(message.includes("ALREADY")||message.includes("MISMATCH")||message.includes("REQUIRED")||message.includes("NOT_ACTIVE"))
            throw new ApiError(message.slice(0,120),409);
          throw error;
        }
        await event(o,"knowledge_edge_"+status,null,{edge_id:edgeId,replacement_edge_id:replacementId});
        return out(req,{ok:true,transition:data});
      }
    }

    const mergePos = parts.lastIndexOf("entity-merge-candidates");
    if (mergePos >= 0) {
      const o = await owner(req);
      const candidateId = parts[mergePos + 1] || "";

      if (!candidateId && req.method === "GET") {
        const url = new URL(req.url);
        const status = url.searchParams.get("status");
        if (status && !["proposed","accepted","rejected","superseded"].includes(status)) throw new ApiError("INVALID_MERGE_STATUS");
        let query = db.from("aqx_favorites_entity_merge_candidates").select("*")
          .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id)
          .order("created_at",{ascending:false}).limit(100);
        if (status) query = query.eq("status",status);
        const {data,error} = await query;
        if (error) throw error;
        return out(req,{ok:true,candidates:data||[],limit:100});
      }

      if (!candidateId && req.method === "POST") {
        const b = await req.json().catch(()=>({}));
        const sourceId = String(b.source_node_id||"");
        const targetId = String(b.target_node_id||"");
        if (!/^[0-9a-f-]{36}$/i.test(sourceId) || !/^[0-9a-f-]{36}$/i.test(targetId) || sourceId===targetId)
          throw new ApiError("VALID_DISTINCT_NODES_REQUIRED");
        const rationale = typeof b.rationale==="string" ? b.rationale.trim().slice(0,4000) : "";
        if (!rationale) throw new ApiError("MERGE_RATIONALE_REQUIRED");
        const confidence = b.confidence==null ? null : Number(b.confidence);
        if (confidence!==null && (!Number.isFinite(confidence)||confidence<0||confidence>1)) throw new ApiError("INVALID_CONFIDENCE");
        const evidence = b.evidence && typeof b.evidence==="object" && !Array.isArray(b.evidence) ? b.evidence : {};
        const idempotencyKey = typeof b.idempotency_key==="string" && b.idempotency_key.trim()
          ? b.idempotency_key.trim().slice(0,200)
          : "merge:"+sourceId+":"+targetId;
        const {data:prior,error:priorError}=await db.from("aqx_favorites_entity_merge_candidates").select("*")
          .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).eq("idempotency_key",idempotencyKey).maybeSingle();
        if(priorError) throw priorError;
        if(prior) return out(req,{ok:true,candidate:prior,already_requested:true});
        const {data:nodes,error:nodesError} = await db.from("aqx_favorites_knowledge_nodes")
          .select("id,merged_into_node_id")
          .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).in("id",[sourceId,targetId]);
        if (nodesError) throw nodesError;
        const sourceNode=(nodes||[]).find((n:any)=>n.id===sourceId);
        const targetNode=(nodes||[]).find((n:any)=>n.id===targetId);
        if (!sourceNode || !targetNode) throw new ApiError("MERGE_NODE_NOT_FOUND",404);
        if (sourceNode.merged_into_node_id) throw new ApiError("SOURCE_NODE_ALREADY_MERGED",409);
        if (targetNode.merged_into_node_id) throw new ApiError("TARGET_NODE_NOT_CANONICAL",409);
        const {data,error} = await db.from("aqx_favorites_entity_merge_candidates").insert({
          owner_type:o.owner_type,owner_id:o.owner_id,source_node_id:sourceId,target_node_id:targetId,
          rationale,confidence,evidence,idempotency_key:idempotencyKey
        }).select("*").single();
        if (error?.code==="23505") {
          const {data:existing,error:existingError}=await db.from("aqx_favorites_entity_merge_candidates").select("*")
            .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).eq("idempotency_key",idempotencyKey).single();
          if(existingError) throw existingError;
          return out(req,{ok:true,candidate:existing,already_requested:true});
        }
        if (error) throw error;
        await event(o,"knowledge_entity_merge_proposed",null,{candidate_id:data.id,source_node_id:sourceId,target_node_id:targetId});
        return out(req,{ok:true,candidate:data},201);
      }

      if (candidateId && /^[0-9a-f-]{36}$/i.test(candidateId) && req.method==="PATCH") {
        const b=await req.json().catch(()=>({}));
        const decision=String(b.decision||"");
        if (!["accepted","rejected"].includes(decision)) throw new ApiError("INVALID_MERGE_DECISION");
        const note=typeof b.decision_note==="string"?b.decision_note.trim().slice(0,2000):null;
        const {data:current,error:currentError}=await db.from("aqx_favorites_entity_merge_candidates")
          .select("id,status,source_node_id,target_node_id")
          .eq("id",candidateId).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).maybeSingle();
        if (currentError) throw currentError;
        if (!current) throw new ApiError("MERGE_CANDIDATE_NOT_FOUND",404);
        if (current.status!=="proposed") throw new ApiError("MERGE_CANDIDATE_ALREADY_DECIDED",409);
        if (decision==="accepted") {
          const {data:result,error}=await db.rpc("aqx_favorites_accept_entity_merge",{
            p_owner_type:o.owner_type,p_owner_id:o.owner_id,p_candidate_id:candidateId,
            p_decision_by:o.owner_type==="account"?o.owner_id:null,p_decision_note:note
          });
          if (error) {
            const message=String(error.message||"");
            if (message.includes("ALREADY_MERGED")||message.includes("NOT_CANONICAL")||message.includes("CYCLE"))
              throw new ApiError(message.slice(0,120),409);
            if (message.includes("ALREADY_DECIDED")) throw new ApiError("MERGE_CANDIDATE_ALREADY_DECIDED",409);
            throw error;
          }
          await event(o,"knowledge_entity_merge_accepted",null,{candidate_id:candidateId,result,decision_note:note});
          return out(req,{ok:true,result});
        }
        const decidedAt=new Date().toISOString();
        const {data,error}=await db.from("aqx_favorites_entity_merge_candidates").update({
          status:"rejected",decision_by:o.owner_type==="account"?o.owner_id:null,
          decided_at:decidedAt,decision_note:note,updated_at:decidedAt
        }).eq("id",candidateId).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id)
          .eq("status","proposed").select("*").maybeSingle();
        if (error) throw error;
        if (!data) throw new ApiError("MERGE_CANDIDATE_ALREADY_DECIDED",409);
        await event(o,"knowledge_entity_merge_rejected",null,{candidate_id:candidateId,decision_note:note});
        return out(req,{ok:true,candidate:data});
      }
    }

    const graphConflictsPos = parts.lastIndexOf("knowledge-graph-conflicts");
    if (graphConflictsPos >= 0 && req.method==="GET") {
      const o=await owner(req);
      const url=new URL(req.url);
      const rawLimit=Number(url.searchParams.get("limit")||100);
      const limit=Number.isFinite(rawLimit)?Math.max(1,Math.min(500,Math.floor(rawLimit))):100;
      const {data,error}=await db.rpc("aqx_favorites_find_graph_edge_conflicts",{
        p_owner_type:o.owner_type,p_owner_id:o.owner_id,p_limit:limit
      });
      if(error) throw error;
      return out(req,{ok:true,conflicts:data||[],conflict_count:(data||[]).length,limit});
    }

    const knowledgePos = parts.lastIndexOf("knowledge-proposals");
    if (knowledgePos >= 0) {
      const o = await owner(req);
      const proposalId = parts[knowledgePos + 1] || "";
      const subAction = parts[knowledgePos + 2] || "";

      if (!proposalId && req.method === "GET") {
        const url = new URL(req.url);
        const status = url.searchParams.get("status");
        const allowedStatuses = ["proposed", "accepted", "rejected", "superseded"];
        if (status && !allowedStatuses.includes(status)) throw new ApiError("INVALID_PROPOSAL_STATUS");
        let query = db.from("aqx_favorites_knowledge_proposals").select("*")
          .eq("owner_type", o.owner_type).eq("owner_id", o.owner_id)
          .order("created_at", { ascending: false }).limit(100);
        if (status) query = query.eq("status", status);
        const sourceItemId = url.searchParams.get("source_item_id");
        if (sourceItemId && /^[0-9a-f-]{36}$/i.test(sourceItemId)) query = query.eq("source_item_id", sourceItemId);
        const { data, error } = await query;
        if (error) throw error;
        return out(req, { ok: true, proposals: data || [], limit: 100 });
      }

      if (proposalId && /^[0-9a-f-]{36}$/i.test(proposalId) && subAction === "conflicts" && req.method === "GET") {
        const { data: proposal, error: proposalError } = await db.from("aqx_favorites_knowledge_proposals")
          .select("id,status,subject_normalized,predicate_normalized,object_normalized,polarity")
          .eq("id", proposalId).eq("owner_type", o.owner_type).eq("owner_id", o.owner_id).maybeSingle();
        if (proposalError) throw proposalError;
        if (!proposal) throw new ApiError("KNOWLEDGE_PROPOSAL_NOT_FOUND", 404);
        const { data: conflicts, error } = await db.rpc("aqx_favorites_find_knowledge_conflicts", {
          p_owner_type: o.owner_type, p_owner_id: o.owner_id, p_proposal_id: proposalId
        });
        if (error) throw error;
        return out(req, { ok: true, proposal_id: proposalId, conflicts: conflicts || [], conflict_count: (conflicts || []).length });
      }

      if (proposalId && /^[0-9a-f-]{36}$/i.test(proposalId) && !subAction && req.method === "PATCH") {
        const body = await req.json().catch(() => ({}));
        const decision = String(body.decision || "");
        if (!["accepted", "rejected", "superseded"].includes(decision)) throw new ApiError("INVALID_PROPOSAL_DECISION");
        const note = typeof body.decision_note === "string" ? body.decision_note.trim().slice(0, 2000) : null;

        const { data: current, error: currentError } = await db.from("aqx_favorites_knowledge_proposals")
          .select("id,status,source_item_id,subject_normalized,predicate_normalized,object_normalized,polarity")
          .eq("id", proposalId).eq("owner_type", o.owner_type).eq("owner_id", o.owner_id).maybeSingle();
        if (currentError) throw currentError;
        if (!current) throw new ApiError("KNOWLEDGE_PROPOSAL_NOT_FOUND", 404);
        if (current.status !== "proposed") throw new ApiError("PROPOSAL_ALREADY_DECIDED", 409);

        let supersededBy: string | null = null;
        if (decision === "superseded") {
          supersededBy = typeof body.superseded_by === "string" ? body.superseded_by : "";
          if (!/^[0-9a-f-]{36}$/i.test(supersededBy) || supersededBy === proposalId) throw new ApiError("VALID_SUPERSEDING_PROPOSAL_REQUIRED");
          const { data: replacement, error: replacementError } = await db.from("aqx_favorites_knowledge_proposals")
            .select("id,status").eq("id", supersededBy).eq("owner_type", o.owner_type).eq("owner_id", o.owner_id).maybeSingle();
          if (replacementError) throw replacementError;
          if (!replacement || !["proposed", "accepted"].includes(replacement.status)) throw new ApiError("SUPERSEDING_PROPOSAL_NOT_FOUND", 404);
        }

        let conflicts: any[] = [];
        if (decision === "accepted") {
          const { data, error } = await db.rpc("aqx_favorites_find_knowledge_conflicts", {
            p_owner_type: o.owner_type, p_owner_id: o.owner_id, p_proposal_id: proposalId
          });
          if (error) throw error;
          conflicts = data || [];
          if (conflicts.length && body.confirm_conflicts !== true) {
            return out(req, { ok: false, error: "KNOWLEDGE_CONFLICTS_REQUIRE_EXPLICIT_CONFIRMATION", conflicts }, 409);
          }
        }


        if (decision === "accepted") {
          const { data: graphResult, error: graphError } = await db.rpc("aqx_favorites_accept_knowledge_proposal", {
            p_owner_type: o.owner_type,
            p_owner_id: o.owner_id,
            p_proposal_id: proposalId,
            p_decision_by: o.owner_type === "account" ? o.owner_id : null,
            p_decision_note: note
          });
          if (graphError) {
            const message = String(graphError.message || "");
            if (message.includes("STRUCTURED_CLAIM_REQUIRED")) throw new ApiError("STRUCTURED_CLAIM_REQUIRED", 409);
            if (message.includes("SOURCE_ITEM_NOT_OWNED_OR_ACTIVE")) throw new ApiError("SOURCE_ITEM_NOT_OWNED_OR_ACTIVE", 409);
            if (message.includes("PROPOSAL_ALREADY_DECIDED")) throw new ApiError("PROPOSAL_ALREADY_DECIDED", 409);
            throw graphError;
          }
          await event(o, "knowledge_proposal_accepted", current.source_item_id, {
            proposal_id: proposalId, graph: graphResult, conflict_count: conflicts.length,
            decision_note: note
          });
          return out(req, {
            ok: true, proposal_id: proposalId, status: "accepted",
            graph: graphResult, conflicts,
            conflict_confirmation_recorded: conflicts.length > 0 && body.confirm_conflicts === true
          });
        }

        const decidedAt = new Date().toISOString();
        const patch: any = {
          status: decision,
          decision_by: o.owner_type === "account" ? o.owner_id : null,
          decided_at: decidedAt,
          decision_note: note,
          superseded_by: decision === "superseded" ? supersededBy : null,
          updated_at: decidedAt
        };
        const { data: updated, error: updateError } = await db.from("aqx_favorites_knowledge_proposals")
          .update(patch).eq("id", proposalId).eq("owner_type", o.owner_type).eq("owner_id", o.owner_id)
          .eq("status", "proposed").select("*").maybeSingle();
        if (updateError) throw updateError;
        if (!updated) throw new ApiError("PROPOSAL_ALREADY_DECIDED", 409);
        await event(o, "knowledge_proposal_" + decision, current.source_item_id, {
          proposal_id: proposalId, superseded_by: supersededBy, conflict_count: conflicts.length,
          decision_note: note
        });
        return out(req, { ok: true, proposal: updated, conflicts, conflict_confirmation_recorded: conflicts.length > 0 && body.confirm_conflicts === true });
      }
    }
    const itemPos = parts.lastIndexOf("items");
    const itemId = itemPos >= 0 ? parts[itemPos + 1] : "";
    const itemAction = itemPos >= 0 ? (parts[itemPos + 2] || "") : "";
    if (itemId && /^[0-9a-f-]{36}$/i.test(itemId)) {
      const o = await owner(req), id = itemId, action = itemAction;

      if ((req.method==="GET"||req.method==="POST") && action==="ai") {
        await ownedItem(o,id);
        await requireFeature(o,"ai_assistant");
        const aiTypes=["ai_summarize","ai_classify","ai_extract_entities","ai_link_knowledge"];
        if(req.method==="GET"){
          const {data,error}=await db.from("aqx_favorites_processing_jobs")
            .select("id,job_type,status,attempts,max_attempts,input_payload,output_payload,last_error,created_at,updated_at")
            .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).eq("item_id",id)
            .in("job_type",aiTypes).order("created_at",{ascending:false}).limit(50);
          if(error) throw error;
          return out(req,{ok:true,ai_jobs:data||[]});
        }
        const b=await req.json().catch(()=>({}));
        const operation=String(b.operation||"");
        const jobType=({summarize:"ai_summarize",classify:"ai_classify",extract_entities:"ai_extract_entities",link_knowledge:"ai_link_knowledge"} as any)[operation];
        if(!jobType) throw new ApiError("INVALID_AI_OPERATION");
        const {data:archive,error:archiveError}=await db.from("aqx_favorites_archives")
          .select("id,content_hash,capture_status").eq("owner_type",o.owner_type).eq("owner_id",o.owner_id)
          .eq("item_id",id).is("deleted_at",null).maybeSingle();
        if(archiveError) throw archiveError;
        if(!archive||archive.capture_status!=="ready"||!archive.content_hash) throw new ApiError("READY_ARCHIVE_REQUIRED",409);
        const {plan}=await planFor(o);
        const monthlyLimit=Number(plan.limits?.ai_jobs_monthly??0);
        if(monthlyLimit===0) throw new ApiError("PLAN_LIMIT_REACHED:ai_jobs_monthly",402);
        if(monthlyLimit>0){
          const monthStart=new Date();monthStart.setUTCDate(1);monthStart.setUTCHours(0,0,0,0);
          const {count,error}=await db.from("aqx_favorites_processing_jobs").select("id",{count:"exact",head:true})
            .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).in("job_type",aiTypes)
            .gte("created_at",monthStart.toISOString());
          if(error) throw error;
          if((count||0)>=monthlyLimit) throw new ApiError("PLAN_LIMIT_REACHED:ai_jobs_monthly",402);
        }
        const idem="ai:"+id+":"+operation+":"+archive.content_hash;
        const {data:existing,error:existingError}=await db.from("aqx_favorites_processing_jobs")
          .select("id,status,output_payload").eq("owner_type",o.owner_type).eq("owner_id",o.owner_id)
          .eq("idempotency_key",idem).maybeSingle();
        if(existingError) throw existingError;
        if(existing) return out(req,{ok:true,job:existing,already_requested:true},202);
        const {data:job,error}=await db.from("aqx_favorites_processing_jobs").insert({
          owner_type:o.owner_type,owner_id:o.owner_id,item_id:id,job_type:jobType,priority:6,
          idempotency_key:idem,input_payload:{operation,archive_id:archive.id,content_hash:archive.content_hash}
        }).select("id,job_type,status,created_at").single();
        if(error) throw error;
        await event(o,"ai_analysis_queued",id,{job_id:job.id,operation,content_hash:archive.content_hash});
        return out(req,{ok:true,job,queued:true,provider_configuration_required:true},202);
      }
      if ((req.method === "GET" || req.method === "POST" || req.method === "DELETE") && action === "archive") {
        const item = await ownedItem(o,id);
        await requireFeature(o,"web_archive");
        if(req.method==="DELETE"){
          const {data:archive,error:archiveError}=await db.from("aqx_favorites_archives").select("id,content_storage_path")
            .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).eq("item_id",id).is("deleted_at",null).maybeSingle();
          if(archiveError) throw archiveError;
          if(!archive) throw new ApiError("ARCHIVE_NOT_FOUND",404);
          const {data:versions,error:versionError}=await db.from("aqx_favorites_archive_versions").select("content_storage_path")
            .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).eq("archive_id",archive.id);
          if(versionError) throw versionError;
          const paths=[...new Set([archive.content_storage_path,...(versions||[]).map((v:any)=>v.content_storage_path)].filter((x:any)=>typeof x==="string"&&x.length>0))] as string[];
          if(paths.length){
            const removed=await db.storage.from(ARCHIVE_BUCKET).remove(paths);
            if(removed.error) throw removed.error;
          }
          const {error:jobCancelError}=await db.from("aqx_favorites_processing_jobs").update({
            status:"canceled",locked_at:null,locked_by:null,last_error:"archive_deleted",updated_at:new Date().toISOString()
          }).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).eq("item_id",id)
            .eq("job_type","capture_archive").in("status",["queued","processing"]);
          if(jobCancelError) throw jobCancelError;
          const {error:versionDeleteError}=await db.from("aqx_favorites_archive_versions").delete()
            .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).eq("archive_id",archive.id);
          if(versionDeleteError) throw versionDeleteError;
          const {error:deleteError}=await db.from("aqx_favorites_archives").delete()
            .eq("id",archive.id).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id);
          if(deleteError) throw deleteError;
          await event(o,"archive_deleted",id,{archive_id:archive.id,versions_removed:versions?.length||0});
          return out(req,{ok:true,deleted:true,files_removed:paths.length,versions_removed:versions?.length||0});
        }
        if(req.method==="GET" && parts[itemPos+3]==="versions"){
          const current=await db.from("aqx_favorites_archives").select("id").eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).eq("item_id",id).is("deleted_at",null).maybeSingle();
          if(current.error) throw current.error;
          if(!current.data) throw new ApiError("ARCHIVE_NOT_FOUND",404);
          const {data:versions,error}=await db.from("aqx_favorites_archive_versions").select("*")
            .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).eq("archive_id",current.data.id)
            .order("version_number",{ascending:false}).limit(50);
          if(error) throw error;
          const withUrls=await Promise.all((versions||[]).map(async(v:any)=>{
            const signed=await db.storage.from(ARCHIVE_BUCKET).createSignedUrl(v.content_storage_path,300);
            return {...v,content_url:signed.error?null:signed.data?.signedUrl||null};
          }));
          return out(req,{ok:true,versions:withUrls});
        }
        if (req.method === "GET") {
          const {data,error}=await db.from("aqx_favorites_archives").select("id,item_id,source_url,canonical_url,page_title,excerpt,word_count,language_code,mime_type,http_status,capture_status,captured_at,last_error,created_at,updated_at")
            .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).eq("item_id",id).is("deleted_at",null).maybeSingle();
          if(error) throw error;
          let contentUrl:string|null=null;
          if(data?.content_storage_path){
            const signed=await db.storage.from(ARCHIVE_BUCKET).createSignedUrl(data.content_storage_path,300);
            if(signed.error) throw signed.error;
            contentUrl=signed.data?.signedUrl||null;
          }
          return out(req,{ok:true,archive:data,content_url:contentUrl,content_url_expires_in:contentUrl?300:0});
        }
        const existing=await db.from("aqx_favorites_archives").select("*").eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).eq("item_id",id).is("deleted_at",null).maybeSingle();
        if(existing.error) throw existing.error;
        if(existing.data){
          if(["queued","capturing"].includes(existing.data.capture_status))
            return out(req,{ok:true,archive:existing.data,already_queued:true});
          const day=new Date().toISOString().slice(0,10);
          const {error:jobError}=await db.from("aqx_favorites_processing_jobs").insert({
            owner_type:o.owner_type,owner_id:o.owner_id,item_id:id,job_type:"capture_archive",priority:4,
            idempotency_key:"archive-refresh:"+existing.data.id+":"+day,
            input_payload:{archive_id:existing.data.id,source_url:item.url,refresh:true}
          });
          if(jobError && jobError.code!=="23505") throw jobError;
          const {data:archive,error}=await db.from("aqx_favorites_archives").update({
            capture_status:"queued",last_error:null,updated_at:new Date().toISOString()
          }).eq("id",existing.data.id).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).select("*").single();
          if(error) throw error;
          return out(req,{ok:true,archive,queued_refresh:true},202);
        }
        await assertCapacity(o,"archive_items","aqx_favorites_archives");
        const {data:archive,error}=await db.from("aqx_favorites_archives").insert({
          owner_type:o.owner_type,owner_id:o.owner_id,item_id:id,source_url:item.url,page_title:item.title,capture_status:"queued"
        }).select("*").single();
        if(error) throw error;
        const {error:jobError}=await db.from("aqx_favorites_processing_jobs").insert({
          owner_type:o.owner_type,owner_id:o.owner_id,item_id:id,job_type:"capture_archive",priority:4,
          idempotency_key:"archive:"+archive.id,input_payload:{archive_id:archive.id,source_url:item.url}
        });
        if(jobError && jobError.code!=="23505") throw jobError;
        return out(req,{ok:true,archive,queued:true},202);
      }
      if ((req.method === "GET" || req.method === "POST") && action === "annotations") {
        const item=await ownedItem(o,id);
        await requireFeature(o,"annotations");
        if(req.method==="GET"){
          const {data,error}=await db.from("aqx_favorites_annotations").select("*")
            .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).eq("item_id",id).order("created_at",{ascending:false}).limit(500);
          if(error) throw error;
          return out(req,{ok:true,annotations:data||[]});
        }
        const b=await req.json().catch(()=>({}));
        const kind=["highlight","note","bookmark"].includes(b.annotation_type)?b.annotation_type:"highlight";
        const selected=typeof b.selected_text==="string"?b.selected_text.slice(0,8000):"";
        const note=typeof b.note_text==="string"?b.note_text.slice(0,4000):"";
        if(kind==="highlight" && !selected.trim()) throw new ApiError("HIGHLIGHT_TEXT_REQUIRED");
        if(kind==="note" && !note.trim()) throw new ApiError("ANNOTATION_NOTE_REQUIRED");
        const anchor=b.anchor && typeof b.anchor==="object" && !Array.isArray(b.anchor)?b.anchor:{};
        const {data,error}=await db.from("aqx_favorites_annotations").insert({
          owner_type:o.owner_type,owner_id:o.owner_id,item_id:id,annotation_type:kind,
          selected_text:selected,note_text:note,color:typeof b.color==="string"?b.color.slice(0,24):"yellow",
          anchor,source_url:item.url
        }).select("*").single();
        if(error) throw error;
        return out(req,{ok:true,annotation:data},201);
      }
      if ((req.method === "GET" || req.method === "POST") && (action === "link-health" || action === "link-check")) {
        const item=await ownedItem(o,id);
        await requireFeature(o,"link_monitor");
        if(req.method==="GET"){
          const {data,error}=await db.from("aqx_favorites_link_health").select("*")
            .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).eq("item_id",id).maybeSingle();
          if(error) throw error;
          return out(req,{ok:true,link_health:data});
        }
        const now=new Date().toISOString();
        let {data:health,error}=await db.from("aqx_favorites_link_health").upsert({
          owner_type:o.owner_type,owner_id:o.owner_id,item_id:id,next_check_at:now,updated_at:now
        },{onConflict:"owner_type,owner_id,item_id"}).select("*").single();
        if(error) throw error;
        const monitor=db.schema("command_center").from("monitoring_checks");
        let checkId=health.monitoring_check_id;
        if(checkId){
          const updated=await monitor.update({target_url:item.url,enabled:true,next_check_at:now,updated_at:now})
            .eq("id",checkId).select("id").maybeSingle();
          if(updated.error) throw updated.error;
          if(!updated.data) checkId=null;
        }
        if(!checkId){
          const existing=await monitor.select("id").eq("target_type","link").eq("target_id",id).maybeSingle();
          if(existing.error) throw existing.error;
          if(existing.data) checkId=existing.data.id;
          else {
            const created=await monitor.insert({
              target_type:"link",target_id:id,target_url:item.url,check_type:"http",enabled:true,
              interval_seconds:86400,timeout_ms:15000,expected_status_codes:[200,201,202,204,301,302,307,308],
              next_check_at:now,last_status:"unknown"
            }).select("id").single();
            if(created.error) throw created.error;
            checkId=created.data.id;
          }
        }
        const saved=await db.from("aqx_favorites_link_health").update({
          monitoring_check_id:checkId,next_check_at:now,updated_at:now
        }).eq("id",health.id).select("*").single();
        if(saved.error) throw saved.error;
        return out(req,{ok:true,link_health:saved.data,monitoring:"AQX central monitor",queued:true},202);
      }
      if ((req.method === "GET" || req.method === "POST") && action === "relations") {
        await ownedItem(o,id);
        await requireFeature(o,"knowledge_graph");
        if(req.method==="GET"){
          const {data,error}=await db.from("aqx_favorites_knowledge_edges").select("*")
            .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).is("deleted_at",null)
            .or("source_item_id.eq."+id+",target_item_id.eq."+id).order("created_at",{ascending:false}).limit(500);
          if(error) throw error;
          return out(req,{ok:true,relations:data||[]});
        }
        const b=await req.json().catch(()=>({}));
        const target=typeof b.target_item_id==="string"?b.target_item_id:"";
        if(!/^[0-9a-f-]{36}$/i.test(target)) throw new ApiError("TARGET_ITEM_REQUIRED");
        await ownedItem(o,target);
        const relation=["related_to","supports","contradicts","derived_from","same_topic","follow_up","duplicate_of"].includes(b.relation_type)?b.relation_type:"related_to";
        const confidence=Number(b.confidence??1);
        if(!Number.isFinite(confidence)||confidence<0||confidence>1) throw new ApiError("INVALID_CONFIDENCE");
        await assertCapacity(o,"knowledge_edges","aqx_favorites_knowledge_edges");
        const {data,error}=await db.from("aqx_favorites_knowledge_edges").upsert({
          owner_type:o.owner_type,owner_id:o.owner_id,source_item_id:id,target_item_id:target,
          relation_type:relation,confidence,origin:"manual",
          rationale:typeof b.rationale==="string"?b.rationale.slice(0,1000):null
        },{onConflict:"owner_type,owner_id,source_item_id,target_item_id,relation_type"}).select("*").single();
        if(error) throw error;
        return out(req,{ok:true,relation:data},201);
      }
      if (req.method==="GET" && action==="aqx-match") {
        const item=await ownedItem(o,id);
        const links=db.schema("command_center").from("links");
        let found=await links.select("id,name,title,url,canonical_url,description,content_type,language_code,image_url,archive_number,archived_at,last_checked_at,last_http_status,status,access_mode")
          .eq("url",item.url).eq("status","active").eq("access_mode","public").eq("requires_auth",false).eq("requires_payment",false).limit(1).maybeSingle();
        if(found.error) throw found.error;
        if(!found.data){
          found=await links.select("id,name,title,url,canonical_url,description,content_type,language_code,image_url,archive_number,archived_at,last_checked_at,last_http_status,status,access_mode")
            .eq("canonical_url",item.url).eq("status","active").eq("access_mode","public").eq("requires_auth",false).eq("requires_payment",false).maybeSingle();
          if(found.error) throw found.error;
        }
        if(!found.data) return out(req,{ok:true,matched:false,scope:"registered_public_aqx_resources_only"});
        const {data:versions,error:versionError}=await db.schema("command_center").from("link_archive_versions")
          .select("id,archive_number,version_number,change_kind,recorded_at,snapshot")
          .eq("link_id",found.data.id).order("version_number",{ascending:false}).limit(10);
        if(versionError) throw versionError;
        return out(req,{ok:true,matched:true,resource:found.data,archive_history:versions||[],scope:"registered_public_aqx_resources_only"});
      }
      if ((req.method === "GET" || req.method === "POST") && action === "aqx-links") {
        await ownedItem(o,id);
        await requireFeature(o,"aqx_bridge");
        if(req.method==="GET"){
          const {data,error}=await db.from("aqx_favorites_aqx_links").select("*")
            .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).eq("item_id",id).is("deleted_at",null).order("created_at",{ascending:false});
          if(error) throw error;
          return out(req,{ok:true,aqx_links:data||[]});
        }
        const b=await req.json().catch(()=>({}));
        const domain=typeof b.aqx_domain==="string"?b.aqx_domain.trim().toLowerCase():"";
        const resourceType=typeof b.resource_type==="string"?b.resource_type.trim().toLowerCase():"";
        const resourceId=typeof b.resource_id==="string"?b.resource_id:"";
        if(!/^[a-z][a-z0-9_]{1,63}$/.test(domain)||!/^[a-z][a-z0-9_]{1,63}$/.test(resourceType)||!/^[0-9a-f-]{36}$/i.test(resourceId))
          throw new ApiError("INVALID_AQX_RESOURCE_REFERENCE");
        const relation=["reference","supports","source_for","action_from","related"].includes(b.relation_type)?b.relation_type:"reference";
        await assertCapacity(o,"aqx_links","aqx_favorites_aqx_links");
        const {data,error}=await db.from("aqx_favorites_aqx_links").upsert({
          owner_type:o.owner_type,owner_id:o.owner_id,item_id:id,aqx_domain:domain,resource_type:resourceType,
          resource_id:resourceId,relation_type:relation,label:typeof b.label==="string"?b.label.slice(0,180):null,
          metadata:b.metadata&&typeof b.metadata==="object"&&!Array.isArray(b.metadata)?b.metadata:{}
        },{onConflict:"owner_type,owner_id,item_id,aqx_domain,resource_type,resource_id,relation_type"}).select("*").single();
        if(error) throw error;
        return out(req,{ok:true,aqx_link:data},201);
      }
      if ((req.method === "GET" || req.method === "POST") && action === "progress") {
        const item=await ownedItem(o,id);
        if(req.method==="GET"){
          const {data,error}=await db.from("aqx_favorites_reading_progress").select("*")
            .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).eq("item_id",id).maybeSingle();
          if(error) throw error;
          return out(req,{ok:true,item,progress:data});
        }
        const b=await req.json().catch(()=>({}));
        const percent=Number(b.progress_percent??0), position=Number(b.position_seconds??0);
        if(!Number.isFinite(percent)||percent<0||percent>100||!Number.isInteger(position)||position<0) throw new ApiError("INVALID_READING_PROGRESS");
        const completed=b.completed===true||percent>=100;
        const {data,error}=await db.from("aqx_favorites_reading_progress").upsert({
          owner_type:o.owner_type,owner_id:o.owner_id,item_id:id,progress_percent:completed?100:percent,
          position_seconds:position,completed,last_read_at:new Date().toISOString(),updated_at:new Date().toISOString()
        },{onConflict:"owner_type,owner_id,item_id"}).select("*").single();
        if(error) throw error;
        await event(o,"reading_progress_updated",id,{progress_percent:data.progress_percent,completed});
        return out(req,{ok:true,progress:data});
      }
      if (req.method === "GET" && action === "snapshots") {
        await requireFeature(o,"item_snapshots"); await ownedItem(o,id);
        const {data,error}=await db.from("aqx_favorites_item_snapshots").select("id,item_id,snapshot_kind,snapshot,created_at")
          .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).eq("item_id",id).order("created_at",{ascending:false}).limit(50);
        if(error) throw error;
        return out(req,{ok:true,snapshots:data||[]});
      }
      if (req.method === "POST" && action === "snapshots") {
        await requireFeature(o,"item_snapshots"); const item=await ownedItem(o,id);
        const {data,error}=await db.from("aqx_favorites_item_snapshots").insert({
          owner_type:o.owner_type,owner_id:o.owner_id,item_id:id,snapshot_kind:"manual",snapshot:item
        }).select("*").single();
        if(error) throw error;
        await event(o,"snapshot_created",id,{snapshot_id:data.id});
        return out(req,{ok:true,snapshot:data},201);
      }
      if (req.method === "DELETE" || (req.method === "POST" && action === "restore")) {
        const patch = req.method === "DELETE" ? { deleted_at: new Date().toISOString() } : { deleted_at: null };
        const { data, error } = await db.from("aqx_favorites_items").update(patch)
          .eq("id", id).eq("owner_type", o.owner_type).eq("owner_id", o.owner_id).select("*").maybeSingle();
        if (error) throw error;
        if (!data) throw new ApiError("FAVORITE_NOT_FOUND", 404);
        if(req.method==="DELETE"){
          const {error:monitorError}=await db.schema("command_center").from("monitoring_checks")
            .update({enabled:false,updated_at:new Date().toISOString()}).eq("target_type","link").eq("target_id",id);
          if(monitorError) throw monitorError;
        } else {
          const health=await db.from("aqx_favorites_link_health").select("monitoring_check_id")
            .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).eq("item_id",id).maybeSingle();
          if(health.error) throw health.error;
          if(health.data?.monitoring_check_id){
            const {error:monitorError}=await db.schema("command_center").from("monitoring_checks")
              .update({enabled:true,next_check_at:new Date().toISOString(),updated_at:new Date().toISOString()})
              .eq("id",health.data.monitoring_check_id);
            if(monitorError) throw monitorError;
          }
        }
        await event(o, req.method === "DELETE" ? "item_trashed" : "item_restored", id);
        return out(req, { ok: true, item: data });
      }
      if (req.method === "POST" && action === "open") {
        const { data, error } = await db.from("aqx_favorites_items").update({ last_opened_at: new Date().toISOString() })
          .eq("id", id).eq("owner_type", o.owner_type).eq("owner_id", o.owner_id).is("deleted_at", null)
          .select("*").maybeSingle();
        if (error) throw error;
        if (!data) throw new ApiError("FAVORITE_NOT_FOUND", 404);
        await event(o, "item_opened", id);
        return out(req, { ok: true, item: data });
      }
      if (req.method === "POST" && action === "purge") {
        const { error } = await db.from("aqx_favorites_items").delete()
          .eq("id", id).eq("owner_type", o.owner_type).eq("owner_id", o.owner_id);
        if (error) throw error;
        await event(o, "item_purged", id);
        return out(req, { ok: true, purged: true });
      }
      if (req.method === "PATCH" && !action) {
        const before=await ownedItem(o,id);
        const {plan}=await planFor(o);
        if(plan.features?.item_snapshots===true) {
          const snap=await db.from("aqx_favorites_item_snapshots").insert({
            owner_type:o.owner_type,owner_id:o.owner_id,item_id:id,snapshot_kind:"before_update",snapshot:before
          });
          if(snap.error) throw snap.error;
        }
        const b = await req.json().catch(() => ({})), patch: any = {};
        if ("title" in b) patch.title = String(b.title).trim().slice(0,180);
        if ("note" in b) patch.note = String(b.note).trim().slice(0,1000);
        if ("url" in b) Object.assign(patch, urlValue(b.url));
        if ("item_type" in b) patch.item_type = b.item_type;
        if ("is_pinned" in b) patch.is_pinned = b.is_pinned === true;
        if ("deleted_at" in b) patch.deleted_at = b.deleted_at ? new Date().toISOString() : null;
        if ("collection_name" in b) patch.collection_id = await collectionId(o, String(b.collection_name).slice(0,80));
        if ("category_id" in b) patch.category_id = await categoryById(o,typeof b.category_id === "string" ? b.category_id : null);
        if ("tags" in b && Array.isArray(b.tags)) patch.tags = [...new Set(b.tags.filter((x: any) => typeof x === "string").map((x: string) => x.trim().slice(0,40)).filter(Boolean))].slice(0,20);
        if (!Object.keys(patch).length) throw new ApiError("NO_CHANGES");
        const { data, error } = await db.from("aqx_favorites_items").update(patch)
          .eq("id", id).eq("owner_type", o.owner_type).eq("owner_id", o.owner_id).select("*").maybeSingle();
        if (error?.code === "23505") throw new ApiError("FAVORITE_ALREADY_EXISTS", 409);
        if (error) throw error;
        if (!data) throw new ApiError("FAVORITE_NOT_FOUND", 404);
        await event(o, "item_updated", id);
        return out(req, { ok: true, item: data });
      }
    }

    const reminderPos=parts.lastIndexOf("reminders");
    const reminderId=reminderPos>=0?parts[reminderPos+1]:"";
    if(reminderId && /^[0-9a-f-]{36}$/i.test(reminderId)) {
      const o=await owner(req); await requireFeature(o,"reminders");
      if(req.method==="PATCH") {
        const b=await req.json().catch(()=>({})), patch:any={updated_at:new Date().toISOString()};
        if("title" in b){const v=String(b.title).trim().slice(0,180);if(!v) throw new ApiError("REMINDER_TITLE_REQUIRED");patch.title=v;}
        if("note" in b) patch.note=String(b.note).trim().slice(0,1000);
        if("remind_at" in b){if(typeof b.remind_at!=="string"||Number.isNaN(Date.parse(b.remind_at))) throw new ApiError("INVALID_REMIND_AT");patch.remind_at=new Date(b.remind_at).toISOString();patch.status="pending";patch.snoozed_until=null;}
        if("recurrence" in b){if(!["none","daily","weekly","monthly"].includes(b.recurrence)) throw new ApiError("INVALID_RECURRENCE");patch.recurrence=b.recurrence;}
        if("status" in b){if(!["pending","completed","canceled"].includes(b.status)) throw new ApiError("INVALID_REMINDER_STATUS");patch.status=b.status;patch.completed_at=b.status==="completed"?new Date().toISOString():null;}
        const {data,error}=await db.from("aqx_favorites_reminders").update(patch).eq("id",reminderId).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).is("deleted_at",null).select("*").maybeSingle();
        if(error) throw error;if(!data) throw new ApiError("REMINDER_NOT_FOUND",404);
        return out(req,{ok:true,reminder:data});
      }
      if(req.method==="POST" && parts[reminderPos+2]==="snooze"){
        const b=await req.json().catch(()=>({}));const minutes=Number(b.minutes??60);
        if(!Number.isInteger(minutes)||minutes<5||minutes>10080) throw new ApiError("INVALID_SNOOZE");
        const until=new Date(Date.now()+minutes*60000).toISOString();
        const {data,error}=await db.from("aqx_favorites_reminders").update({status:"snoozed",snoozed_until:until,updated_at:new Date().toISOString()})
          .eq("id",reminderId).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).is("deleted_at",null).select("*").maybeSingle();
        if(error) throw error;if(!data) throw new ApiError("REMINDER_NOT_FOUND",404);
        return out(req,{ok:true,reminder:data});
      }
      if(req.method==="DELETE"){
        const {data,error}=await db.from("aqx_favorites_reminders").update({deleted_at:new Date().toISOString(),status:"canceled",updated_at:new Date().toISOString()})
          .eq("id",reminderId).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).is("deleted_at",null).select("id").maybeSingle();
        if(error) throw error;if(!data) throw new ApiError("REMINDER_NOT_FOUND",404);
        return out(req,{ok:true,deleted:true});
      }
    }
    const savedPos=parts.lastIndexOf("saved-searches");
    const savedId=savedPos>=0?parts[savedPos+1]:"";
    if(savedId && /^[0-9a-f-]{36}$/i.test(savedId)){
      const o=await owner(req); await requireFeature(o,"saved_searches");
      if(req.method==="PATCH"){
        const b=await req.json().catch(()=>({})),patch:any={updated_at:new Date().toISOString()};
        if("name" in b){const v=String(b.name).trim().slice(0,100);if(!v) throw new ApiError("SAVED_SEARCH_NAME_REQUIRED");patch.name=v;}
        if("query_text" in b) patch.query_text=String(b.query_text).trim().slice(0,300);
        if("filters" in b) patch.filters=b.filters&&typeof b.filters==="object"&&!Array.isArray(b.filters)?b.filters:{};
        if("is_pinned" in b) patch.is_pinned=b.is_pinned===true;
        if("last_used" in b) patch.last_used_at=new Date().toISOString();
        const {data,error}=await db.from("aqx_favorites_saved_searches").update(patch).eq("id",savedId).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).is("deleted_at",null).select("*").maybeSingle();
        if(error?.code==="23505") throw new ApiError("SAVED_SEARCH_ALREADY_EXISTS",409);
        if(error) throw error;if(!data) throw new ApiError("SAVED_SEARCH_NOT_FOUND",404);
        return out(req,{ok:true,saved_search:data});
      }
      if(req.method==="DELETE"){
        const {data,error}=await db.from("aqx_favorites_saved_searches").update({deleted_at:new Date().toISOString(),updated_at:new Date().toISOString()})
          .eq("id",savedId).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).is("deleted_at",null).select("id").maybeSingle();
        if(error) throw error;if(!data) throw new ApiError("SAVED_SEARCH_NOT_FOUND",404);
        return out(req,{ok:true,deleted:true});
      }
    }
    const categoryPos = parts.lastIndexOf("categories");
    const categoryIdParam = categoryPos >= 0 ? parts[categoryPos + 1] : "";
    if (categoryIdParam && /^[0-9a-f-]{36}$/i.test(categoryIdParam)) {
      const o = await owner(req), id = categoryIdParam;
      if (req.method === "PATCH") {
        const b = await req.json().catch(()=>({})), patch:any = {};
        if ("name" in b) { const name = typeof b.name==="string"?b.name.trim().slice(0,100):""; if(!name) throw new ApiError("CATEGORY_NAME_REQUIRED"); patch.name=name; }
        if ("slug" in b) patch.slug = String(b.slug).trim().toLowerCase().replace(/[^a-z0-9-]/g,"-").replace(/-+/g,"-").slice(0,120);
        if ("description" in b) patch.description = typeof b.description==="string"?b.description.trim().slice(0,500):"";
        if ("icon" in b) patch.icon = typeof b.icon==="string"?b.icon.slice(0,64):null;
        if ("color" in b) patch.color = typeof b.color==="string"?b.color.slice(0,24):null;
        if ("sort_order" in b && Number.isInteger(b.sort_order)) patch.sort_order=b.sort_order;
        if ("parent_id" in b) patch.parent_id=await categoryById(o,typeof b.parent_id==="string"?b.parent_id:null);
        if (!Object.keys(patch).length) throw new ApiError("NO_CHANGES");
        const {data,error}=await db.from("aqx_favorites_categories").update(patch).eq("id",id)
          .eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).is("deleted_at",null).select("*").maybeSingle();
        if (error?.code==="23505") throw new ApiError("CATEGORY_ALREADY_EXISTS",409);
        if (error) throw error;
        if (!data) throw new ApiError("CATEGORY_NOT_FOUND",404);
        await event(o,"category_updated",null,{category_id:id});
        return out(req,{ok:true,category:data});
      }
      if (req.method === "DELETE") {
        const {data,error}=await db.from("aqx_favorites_categories").update({deleted_at:new Date().toISOString()})
          .eq("id",id).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).is("deleted_at",null).select("id").maybeSingle();
        if (error) throw error;
        if (!data) throw new ApiError("CATEGORY_NOT_FOUND",404);
        await db.from("aqx_favorites_items").update({category_id:null}).eq("owner_type",o.owner_type).eq("owner_id",o.owner_id).eq("category_id",id);
        await event(o,"category_deleted",null,{category_id:id});
        return out(req,{ok:true,deleted:true});
      }
    }

    const collectionPos = parts.lastIndexOf("collections");
    const collectionIdParam = collectionPos >= 0 ? parts[collectionPos + 1] : "";
    if (collectionIdParam && /^[0-9a-f-]{36}$/i.test(collectionIdParam)) {
      const o = await owner(req), id = collectionIdParam;
      if (req.method === "PATCH") {
        const b = await req.json().catch(() => ({})), patch: any = {};
        if ("name" in b) {
          const name = typeof b.name === "string" ? b.name.trim().slice(0,80) : "";
          if (!name) throw new ApiError("COLLECTION_NAME_REQUIRED");
          patch.name = name;
        }
        if ("description" in b) patch.description = typeof b.description === "string" ? b.description.trim().slice(0,500) : "";
        if ("color" in b) patch.color = typeof b.color === "string" ? b.color.trim().slice(0,24) : "purple";
        if ("sort_order" in b && Number.isInteger(b.sort_order)) patch.sort_order = b.sort_order;
        if (!Object.keys(patch).length) throw new ApiError("NO_CHANGES");
        const { data, error } = await db.from("aqx_favorites_collections").update(patch)
          .eq("id", id).eq("owner_type", o.owner_type).eq("owner_id", o.owner_id).is("deleted_at", null)
          .select("*").maybeSingle();
        if (error?.code === "23505") throw new ApiError("COLLECTION_ALREADY_EXISTS", 409);
        if (error) throw error;
        if (!data) throw new ApiError("COLLECTION_NOT_FOUND", 404);
        await event(o, "collection_updated", null, { collection_id: id });
        return out(req, { ok: true, collection: data });
      }
      if (req.method === "DELETE") {
        const { data, error } = await db.from("aqx_favorites_collections").update({ deleted_at: new Date().toISOString() })
          .eq("id", id).eq("owner_type", o.owner_type).eq("owner_id", o.owner_id).is("deleted_at", null)
          .select("id").maybeSingle();
        if (error) throw error;
        if (!data) throw new ApiError("COLLECTION_NOT_FOUND", 404);
        await db.from("aqx_favorites_items").update({ collection_id: null })
          .eq("owner_type", o.owner_type).eq("owner_id", o.owner_id).eq("collection_id", id);
        await event(o, "collection_deleted", null, { collection_id: id });
        return out(req, { ok: true, deleted: true });
      }
    }
    return out(req, { ok: false, error: "NOT_FOUND" }, 404);
  } catch (e) {
    if (e instanceof ApiError) return out(req, { ok: false, error: e.message }, e.status);
    const dbError = e as any;
    if (dbError?.code === "P0001" && String(dbError?.message||"").includes("PLAN_LIMIT_REACHED"))
      return out(req,{ok:false,error:String(dbError.message)},402);
    if (dbError?.code === "23514" && String(dbError?.message||"").includes("CATEGORY_"))
      return out(req,{ok:false,error:String(dbError.message)},409);
    console.error("AQX Favorites error", e);
    return out(req, { ok: false, error: "INTERNAL_ERROR" }, 500);
  }
});
