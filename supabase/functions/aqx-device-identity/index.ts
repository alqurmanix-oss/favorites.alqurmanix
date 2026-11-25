import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from "npm:@simplewebauthn/server@13.2.2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SECRET = (() => {
  const raw = Deno.env.get("SUPABASE_SECRET_KEYS");
  if (raw) { try { return JSON.parse(raw).default; } catch {} }
  return Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
})();
const db = createClient(SUPABASE_URL, SECRET, { auth: { persistSession: false, autoRefreshToken: false } });
const RP_ID = "alqurmanix.com";
const RP_NAME = "AQX Favorites";
const ORIGIN = "https://favorites.alqurmanix.com";
function allowedOrigin(value:string) {
  try { const u=new URL(value); return u.protocol==="https:" && !u.port && (u.hostname==="alqurmanix.com" || u.hostname.endsWith(".alqurmanix.com")); }
  catch { return false; }
}
class ApiError extends Error { constructor(message: string, public status = 400) { super(message); } }
const cors = (req: Request) => {
  const origin = req.headers.get("origin") || ORIGIN;
  return {
    "Access-Control-Allow-Origin": allowedOrigin(origin) ? origin : "null",
    "Access-Control-Allow-Headers": "content-type,x-aqx-guest-token",
    "Access-Control-Allow-Methods": "POST,OPTIONS",
    "Vary": "Origin"
  };
};
const out = (req: Request, data: unknown, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { ...cors(req), "Content-Type": "application/json", "Cache-Control": "no-store" }
});
const enc = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
const dec = (s: string) => Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")+"=".repeat((4-s.length%4)%4)), c=>c.charCodeAt(0));
const hash = async (s: string) => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(s))),b=>b.toString(16).padStart(2,"0")).join("");
const randomToken = () => enc(crypto.getRandomValues(new Uint8Array(32)));
function uuidBytes(id: string) { return Uint8Array.from(id.replaceAll("-","").match(/.{2}/g)!.map(x=>parseInt(x,16))); }

async function guestId(req: Request) {
  const raw = req.headers.get("x-aqx-guest-token") || "";
  if (raw.length < 32 || raw.length > 256) throw new ApiError("GUEST_SESSION_REQUIRED",401);
  const tokenHash = await hash(raw);
  const session = await db.from("aqx_favorites_guest_sessions").select("guest_id,status,expires_at").eq("token_hash_hex",tokenHash).maybeSingle();
  if (session.error) throw session.error;
  let id = session.data?.guest_id || null;
  if (!id) {
    const device = await db.from("aqx_favorites_guest_devices").select("guest_id").eq("device_token_hash_hex",tokenHash).is("revoked_at",null).maybeSingle();
    if (device.error) throw device.error;
    id = device.data?.guest_id || null;
  }
  if (!id) throw new ApiError("GUEST_SESSION_INVALID",401);
  const active=await db.from("aqx_favorites_guest_sessions").select("status,expires_at").eq("guest_id",id).maybeSingle();
  if(active.error) throw active.error;
  if(!active.data||active.data.status!=="active"||new Date(active.data.expires_at).getTime()<Date.now())
    throw new ApiError("GUEST_SESSION_INVALID",401);
  return id as string;
}
async function saveChallenge(challenge: string,purpose:"register"|"authenticate",guest_id:string|null,origin:string) {
  const {data,error}=await db.from("aqx_favorites_webauthn_challenges").insert({
    challenge,origin,purpose,guest_id,expires_at:new Date(Date.now()+5*60*1000).toISOString()
  }).select("id").single();
  if(error) throw error;
  return data.id as string;
}
async function consumeChallenge(id:string,purpose:"register"|"authenticate",guest_id?:string) {
  let q=db.from("aqx_favorites_webauthn_challenges").update({consumed_at:new Date().toISOString()})
    .eq("id",id).eq("purpose",purpose).is("consumed_at",null).gt("expires_at",new Date().toISOString());
  q=guest_id?q.eq("guest_id",guest_id):q.is("guest_id",null);
  const {data,error}=await q.select("challenge,origin").maybeSingle();
  if(error) throw error;
  if(!data) throw new ApiError("WEBAUTHN_CHALLENGE_EXPIRED_OR_USED",400);
  return {challenge:data.challenge as string,origin:data.origin as string};
}
async function issueDeviceToken(guest_id:string,deviceLabel:string) {
  const {count,error:countError}=await db.from("aqx_favorites_guest_devices").select("id",{count:"exact",head:true}).eq("guest_id",guest_id).is("revoked_at",null);
  if(countError) throw countError;
  if((count||0)>=20) throw new ApiError("GUEST_DEVICE_LIMIT_REACHED",409);
  const deviceToken=randomToken();
  const {data,error}=await db.from("aqx_favorites_guest_devices").insert({
    guest_id,device_token_hash_hex:await hash(deviceToken),device_label:deviceLabel.slice(0,120)
  }).select("id,device_label,created_at,last_seen_at,trusted_at").single();
  if(error) throw error;
  return {device_token:deviceToken,device:data};
}

Deno.serve(async (req:Request) => {
  if(req.method==="OPTIONS") return new Response("ok",{headers:cors(req)});
  if(req.method!=="POST") return out(req,{ok:false,error:"METHOD_NOT_ALLOWED"},405);
  const requestOrigin=req.headers.get("origin")||"";
  if(!allowedOrigin(requestOrigin)) return out(req,{ok:false,error:"ORIGIN_NOT_ALLOWED"},403);
  try {
    const path=new URL(req.url).pathname.replace(/\/+$/,"");
    const body=await req.json().catch(()=>({}));
    if(path.endsWith("/register/options")) {
      const guest_id=await guestId(req);
      const existing=await db.from("aqx_favorites_guest_webauthn_credentials").select("credential_id")
        .eq("guest_id",guest_id).is("revoked_at",null);
      if(existing.error) throw existing.error;
      const options=await generateRegistrationOptions({
        rpName:RP_NAME,rpID:RP_ID,userID:uuidBytes(guest_id),userName:"guest-"+guest_id,
        attestationType:"none",
        authenticatorSelection:{authenticatorAttachment:"platform",residentKey:"required",userVerification:"preferred"},
        excludeCredentials:(existing.data||[]).map(x=>({id:x.credential_id}))
      });
      const challenge_id=await saveChallenge(options.challenge,"register",guest_id,requestOrigin);
      return out(req,{ok:true,challenge_id,options});
    }
    if(path.endsWith("/register/verify")) {
      const guest_id=await guestId(req);
      if(typeof body.challenge_id!=="string"||!body.response) throw new ApiError("WEBAUTHN_RESPONSE_REQUIRED");
      const expected=await consumeChallenge(body.challenge_id,"register",guest_id);
      if(expected.origin!==requestOrigin) throw new ApiError("WEBAUTHN_ORIGIN_MISMATCH",403);
      const verification=await verifyRegistrationResponse({
        response:body.response,expectedChallenge:expected.challenge,expectedOrigin:expected.origin,expectedRPID:RP_ID,requireUserVerification:false
      });
      if(!verification.verified||!verification.registrationInfo) throw new ApiError("WEBAUTHN_REGISTRATION_FAILED",400);
      const info=verification.registrationInfo;
      const credential=info.credential;
      const {error}=await db.from("aqx_favorites_guest_webauthn_credentials").insert({
        credential_id:credential.id,guest_id,public_key_b64:enc(credential.publicKey),
        sign_count:credential.counter,transports:credential.transports||[],
        device_type:info.credentialDeviceType||null,backed_up:info.credentialBackedUp===true
      });
      if(error?.code==="23505") throw new ApiError("WEBAUTHN_CREDENTIAL_ALREADY_REGISTERED",409);
      if(error) throw error;
      const issued=await issueDeviceToken(guest_id,"جهاز موثوق عبر WebAuthn");
      return out(req,{ok:true,verified:true,...issued},201);
    }
    if(path.endsWith("/authenticate/options")) {
      const options=await generateAuthenticationOptions({rpID:RP_ID,userVerification:"preferred",allowCredentials:[]});
      const challenge_id=await saveChallenge(options.challenge,"authenticate",null,requestOrigin);
      return out(req,{ok:true,challenge_id,options});
    }
    if(path.endsWith("/authenticate/verify")) {
      if(typeof body.challenge_id!=="string"||!body.response?.id) throw new ApiError("WEBAUTHN_RESPONSE_REQUIRED");
      const expected=await consumeChallenge(body.challenge_id,"authenticate");
      if(expected.origin!==requestOrigin) throw new ApiError("WEBAUTHN_ORIGIN_MISMATCH",403);
      const {data:stored,error}=await db.from("aqx_favorites_guest_webauthn_credentials")
        .select("credential_id,guest_id,public_key_b64,sign_count,transports")
        .eq("credential_id",body.response.id).is("revoked_at",null).maybeSingle();
      if(error) throw error;
      if(!stored) throw new ApiError("WEBAUTHN_CREDENTIAL_NOT_FOUND",404);
      const verification=await verifyAuthenticationResponse({
        response:body.response,expectedChallenge:expected.challenge,expectedOrigin:expected.origin,expectedRPID:RP_ID,
        credential:{id:stored.credential_id,publicKey:dec(stored.public_key_b64),counter:Number(stored.sign_count),transports:stored.transports||[]},
        requireUserVerification:false
      });
      if(!verification.verified) throw new ApiError("WEBAUTHN_AUTHENTICATION_FAILED",401);
      const renewed=await db.from("aqx_favorites_guest_sessions")
        .update({last_activity_at:new Date().toISOString(),expires_at:new Date(Date.now()+180*86400000).toISOString()})
        .eq("guest_id",stored.guest_id).eq("status","active").select("guest_id").maybeSingle();
      if(renewed.error) throw renewed.error;
      if(!renewed.data) throw new ApiError("GUEST_LIBRARY_UNAVAILABLE",410);
      const {error:updateError}=await db.from("aqx_favorites_guest_webauthn_credentials")
        .update({sign_count:verification.authenticationInfo.newCounter,last_used_at:new Date().toISOString()})
        .eq("credential_id",stored.credential_id).eq("sign_count",stored.sign_count).is("revoked_at",null);
      if(updateError) throw updateError;
      const issued=await issueDeviceToken(stored.guest_id,"جهاز موثوق عبر WebAuthn");
      return out(req,{ok:true,verified:true,...issued},200);
    }
    return out(req,{ok:false,error:"NOT_FOUND"},404);
  } catch(e) {
    if(e instanceof ApiError) return out(req,{ok:false,error:e.message},e.status);
    console.error("AQX WebAuthn error",e);
    return out(req,{ok:false,error:"INTERNAL_ERROR"},500);
  }
});
