const API = "https://vuszqzgldbsscuxdfhdz.supabase.co/functions/v1/aqx-favorites";
const KEYS = { token: "aqx_guest_token", guestId: "aqx_guest_id", queue: "aqx_offline_queue", lastSync: "aqx_last_sync" };

async function getState() {
  return chrome.storage.local.get([KEYS.token, KEYS.guestId, KEYS.queue, KEYS.lastSync]);
}
async function api(path, options = {}, token = "") {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (token) headers["x-aqx-guest-token"] = token;
  const response = await fetch(API + path, { ...options, headers, cache: "no-store" });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || "HTTP_" + response.status);
  return body;
}
async function createGuestSession() {
  const result = await api("/guest/session", { method: "POST", body: "{}" });
  await chrome.storage.local.set({ [KEYS.token]: result.guest_token, [KEYS.guestId]: result.guest_id });
  return result;
}
async function ensureSession() {
  const state = await getState();
  if (state[KEYS.token]) return state[KEYS.token];
  return (await createGuestSession()).guest_token;
}
async function saveToCloud(item, token) {
  return api("/items", {
    method: "POST",
    body: JSON.stringify({
      url: item.url,
      title: item.title || item.url,
      note: item.note || "",
      item_type: item.item_type || "link",
      tags: Array.isArray(item.tags) ? item.tags : []
    })
  }, token);
}
async function enqueue(item) {
  const state = await getState();
  const queue = Array.isArray(state[KEYS.queue]) ? state[KEYS.queue] : [];
  const key = item.url;
  if (!queue.some(x => x.url === key)) queue.push({ ...item, queued_at: new Date().toISOString() });
  await chrome.storage.local.set({ [KEYS.queue]: queue });
}
async function flushQueue() {
  if (!navigator.onLine) return { synced: 0, pending: (await getState())[KEYS.queue]?.length || 0 };
  const state = await getState();
  const queue = Array.isArray(state[KEYS.queue]) ? state[KEYS.queue] : [];
  if (!queue.length) return { synced: 0, pending: 0 };
  const token = await ensureSession();
  const remaining = [];
  let synced = 0;
  for (const item of queue) {
    try {
      await saveToCloud(item, token);
      synced++;
    } catch (error) {
      if (String(error.message).includes("FAVORITE_ALREADY_EXISTS")) synced++;
      else remaining.push(item);
    }
  }
  await chrome.storage.local.set({ [KEYS.queue]: remaining, [KEYS.lastSync]: new Date().toISOString() });
  return { synced, pending: remaining.length };
}
async function savePage(input) {
  const url = input.url;
  if (!url || !/^https?:\/\//i.test(url)) throw new Error("هذا النوع من الصفحات غير مدعوم؛ احفظ روابط HTTP أو HTTPS.");
  const item = { url, title: (input.title || url).slice(0, 180), note: (input.note || "").slice(0, 1000), item_type: "link" };
  if (!navigator.onLine) {
    await enqueue(item);
    return { queued: true, message: "انقطع الاتصال؛ أُضيف الرابط إلى طابور الحفظ المحلي وسيُزامَن عند عودة الإنترنت." };
  }
  try {
    const token = await ensureSession();
    await saveToCloud(item, token);
    return { saved: true, message: "تم حفظ الرابط في مكتبة AQX السحابية." };
  } catch (error) {
    if (String(error.message).includes("FAVORITE_ALREADY_EXISTS")) return { saved: true, duplicate: true, message: "هذا الرابط محفوظ بالفعل في مكتبتك." };
    await enqueue(item);
    return { queued: true, message: "تعذر الوصول إلى الخادم؛ احتفظنا بالرابط في طابور محلي وسنحاول مزامنته تلقائياً." };
  }
}
chrome.runtime.onInstalled.addListener(async () => {
  chrome.contextMenus.removeAll(() => chrome.contextMenus.create({ id: "aqx-save-page", title: "احفظ الصفحة في AQX Favorites", contexts: ["page", "link"] }));
  chrome.alarms.create("aqx-sync", { periodInMinutes: 5 });
});
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== "aqx-save-page") return;
  const url = info.linkUrl || info.pageUrl || tab?.url;
  const title = info.linkUrl ? info.linkUrl : (tab?.title || url);
  await savePage({ url, title });
});
chrome.commands.onCommand.addListener(async command => {
  if (command !== "save-current-page") return;
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  if (tab?.url) await savePage({ url: tab.url, title: tab.title });
});
chrome.alarms.onAlarm.addListener(alarm => { if (alarm.name === "aqx-sync") flushQueue(); });
chrome.runtime.onStartup.addListener(() => flushQueue());
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    try {
      if (message.type === "AQX_STATUS") {
        const state = await getState();
        sendResponse({ ok: true, connected: !!state[KEYS.token], guestId: state[KEYS.guestId] || null, pending: (state[KEYS.queue] || []).length, lastSync: state[KEYS.lastSync] || null });
      } else if (message.type === "AQX_SAVE_CURRENT") {
        const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
        sendResponse({ ok: true, result: await savePage({ url: tab?.url, title: tab?.title }) });
      } else if (message.type === "AQX_SAVE_LINK") {
        sendResponse({ ok: true, result: await savePage(message.item || {}) });
      } else if (message.type === "AQX_FLUSH") {
        sendResponse({ ok: true, result: await flushQueue() });
      } else if (message.type === "AQX_RECOVER") {
        const token = String(message.token || "").trim();
        if (token.length < 40) throw new Error("مفتاح الاسترداد غير صالح.");
        const result = await api("/items?limit=1", { method: "GET" }, token);
        await chrome.storage.local.set({ [KEYS.token]: token, [KEYS.guestId]: result.items?.[0]?.owner_id || "recovered" });
        sendResponse({ ok: true, message: "تم التحقق من مفتاح الاسترداد. أصبحت مكتبتك متاحة على هذا المتصفح." });
      } else if (message.type === "AQX_SET_TOKEN") {
        const token = String(message.token || "").trim();
        if (token.length < 40) throw new Error("مفتاح الاسترداد غير صالح.");
        await api("/items?limit=1", { method: "GET" }, token);
        await chrome.storage.local.set({ [KEYS.token]: token });
        sendResponse({ ok: true, message: "تم ربط مكتبتك بهذا المتصفح." });
      } else if (message.type === "AQX_EXPORT_KEY") {
        const state = await getState();
        sendResponse({ ok: true, token: state[KEYS.token] || null });
      } else {
        throw new Error("طلب غير معروف.");
      }
    } catch (error) { sendResponse({ ok: false, error: error.message || "حدث خطأ غير متوقع." }); }
  })();
  return true;
});
