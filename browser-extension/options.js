const $=id=>document.getElementById(id);let current=null;
async function load(){const r=await chrome.runtime.sendMessage({type:"AQX_EXPORT_KEY"});current=r?.token||null;if(!current){$("msg").textContent="لم يتم إنشاء مكتبة ضيف بعد. افتح الإضافة واحفظ أول رابط.";return;}$("key").textContent=current;}
$("reveal").addEventListener("click",async()=>{if(!current)await load();$("key").style.display=current?"block":"none";});
$("copy").addEventListener("click",async()=>{if(!current)await load();if(!current)return;await navigator.clipboard.writeText(current);$("msg").textContent="تم نسخ المفتاح. احفظه في مكان آمن."});
$("download").addEventListener("click",async()=>{if(!current)await load();if(!current)return;const blob=new Blob([JSON.stringify({product:"AQX Favorites",type:"guest-recovery-key",created_at:new Date().toISOString(),recovery_key:current},null,2)],{type:"application/json"});const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download="aqx-favorites-recovery-key.json";a.click();URL.revokeObjectURL(url);$("msg").textContent="تم تجهيز ملف المفتاح. خزّنه في مكان خاص وآمن."});
load();
