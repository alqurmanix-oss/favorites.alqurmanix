const $=id=>document.getElementById(id);
function send(type,extra={}){return chrome.runtime.sendMessage({type,...extra});}
function show(message){$("message").textContent=message;}
async function refresh(){const r=await send("AQX_STATUS");if(!r?.ok)return;$("connection").textContent=r.connected?"مكتبة مرتبطة":"لم تُنشأ جلسة";$("pending").textContent=r.pending;$("sync").disabled=!r.pending;}
$("save").addEventListener("click",async()=>{const b=$("save");b.disabled=true;show("جارٍ حفظ الصفحة…");const r=await send("AQX_SAVE_CURRENT");show(r?.ok?r.result.message:r?.error||"تعذر الحفظ.");await refresh();b.disabled=false;});
$("sync").addEventListener("click",async()=>{const r=await send("AQX_FLUSH");show(r?.ok?("تمت مزامنة "+r.result.synced+" عنصر، والمتبقي "+r.result.pending+"."):r?.error);await refresh();});
$("recover").addEventListener("click",async()=>{const token=$("recovery").value.trim();if(!token){show("أدخل مفتاح الاسترداد أولاً.");return;}const r=await send("AQX_RECOVER",{token});show(r?.ok?r.message:r?.error||"تعذر الاسترداد.");if(r?.ok)$("recovery").value="";await refresh();});
refresh();
