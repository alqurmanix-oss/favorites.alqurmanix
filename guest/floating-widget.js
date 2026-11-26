(()=>{'use strict';
const ORIGIN='https://favorites.alqurmanix.com';
const EMBED_URL=ORIGIN+'/guest/embed.html?mode=recent&v=9';
const loader=document.currentScript;
if(window.__AQX_FAVORITES_FLOATING_V1__)return;
window.__AQX_FAVORITES_FLOATING_V1__=true;
function redirect(){if(window.__AQX_FAVORITES_REDIRECTING__)return;window.__AQX_FAVORITES_REDIRECTING__=true;window.location.replace('https://alqurmanix.com/');}
function mount(){
 if(!document.documentElement)return;
 const frame=document.createElement('iframe');
 frame.src=EMBED_URL;
 frame.loading='eager';
 frame.title='AQX Favorites - Recent';
 frame.width='60';frame.height='80';
 frame.setAttribute('allow','storage-access');
 frame.setAttribute('referrerpolicy','strict-origin-when-cross-origin');
 const compact='position:fixed;left:5px;top:50%;transform:translateY(-50%);width:60px;height:80px;border:0;z-index:2147483000;overflow:hidden;background:transparent;';
 const expanded='position:fixed;inset:0;width:100vw;height:100vh;height:100dvh;transform:none;border:0;z-index:2147483000;overflow:hidden;background:transparent;';
 frame.dataset.aqxFavoritesFrame='1';
 frame.style.cssText=compact+'visibility:hidden;';
 const launcher=document.createElement('button');
 launcher.type='button';launcher.textContent='♡';launcher.setAttribute('aria-label','آخر محفوظاتي');launcher.title='آخر محفوظاتي';
 launcher.style.cssText='position:fixed;left:11px;top:calc(50% - 24px);width:48px;height:48px;border:0;border-radius:50%;z-index:2147483001;background:linear-gradient(135deg,#6d4bd1,#9277e6);color:#fff;font:28px Tahoma,Arial,sans-serif;box-shadow:0 5px 18px #34205b55;cursor:pointer;';
 document.documentElement.appendChild(launcher);
 document.documentElement.appendChild(frame);
 let pendingOpen=false;
 launcher.addEventListener('click',()=>{pendingOpen=true;if(frame.dataset.ready==='1'){frame.contentWindow.postMessage({type:'aqx-favorites-parent-open'},ORIGIN);pendingOpen=false;}});
 frame.addEventListener('load',()=>{frame.dataset.ready='1';frame.style.visibility='visible';launcher.remove();if(pendingOpen){frame.contentWindow.postMessage({type:'aqx-favorites-parent-open'},ORIGIN);pendingOpen=false;}},{once:true});
 let opened=false,integrityArmed=false;
 const loaderParent=loader&&loader.parentNode;
 function intact(){
  // The iframe is only the carrier for AQX's three protected elements.
  // Do not inspect publisher page, save button, saved-items loading, or styles.
  if(integrityArmed&&!frame.isConnected)redirect();
 }
 const watch=(target,options)=>{if(!target)return null;const observer=new MutationObserver(intact);observer.observe(target,options);return observer};
 const rootObserver=watch(document.documentElement,{childList:true});

 // Do not observe the loader's parent: it may be BODY and receive unrelated
 // publisher widgets during startup. Those normal insertions are not tampering.
 frame.addEventListener('load',()=>{integrityArmed=true;intact()},{once:true});
 // Root and frame observers detect removal or attribute changes without polling.
 function onMessage(event){
  if(event.origin!==ORIGIN||event.source!==frame.contentWindow)return;
  const type=event.data&&event.data.type;
  if(type==='aqx-favorites-tamper'){redirect();}
  else if(type==='aqx-favorites-open'){opened=true;frame.style.cssText=expanded;intact();}
  else if(type==='aqx-favorites-close'){opened=false;frame.style.cssText=compact;intact();}
 }
 window.addEventListener('message',onMessage);
 window.addEventListener('pagehide',()=>{window.removeEventListener('message',onMessage);[rootObserver].forEach(o=>o&&o.disconnect())},{once:true});
}
mount();
})();