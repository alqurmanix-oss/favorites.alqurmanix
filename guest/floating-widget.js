(()=>{'use strict';
const ORIGIN='https://favorites.alqurmanix.com';
const EMBED_URL=ORIGIN+'/guest/embed.html?mode=recent&v=1';
const LOADER_URL=ORIGIN+'/guest/floating-widget.js?v=1';
const HOME='https://alqurmanix.com/';
const loader=document.currentScript;
if(window.__AQX_FAVORITES_FLOATING_V1__)return;
window.__AQX_FAVORITES_FLOATING_V1__=true;
function mount(){
 if(!document.body)return;
 const frame=document.createElement('iframe');
 frame.src=EMBED_URL;
 frame.title='AQX Favorites - Recent';
 frame.width='60';frame.height='80';
 frame.setAttribute('allow','storage-access');
 frame.setAttribute('referrerpolicy','strict-origin-when-cross-origin');
 const compact='position:fixed;left:5px;top:50%;transform:translateY(-50%);width:60px;height:80px;border:0;z-index:2147483000;overflow:hidden;background:transparent;';
 const expanded='position:fixed;inset:0;width:100vw;height:100vh;height:100dvh;transform:none;border:0;z-index:2147483000;overflow:hidden;background:transparent;';
 frame.style.cssText=compact;
 document.body.appendChild(frame);
 let opened=false,redirecting=false;
 const redirect=()=>{if(redirecting)return;redirecting=true;window.location.replace(HOME)};
 function onMessage(event){
  if(event.origin!==ORIGIN||event.source!==frame.contentWindow)return;
  const type=event.data&&event.data.type;
  if(type==='aqx-favorites-open'){opened=true;frame.style.cssText=expanded;}
  else if(type==='aqx-favorites-close'){opened=false;frame.style.cssText=compact;}
  else if(type==='aqx-favorites-violation'){redirect();}
 }
 window.addEventListener('message',onMessage);
 // Redirect is triggered only by an explicit integrity violation
 // reported by the embedded widget for the required AQX brand/ad components.
 window.addEventListener('pagehide',()=>window.removeEventListener('message',onMessage),{once:true});
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',mount,{once:true});else mount();
})();