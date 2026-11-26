(()=>{'use strict';
const ORIGIN='https://favorites.alqurmanix.com';
const EMBED_URL=ORIGIN+'/guest/embed.html?mode=recent&v=3';
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
 frame.dataset.aqxFavoritesFrame='1';
 frame.style.cssText=compact;
 document.body.appendChild(frame);
 let opened=false,redirecting=false,watchdog=null;
 const loaderParent=loader&&loader.parentNode;
 const redirect=()=>{if(redirecting)return;redirecting=true;if(watchdog)clearInterval(watchdog);window.location.replace(HOME)};
 function intact(){
  if(redirecting)return;
  const s=frame.style,cs=getComputedStyle(frame);
  const styleValid=s.position==='fixed'&&s.width===(opened?'100vw':'60px')&&s.height===(opened?'100dvh':'80px')&&s.transform===(opened?'none':'translateY(-50%)')&&s.zIndex==='2147483000'&&s.overflow==='hidden'&&s.borderWidth==='0px'&&s.backgroundColor==='transparent'&&(opened?(s.left==='0px'&&s.top==='0px'&&s.right==='0px'&&s.bottom==='0px'):(s.left==='5px'&&s.top==='50%'&&s.right===''&&s.bottom===''));
  const valid=!!loader&&loader.isConnected&&loader.parentNode===loaderParent&&frame.isConnected&&frame.parentElement===document.body&&document.querySelectorAll('iframe[data-aqx-favorites-frame="1"]').length===1&&frame.getAttribute('data-aqx-favorites-frame')==='1'&&frame.getAttribute('src')===EMBED_URL&&frame.title==='AQX Favorites - Recent'&&frame.getAttribute('allow')==='storage-access'&&frame.getAttribute('referrerpolicy')==='strict-origin-when-cross-origin'&&frame.getAttribute('width')==='60'&&frame.getAttribute('height')==='80'&&styleValid&&cs.position==='fixed'&&cs.display!=='none'&&cs.visibility!=='hidden'&&cs.visibility!=='collapse'&&Number(cs.opacity)>0&&cs.zIndex==='2147483000'&&cs.overflow==='hidden'&&cs.borderTopWidth==='0px';
  if(!valid)redirect();
 }
 const watch=(target,options)=>{if(!target)return null;const observer=new MutationObserver(intact);observer.observe(target,options);return observer};
 const bodyObserver=watch(document.body,{childList:true});
 const rootObserver=watch(document.documentElement,{childList:true});
 const frameObserver=watch(frame,{attributes:true,attributeFilter:['src','style','title','allow','referrerpolicy','width','height','data-aqx-favorites-frame']});
 const loaderObserver=watch(loaderParent,{childList:true});
 intact();
 // MutationObserver provides immediate detection; this low-frequency check
 // is a backup for DOM/CSS interference that does not produce observed mutations.
 watchdog=setInterval(intact,1000);
 function onMessage(event){
  if(event.origin!==ORIGIN||event.source!==frame.contentWindow)return;
  const type=event.data&&event.data.type;
  if(type==='aqx-favorites-open'){opened=true;frame.style.cssText=expanded;intact();}
  else if(type==='aqx-favorites-close'){opened=false;frame.style.cssText=compact;intact();}
  else if(type==='aqx-favorites-violation'){redirect();}
 }
 window.addEventListener('message',onMessage);
 // Redirect is triggered only by an explicit integrity violation
 // reported by the embedded widget for the required AQX brand/ad components.
 window.addEventListener('pagehide',()=>{window.removeEventListener('message',onMessage);if(watchdog)clearInterval(watchdog);[bodyObserver,rootObserver,frameObserver,loaderObserver].forEach(o=>o&&o.disconnect())},{once:true});
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',mount,{once:true});else mount();
})();