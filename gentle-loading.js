/* GentleLogs shared micro-navigation feedback. No artificial delay is added. */
(function(){
  if(document.getElementById("gentleNavFeedback"))return;
  var style=document.createElement("style");style.textContent="#gentleNavFeedback{position:fixed;right:15px;bottom:18px;z-index:99990;background:#10233a;color:#fff;border-radius:24px;padding:9px 13px;font:12px Arial,sans-serif;display:none;align-items:center;gap:8px;box-shadow:0 6px 20px #0002}#gentleNavFeedback.show{display:flex}#gentleNavFeedback i{color:#8bd49e}";document.head.appendChild(style);
  var box=document.createElement("div");box.id="gentleNavFeedback";box.innerHTML='<i class="fa-solid fa-circle-notch fa-spin"></i><span>Opening…</span>';document.body.appendChild(box);
  document.addEventListener("click",function(e){var a=e.target.closest&&e.target.closest('a[href]');if(!a||a.target==="_blank"||e.defaultPrevented||e.metaKey||e.ctrlKey||e.shiftKey||e.altKey)return;var href=a.getAttribute("href")||"";if(/^(https?:|mailto:|tel:|#|javascript:)/i.test(href))return;if(!/\.html(?:[?#]|$)/i.test(href))return;box.classList.add("show");});
})();
