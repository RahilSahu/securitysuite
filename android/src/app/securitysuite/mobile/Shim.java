package app.securitysuite.mobile;

public class Shim {
    // Injected at the top of HTML pages served by the intercepting engine.
    // Reports fetch / XHR / form bodies to the app before the requests fire,
    // because Android WebView never exposes request bodies itself.
    public static final String JS =
        "<script>(function(){try{" +
        "function abs(u){try{return new URL(u,location.href).href}catch(e){return u}}" +
        "function R(m,u,b){try{window.SSBridge&&SSBridge.reportBody(JSON.stringify({method:(m||'GET').toUpperCase(),url:abs(u||''),body:(typeof b==='string')?b:''}))}catch(e){}}" +
        "function enc(b){try{if(typeof b==='string')return b;if(b instanceof URLSearchParams)return b.toString();if(b instanceof FormData){var p=[];b.forEach(function(v,k){p.push(encodeURIComponent(k)+'='+encodeURIComponent(v))});return p.join('&')}return ''}catch(e){return ''}}" +
        "var of=window.fetch;if(of){window.fetch=function(i,init){try{var m='GET',u='',b='';if(typeof i==='string'){u=i}else if(i&&i.url){u=i.url;m=i.method||m}if(init){if(init.method)m=init.method;if(init.body!=null)b=enc(init.body)}R(m,u,b)}catch(e){}return of.apply(this,arguments)}}" +
        "var oo=XMLHttpRequest.prototype.open,os=XMLHttpRequest.prototype.send;" +
        "XMLHttpRequest.prototype.open=function(m,u){this.__ssm=m;this.__ssu=u;return oo.apply(this,arguments)};" +
        "XMLHttpRequest.prototype.send=function(b){try{R(this.__ssm||'GET',this.__ssu||'',enc(b))}catch(e){}return os.apply(this,arguments)};" +
        "document.addEventListener('submit',function(ev){try{var f=ev.target;var p=[];new FormData(f).forEach(function(v,k){p.push(encodeURIComponent(k)+'='+encodeURIComponent(v))});R((f.method||'GET'),f.action||location.href,p.join('&'))}catch(e){}},true);" +
        "if(navigator.sendBeacon){var ob=navigator.sendBeacon.bind(navigator);navigator.sendBeacon=function(u,b){try{R('POST',u,enc(b))}catch(e){}return ob(u,b)}}" +
        "}catch(e){}})();</script>";

    public static byte[] inject(byte[] body, String charset) {
        try {
            String html = new String(body, charset == null ? "UTF-8" : charset);
            String lower = html.toLowerCase();
            int headEnd = lower.indexOf("<head>");
            String out;
            if (headEnd >= 0) {
                int pos = headEnd + "<head>".length();
                out = html.substring(0, pos) + JS + html.substring(pos);
            } else {
                out = JS + html;
            }
            return out.getBytes(charset == null ? "UTF-8" : charset);
        } catch (Exception e) {
            return body;
        }
    }
}
