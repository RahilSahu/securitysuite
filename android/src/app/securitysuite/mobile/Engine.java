package app.securitysuite.mobile;

import android.webkit.CookieManager;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class Engine {
    public static class Result {
        public int status;
        public String reason = "";
        public List<String[]> headers = new ArrayList<>();
        public byte[] body = new byte[0];
        public String mime = "text/plain";
        public String charset = "utf-8";
        public String contentType;
    }

    private static final int MAX_STORE_CHARS = 256 * 1024;

    // User settings (Settings section in Rules tab)
    public static String upstreamHost = "";
    public static int upstreamPort = 0;
    public static String uaOverride = "";
    public static int timeoutSec = 20;

    // Performs the entry's request with our own HTTP engine and fills in the response.
    public static Result fetch(Entry e) throws Exception {
        HttpURLConnection conn;
        if (upstreamHost != null && !upstreamHost.isEmpty() && upstreamPort > 0) {
            java.net.Proxy proxy = new java.net.Proxy(java.net.Proxy.Type.HTTP,
                    new java.net.InetSocketAddress(upstreamHost, upstreamPort));
            conn = (HttpURLConnection) new URL(e.url).openConnection(proxy);
        } else {
            conn = (HttpURLConnection) new URL(e.url).openConnection();
        }
        conn.setInstanceFollowRedirects(false);
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(Math.max(5, timeoutSec) * 1000);
        if (uaOverride != null && !uaOverride.isEmpty()) conn.setRequestProperty("User-Agent", uaOverride);
        setMethod(conn, e.method);

        CookieManager cm = CookieManager.getInstance();
        boolean hasCookie = false;
        boolean hasContentType = false;
        for (String[] h : e.reqHeaders) {
            String lk = h[0].toLowerCase();
            if (lk.equals("host") || lk.equals("content-length") || lk.equals("connection")
                    || lk.equals("accept-encoding")) continue;
            if (lk.equals("cookie")) { hasCookie = true; continue; } // replaced by CookieManager below
            if (lk.equals("content-type")) hasContentType = true;
            try { conn.setRequestProperty(h[0], h[1]); } catch (Exception ignored) { }
        }
        String cookie = null;
        try { cookie = cm.getCookie(e.url); } catch (Exception ignored) { }
        if (cookie != null && !cookie.isEmpty()) conn.setRequestProperty("Cookie", cookie);
        else if (hasCookie) {
            String c = e.headerValue("Cookie");
            if (c != null) conn.setRequestProperty("Cookie", c);
        }

        if (e.reqBody != null && !e.reqBody.isEmpty()
                && !e.method.equals("GET") && !e.method.equals("HEAD")) {
            byte[] bytes = e.reqBody.getBytes(Charset.forName("UTF-8"));
            conn.setDoOutput(true);
            if (!hasContentType) conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            OutputStream os = conn.getOutputStream();
            os.write(bytes);
            os.close();
        }

        Result r = new Result();
        r.status = conn.getResponseCode();
        String msg = conn.getResponseMessage();
        r.reason = (msg == null || msg.isEmpty()) ? defaultReason(r.status) : msg;

        for (Map.Entry<String, List<String>> en : conn.getHeaderFields().entrySet()) {
            if (en.getKey() == null) continue;
            for (String v : en.getValue()) {
                r.headers.add(new String[]{en.getKey(), v});
                if (en.getKey().equalsIgnoreCase("Set-Cookie")) {
                    try { cm.setCookie(e.url, v); } catch (Exception ignored) { }
                }
                if (en.getKey().equalsIgnoreCase("Content-Type")) r.contentType = v;
            }
        }
        try { cm.flush(); } catch (Exception ignored) { }

        InputStream is = null;
        try { is = r.status >= 400 ? conn.getErrorStream() : conn.getInputStream(); } catch (Exception ignored) { }
        if (is != null) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) > 0) bos.write(buf, 0, n);
            is.close();
            r.body = bos.toByteArray();
        }

        if (r.contentType != null) {
            String ct = r.contentType;
            int semi = ct.indexOf(';');
            r.mime = (semi > 0 ? ct.substring(0, semi) : ct).trim().toLowerCase();
            int ci = ct.toLowerCase().indexOf("charset=");
            if (ci > 0) r.charset = ct.substring(ci + 8).split("[; ]")[0].trim();
        }

        // Fill the entry for History / detail views
        e.status = r.status;
        e.respHeaders = filterForView(r.headers);
        e.respBodyText = bodyTextForStore(r);
        return r;
    }

    public static List<String[]> filterForView(List<String[]> headers) {
        List<String[]> out = new ArrayList<>();
        for (String[] h : headers) out.add(h);
        return out;
    }

    // Headers safe to hand back to WebView (body is already decoded and re-served by us)
    public static Map<String, String> headersForWebView(Result r) {
        java.util.LinkedHashMap<String, String> out = new java.util.LinkedHashMap<>();
        for (String[] h : r.headers) {
            String lk = h[0].toLowerCase();
            if (lk.equals("content-encoding") || lk.equals("content-length")
                    || lk.equals("transfer-encoding")
                    || lk.equals("content-security-policy") || lk.equals("content-security-policy-report-only")
                    || lk.equals("x-frame-options")) continue;
            out.put(h[0], h[1]);
        }
        return out;
    }

    public static String bodyTextForStore(Result r) {
        if (r.body == null || r.body.length == 0) return "";
        String m = r.mime == null ? "" : r.mime;
        boolean textish = m.startsWith("text/") || m.contains("json") || m.contains("xml")
                || m.contains("javascript") || m.contains("html");
        if (!textish) return "[binary body, " + r.body.length + " bytes]";
        String s;
        try { s = new String(r.body, Charset.forName(r.charset)); }
        catch (Exception e) { s = new String(r.body, Charset.forName("UTF-8")); }
        if (s.length() > MAX_STORE_CHARS) s = s.substring(0, MAX_STORE_CHARS) + "\n[truncated for storage]";
        return s;
    }

    private static void setMethod(HttpURLConnection conn, String method) throws Exception {
        try {
            conn.setRequestMethod(method);
        } catch (java.net.ProtocolException pe) {
            // PATCH and friends: try the reflection workaround, may fail on newer Android
            try {
                java.lang.reflect.Field f = null;
                Class<?> c = conn.getClass();
                while (c != null && f == null) {
                    try { f = c.getDeclaredField("method"); } catch (NoSuchFieldException nf) { c = c.getSuperclass(); }
                }
                if (f == null) throw pe;
                f.setAccessible(true);
                f.set(conn, method);
            } catch (Exception reflectionFail) {
                throw new Exception("Method " + method + " is not supported by the Android HTTP engine");
            }
        }
    }

    public static String defaultReason(int status) {
        switch (status) {
            case 200: return "OK";
            case 201: return "Created";
            case 204: return "No Content";
            case 301: return "Moved Permanently";
            case 302: return "Found";
            case 303: return "See Other";
            case 304: return "Not Modified";
            case 307: return "Temporary Redirect";
            case 308: return "Permanent Redirect";
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 405: return "Method Not Allowed";
            case 500: return "Internal Server Error";
            case 502: return "Bad Gateway";
            case 503: return "Service Unavailable";
            default: return status >= 200 && status < 300 ? "OK" : "Status";
        }
    }
}
