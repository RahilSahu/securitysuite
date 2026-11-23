package app.securitysuite.mobile;

import android.content.SharedPreferences;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

// Intercept skip / scope rules, Burp-style: matching requests are forwarded
// automatically without being held, but are still logged in History.
public class Rules {
    public static boolean enabled = true;
    public static List<String> skipHosts = new ArrayList<>();
    public static List<String> skipIps = new ArrayList<>();
    public static List<String> skipPaths = new ArrayList<>();
    public static List<String> skipExts = new ArrayList<>();
    public static List<String> skipMethods = new ArrayList<>();
    public static List<String> onlyHosts = new ArrayList<>(); // scope: if non-empty, hold only these

    public static void load(SharedPreferences p) {
        enabled = p.getBoolean("rulesEnabled", true);
        skipHosts = split(p.getString("skipHosts", ""));
        skipIps = split(p.getString("skipIps", ""));
        skipPaths = split(p.getString("skipPaths", ""));
        skipExts = split(p.getString("skipExts", ".png\n.jpg\n.jpeg\n.gif\n.webp\n.svg\n.ico\n.woff\n.woff2\n.ttf"));
        skipMethods = split(p.getString("skipMethods", ""));
        onlyHosts = split(p.getString("onlyHosts", ""));
    }

    public static void save(SharedPreferences p) {
        SharedPreferences.Editor ed = p.edit();
        ed.putBoolean("rulesEnabled", enabled);
        ed.putString("skipHosts", join(skipHosts));
        ed.putString("skipIps", join(skipIps));
        ed.putString("skipPaths", join(skipPaths));
        ed.putString("skipExts", join(skipExts));
        ed.putString("skipMethods", join(skipMethods));
        ed.putString("onlyHosts", join(onlyHosts));
        ed.apply();
    }

    public static List<String> split(String s) {
        List<String> out = new ArrayList<>();
        if (s == null) return out;
        for (String line : s.split("\n")) {
            String t = line.trim();
            if (!t.isEmpty()) out.add(t);
        }
        return out;
    }

    public static String join(List<String> list) {
        StringBuilder sb = new StringBuilder();
        for (String s : list) sb.append(s).append("\n");
        return sb.toString();
    }

    public static boolean hostMatches(String host, String pattern) {
        String h = host.toLowerCase();
        String p = pattern.toLowerCase().trim();
        if (p.startsWith("*.")) {
            String suffix = p.substring(1); // .example.com
            return h.endsWith(suffix) || h.equals(p.substring(2));
        }
        return h.equals(p) || h.endsWith("." + p);
    }

    public static boolean ipMatches(String host, String pattern) {
        String p = pattern.trim();
        try {
            if (p.contains("/")) {
                String[] parts = p.split("/");
                long base = ipToLong(parts[0]);
                int bits = Integer.parseInt(parts[1]);
                long ip = ipToLong(host);
                if (base < 0 || ip < 0) return false;
                long mask = bits == 0 ? 0 : (0xFFFFFFFFL << (32 - bits)) & 0xFFFFFFFFL;
                return (base & mask) == (ip & mask);
            }
            return host.equals(p);
        } catch (Exception e) {
            return false;
        }
    }

    private static long ipToLong(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return -1;
        long v = 0;
        for (String part : parts) {
            int n = Integer.parseInt(part);
            if (n < 0 || n > 255) return -1;
            v = (v << 8) + n;
        }
        return v;
    }

    // Returns a human reason if this entry should NOT be held, or null if it may be held.
    public static String skipReason(Entry e) {
        if (!enabled) return null;
        String host = "";
        String path = "";
        try {
            URL u = new URL(e.url);
            host = u.getHost() == null ? "" : u.getHost();
            path = u.getPath() == null ? "" : u.getPath();
        } catch (Exception ignored) { }

        for (String m : skipMethods) {
            if (e.method.equalsIgnoreCase(m.trim())) return "rule: skip method " + m;
        }
        for (String h : skipHosts) {
            if (hostMatches(host, h)) return "rule: skip host " + h;
        }
        for (String ip : skipIps) {
            if (ipMatches(host, ip)) return "rule: skip IP " + ip;
        }
        for (String p : skipPaths) {
            if (!p.isEmpty() && (e.url.contains(p) || path.contains(p))) return "rule: skip path " + p;
        }
        String lower = e.url.toLowerCase();
        for (String ext : skipExts) {
            String x = ext.trim().toLowerCase();
            if (!x.isEmpty() && lower.split("\\?")[0].endsWith(x)) return "rule: skip extension " + x;
        }
        if (!onlyHosts.isEmpty()) {
            boolean inScope = false;
            for (String h : onlyHosts) if (hostMatches(host, h)) { inScope = true; break; }
            if (!inScope) return "rule: host out of scope";
        }
        return null;
    }
}
