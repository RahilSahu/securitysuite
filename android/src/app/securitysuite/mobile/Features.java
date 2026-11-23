package app.securitysuite.mobile;

import android.util.Base64;

import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.zip.GZIPInputStream;

public class Features {

    // ---------- Decoder ----------
    public static String decode(String op, String in) throws Exception {
        switch (op) {
            case "Base64 decode": return new String(Base64.decode(in.trim(), Base64.DEFAULT), "UTF-8");
            case "Base64 encode": return Base64.encodeToString(in.getBytes("UTF-8"), Base64.NO_WRAP);
            case "URL decode": return URLDecoder.decode(in, "UTF-8");
            case "URL encode": return URLEncoder.encode(in, "UTF-8").replace("+", "%20");
            case "HTML decode": return htmlDecode(in);
            case "HTML encode": return in.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
            case "Hex decode": return new String(hexToBytes(in.replaceAll("\\s", "")), "UTF-8");
            case "Hex encode": return bytesToHex(in.getBytes("UTF-8"));
            case "Octal decode": {
                StringBuilder sb = new StringBuilder();
                for (String p : in.trim().split("\\s+")) sb.append((char) Integer.parseInt(p, 8));
                return sb.toString();
            }
            case "Binary decode": {
                StringBuilder sb = new StringBuilder();
                for (String p : in.trim().split("\\s+")) sb.append((char) Integer.parseInt(p, 2));
                return sb.toString();
            }
            case "GZIP decode (Base64 input)": {
                byte[] gz = Base64.decode(in.trim(), Base64.DEFAULT);
                GZIPInputStream g = new GZIPInputStream(new ByteArrayInputStream(gz));
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte[] buf = new byte[4096];
                int n;
                while ((n = g.read(buf)) > 0) bos.write(buf, 0, n);
                return new String(bos.toByteArray(), "UTF-8");
            }
            case "JWT decode": return jwtDecode(in.trim());
            case "MD5": return hash("MD5", in);
            case "SHA-1": return hash("SHA-1", in);
            case "SHA-256": return hash("SHA-256", in);
            case "SHA-512": return hash("SHA-512", in);
            case "Smart decode": return smartDecode(in.trim(), 0);
            default: return in;
        }
    }

    public static String[] DECODER_OPS = {
        "Base64 decode", "Base64 encode", "URL decode", "URL encode", "HTML decode", "HTML encode",
        "Hex decode", "Hex encode", "Octal decode", "Binary decode", "GZIP decode (Base64 input)",
        "JWT decode", "MD5", "SHA-1", "SHA-256", "SHA-512", "Smart decode"
    };

    private static String htmlDecode(String s) {
        return s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"")
                .replace("&#39;", "'").replace("&apos;", "'")
                .replaceAll("&#(\\d+);", "&#$1;") // numeric handled below simply
                .replace("&amp;", "&");
    }

    public static byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        return out;
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private static String hash(String algo, String in) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algo);
        return bytesToHex(md.digest(in.getBytes("UTF-8")));
    }

    private static String jwtDecode(String token) throws Exception {
        String[] parts = token.split("\\.");
        if (parts.length < 2) return "Not a JWT: needs at least header.payload";
        StringBuilder sb = new StringBuilder();
        sb.append("HEADER\n").append(prettyJson(new String(Base64.decode(pad(parts[0]), Base64.URL_SAFE), "UTF-8"))).append("\n\nPAYLOAD\n");
        sb.append(prettyJson(new String(Base64.decode(pad(parts[1]), Base64.URL_SAFE), "UTF-8")));
        sb.append("\n\nSIGNATURE\n").append(parts.length > 2 ? parts[2] : "(none)");
        try {
            JSONObject payload = new JSONObject(new String(Base64.decode(pad(parts[1]), Base64.URL_SAFE), "UTF-8"));
            sb.append("\n\nCHECKS\n");
            if (payload.has("exp")) {
                long exp = payload.getLong("exp");
                long now = System.currentTimeMillis() / 1000;
                sb.append("exp: ").append(exp).append(exp < now ? " (EXPIRED)" : " (valid)").append("\n");
            }
            if (payload.optString("alg").isEmpty()) { /* alg lives in header */ }
            JSONObject header = new JSONObject(new String(Base64.decode(pad(parts[0]), Base64.URL_SAFE), "UTF-8"));
            String alg = header.optString("alg", "");
            if (alg.equalsIgnoreCase("none")) sb.append("alg is 'none': signature may not be verified by weak servers, test it.\n");
            if (payload.has("isAdmin") || payload.has("admin") || payload.has("role")) sb.append("Privilege claims present (role/admin): test by modifying them in Repeater.\n");
        } catch (Exception ignored) { }
        return sb.toString();
    }

    private static String pad(String s) {
        while (s.length() % 4 != 0) s += "=";
        return s;
    }

    private static String prettyJson(String json) {
        try { return new JSONObject(json).toString(2); } catch (Exception e) { return json; }
    }

    private static String smartDecode(String in, int depth) {
        if (depth > 5) return in;
        String cur = in;
        // Try Base64 if it looks like it
        if (cur.matches("^[A-Za-z0-9+/=\\s]+$") && cur.replaceAll("\\s", "").length() % 4 == 0 && cur.length() >= 8) {
            try {
                String dec = new String(Base64.decode(cur, Base64.DEFAULT), "UTF-8");
                if (isPrintable(dec) && !dec.equals(cur)) return smartDecode(dec, depth + 1) + "\n[layer " + (depth + 1) + ": Base64]";
            } catch (Exception ignored) { }
        }
        if (cur.contains("%")) {
            try {
                String dec = URLDecoder.decode(cur, "UTF-8");
                if (!dec.equals(cur)) return smartDecode(dec, depth + 1) + "\n[layer " + (depth + 1) + ": URL]";
            } catch (Exception ignored) { }
        }
        if (cur.matches("^[0-9a-fA-F\\s]+$") && cur.replaceAll("\\s", "").length() % 2 == 0 && cur.length() >= 8) {
            try {
                String dec = new String(hexToBytes(cur.replaceAll("\\s", "")), "UTF-8");
                if (isPrintable(dec) && !dec.equals(cur)) return smartDecode(dec, depth + 1) + "\n[layer " + (depth + 1) + ": Hex]";
            } catch (Exception ignored) { }
        }
        return cur;
    }

    private static boolean isPrintable(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 32 && c != '\n' && c != '\r' && c != '\t') return false;
        }
        return true;
    }

    // ---------- Comparer ----------
    public static String wordDiff(String a, String b) {
        String[] wa = a.trim().split("\\s+");
        String[] wb = b.trim().split("\\s+");
        Set<String> setA = new HashSet<>();
        Set<String> setB = new HashSet<>();
        for (String w : wa) setA.add(w);
        for (String w : wb) setB.add(w);
        List<String> onlyA = new ArrayList<>();
        List<String> onlyB = new ArrayList<>();
        for (String w : wa) if (!setB.contains(w) && !onlyA.contains(w)) onlyA.add(w);
        for (String w : wb) if (!setA.contains(w) && !onlyB.contains(w)) onlyB.add(w);
        StringBuilder sb = new StringBuilder();
        sb.append("Words: left ").append(wa.length).append(", right ").append(wb.length).append("\n");
        sb.append("Unique words only in LEFT (").append(onlyA.size()).append("):\n");
        for (String w : onlyA) sb.append("- ").append(w).append("\n");
        sb.append("\nUnique words only in RIGHT (").append(onlyB.size()).append("):\n");
        for (String w : onlyB) sb.append("+ ").append(w).append("\n");
        return sb.toString();
    }

    public static String byteDiff(String a, String b) {
        byte[] x = a.getBytes(Charset.forName("UTF-8"));
        byte[] y = b.getBytes(Charset.forName("UTF-8"));
        int min = Math.min(x.length, y.length);
        int first = -1;
        int diffs = 0;
        for (int i = 0; i < min; i++) {
            if (x[i] != y[i]) { diffs++; if (first < 0) first = i; }
        }
        diffs += Math.abs(x.length - y.length);
        return "Bytes: left " + x.length + ", right " + y.length + "\nDiffering bytes: " + diffs
            + (first >= 0 ? "\nFirst difference at byte offset " + first : "\nNo difference in the common length");
    }

    // ---------- Sequencer ----------
    public static String tokenStats(List<String> tokens) {
        if (tokens.isEmpty()) return "No tokens captured.";
        StringBuilder sb = new StringBuilder();
        sb.append("Tokens captured: ").append(tokens.size()).append("\n");
        Set<String> uniq = new HashSet<>(tokens);
        sb.append("Unique: ").append(uniq.size()).append(uniq.size() == tokens.size() ? " (all unique)" : " (DUPLICATES FOUND, weak randomness or reuse)").append("\n");
        int min = Integer.MAX_VALUE, max = 0;
        Map<Character, Integer> freq = new HashMap<>();
        long totalChars = 0;
        for (String t : tokens) {
            min = Math.min(min, t.length());
            max = Math.max(max, t.length());
            for (char c : t.toCharArray()) { freq.put(c, freq.getOrDefault(c, 0) + 1); totalChars++; }
        }
        sb.append("Length: min ").append(min).append(", max ").append(max).append("\n");
        double entropy = 0;
        for (int count : freq.values()) {
            double p = (double) count / totalChars;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        sb.append(String.format(Locale.US, "Character entropy: %.2f bits per character", entropy)).append("\n");
        sb.append("Distinct characters used: ").append(freq.size()).append("\n");
        // Monotonicity for numeric tokens
        boolean allNumeric = true;
        long prev = Long.MIN_VALUE;
        boolean monotonic = true;
        for (String t : tokens) {
            try {
                long v = Long.parseLong(t.replaceAll("[^0-9-]", ""));
                if (v < prev) monotonic = false;
                prev = v;
            } catch (Exception e) { allNumeric = false; break; }
        }
        if (allNumeric) sb.append("Numeric sequence: ").append(monotonic ? "strictly increasing (predictable, test by guessing neighbours)" : "not monotonic").append("\n");
        if (entropy < 2.0) sb.append("Verdict: LOW entropy, tokens look predictable.\n");
        else if (entropy < 3.5) sb.append("Verdict: MODERATE entropy, check uniqueness and length before trusting these tokens.\n");
        else sb.append("Verdict: entropy looks healthy for the sample size. This is a quick statistical view, not a full Sequencer analysis.\n");
        return sb.toString();
    }

    // ---------- Passive scanner ----------
    public static List<String> passiveScan(Entry e) {
        List<String> issues = new ArrayList<>();
        if (e == null) return issues;
        String[] secHeaders = {"Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy"};
        for (String h : secHeaders) {
            boolean found = false;
            for (String[] rh : e.respHeaders) if (rh[0].equalsIgnoreCase(h)) { found = true; break; }
            if (!found) issues.add("[Info] Missing security header: " + h);
        }
        for (String[] rh : e.respHeaders) {
            String lk = rh[0].toLowerCase();
            if (lk.equals("access-control-allow-origin") && rh[1].trim().equals("*")) {
                issues.add("[Low] CORS: Access-Control-Allow-Origin is * (check if credentials are also allowed)");
            }
            if (lk.equals("set-cookie")) {
                String v = rh[1].toLowerCase();
                if (!v.contains("httponly")) issues.add("[Low] Cookie without HttpOnly flag: " + rh[1].split(";")[0]);
                if (!v.contains("secure") && e.url.startsWith("https")) issues.add("[Low] Cookie without Secure flag: " + rh[1].split(";")[0]);
                if (!v.contains("samesite")) issues.add("[Info] Cookie without SameSite: " + rh[1].split(";")[0]);
            }
            if (lk.equals("server") || lk.equals("x-powered-by")) {
                issues.add("[Info] Version disclosure header: " + rh[0] + ": " + rh[1]);
            }
        }
        String body = e.respBodyText == null ? "" : e.respBodyText;
        String[] secretHints = {"api_key", "apikey", "access_token", "private key", "BEGIN RSA", "BEGIN PRIVATE", "aws_secret", "password\""};
        for (String s : secretHints) {
            if (body.toLowerCase().contains(s.toLowerCase())) issues.add("[Medium?] Possible secret or token pattern in response body: " + s + " (verify manually)");
        }
        if (e.url.startsWith("http://")) issues.add("[Info] Target is plain HTTP, traffic is not encrypted");
        if (issues.isEmpty()) issues.add("No passive issues found in this response.");
        return issues;
    }

    // ---------- Match and replace ----------
    // rulesText lines: req|match|replace  or  resp|match|replace  (plain contains, case-sensitive)
    public static String applyMatchReplace(String rulesText, boolean request, String input) {
        if (rulesText == null || input == null) return input;
        String out = input;
        for (String line : rulesText.split("\n")) {
            String[] parts = line.split("\\|", 3);
            if (parts.length < 3) continue;
            boolean isReq = parts[0].trim().equalsIgnoreCase("req");
            if (isReq != request) continue;
            if (!parts[1].isEmpty()) out = out.replace(parts[1], parts[2]);
        }
        return out;
    }
}
