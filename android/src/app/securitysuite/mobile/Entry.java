package app.securitysuite.mobile;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;

public class Entry {
    public static final int STATE_HELD = 0;
    public static final int STATE_COMPLETED = 1;
    public static final int STATE_DROPPED = 2;
    public static final int STATE_PASSTHROUGH = 3;

    public long id;
    public String time = "";
    public String method = "GET";
    public String url = "";
    public List<String[]> reqHeaders = new ArrayList<>();
    public String reqBody;
    public boolean mainFrame;
    public String source = "browser"; // browser | repeater | native

    public int state = STATE_COMPLETED;
    public Integer status;
    public List<String[]> respHeaders = new ArrayList<>();
    public String respBodyText;
    public String error;
    public String note;

    public final CountDownLatch latch = new CountDownLatch(1);
    public boolean dropDecision = false;

    public String headerValue(String name) {
        for (String[] h : reqHeaders) {
            if (h[0] != null && h[0].equalsIgnoreCase(name)) return h[1];
        }
        return null;
    }

    public String label() {
        String s = method + "  " + url;
        if (state == STATE_HELD) s += "   [HELD]";
        else if (state == STATE_DROPPED) s += "   [DROPPED]";
        else if (status != null) s += "   " + status;
        if (error != null) s += "   [ERR]";
        return s + "   " + time;
    }

    public String headersToText(List<String[]> headers) {
        StringBuilder sb = new StringBuilder();
        for (String[] h : headers) sb.append(h[0]).append(": ").append(h[1]).append("\n");
        return sb.toString();
    }

    public static List<String[]> parseHeaders(String text) {
        List<String[]> out = new ArrayList<>();
        if (text == null) return out;
        for (String line : text.split("\n")) {
            int i = line.indexOf(":");
            if (i > 0) out.add(new String[]{line.substring(0, i).trim(), line.substring(i + 1).trim()});
        }
        return out;
    }
}
