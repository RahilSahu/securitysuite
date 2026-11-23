package app.securitysuite.mobile;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Store {
    public static final List<Entry> history = new ArrayList<>();
    public static final List<Entry> queue = new ArrayList<>();
    private static final Map<String, String> bodies = new HashMap<>();
    private static final List<Runnable> listeners = new ArrayList<>();
    private static long nextId = 1;

    public static synchronized long nextId() { return nextId++; }

    public static void addListener(Runnable r) { listeners.add(r); }

    public static void changed() {
        List<Runnable> copy;
        synchronized (Store.class) { copy = new ArrayList<>(listeners); }
        for (Runnable r : copy) r.run();
    }

    public static void addHistory(Entry e) {
        synchronized (history) {
            history.add(0, e);
            while (history.size() > 500) history.remove(history.size() - 1);
        }
        changed();
    }

    public static void hold(Entry e) {
        synchronized (queue) { queue.add(e); }
        changed();
    }

    public static void unhold(Entry e) {
        synchronized (queue) { queue.remove(e); }
        changed();
    }

    public static Entry firstHeld() {
        synchronized (queue) { return queue.isEmpty() ? null : queue.get(0); }
    }

    public static void clearHistory() {
        synchronized (history) { history.clear(); }
        changed();
    }

    // ---- JS body bridge ----
    public static void putBodyJson(String json) {
        try {
            JSONObject o = new JSONObject(json);
            String key = o.optString("method", "GET").toUpperCase() + " " + o.optString("url", "");
            String body = o.optString("body", "");
            synchronized (bodies) { bodies.put(key, body); }
        } catch (Exception ignored) { }
    }

    // Wait briefly for the page shim to report the body for this request.
    public static String takeBody(String method, String url) {
        String key = method.toUpperCase() + " " + url;
        for (int i = 0; i < 10; i++) {
            synchronized (bodies) {
                if (bodies.containsKey(key)) return bodies.remove(key);
            }
            try { Thread.sleep(80); } catch (InterruptedException e) { return null; }
        }
        return null;
    }
}
