package app.securitysuite.mobile;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.EditorInfo;
import android.webkit.JavascriptInterface;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import android.widget.ToggleButton;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class MainActivity extends Activity {

    private static final String SUITE_URL = "https://securitysuite-woad.vercel.app";
    private static final int BG = Color.rgb(10, 14, 19);
    private static final int PANEL = Color.rgb(18, 26, 36);
    private static final int PANEL2 = Color.rgb(24, 34, 48);
    private static final int ORANGE = Color.rgb(255, 106, 26);
    private static final int TEXT = Color.rgb(232, 238, 245);
    private static final int MUTED = Color.rgb(157, 176, 195);

    private WebView suiteWeb;
    private WebView browserWeb;
    private FrameLayout stage;
    private LinearLayout browserChrome;
    private EditText urlInput;
    private ToggleButton interceptToggle;
    private ToggleButton modeToggle;
    private ToggleButton scopeToggle;

    private LinearLayout sheet;
    private TextView sheetText;

    private LinearLayout historyPanel;
    private ListView historyList;
    private TextView historyInfo;
    private ArrayAdapter<String> historyAdapter;
    private final List<String> historyLabels = new ArrayList<>();

    private LinearLayout interceptPanel;
    private ListView queueList;
    private TextView interceptInfo;
    private ArrayAdapter<String> queueAdapter;
    private final List<String> queueLabels = new ArrayList<>();

    private LinearLayout editorPanel;
    private EditText edUrl, edHeaders, edBody;
    private TextView edTitle;
    private Entry editingEntry;

    private LinearLayout detailPanel;
    private TextView detailText;
    private Entry detailEntry;

    private LinearLayout repeaterPanel;
    private EditText rpMethod, rpUrl, rpHeaders, rpBody, rpResponse;

    private Button tabSuite, tabBrowser, tabIntercept, tabHistory, tabRepeater;
    private int currentTab = 0; // 0 suite, 1 browser, 2 intercept, 3 history, 4 repeater
    private final SimpleDateFormat timeFmt = new SimpleDateFormat("HH:mm:ss", Locale.US);

    public class BodyBridge {
        @JavascriptInterface
        public void reportBody(String json) { Store.putBodyJson(json); }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BG);

        // ---- Browser chrome: address bar + transport controls ----
        browserChrome = new LinearLayout(this);
        browserChrome.setOrientation(LinearLayout.VERTICAL);
        browserChrome.setBackgroundColor(PANEL);
        browserChrome.setPadding(10, 8, 10, 8);
        LinearLayout urlRow = new LinearLayout(this);
        urlRow.setOrientation(LinearLayout.HORIZONTAL);
        urlInput = new EditText(this);
        urlInput.setSingleLine(true);
        urlInput.setTextColor(TEXT);
        urlInput.setHintTextColor(MUTED);
        urlInput.setHint("https://your-target.example");
        urlInput.setImeOptions(EditorInfo.IME_ACTION_GO);
        urlInput.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        urlInput.setOnEditorActionListener((v, a, e) -> { navigateBrowser(); return true; });
        Button goBtn = smallButton("Go");
        goBtn.setOnClickListener(v -> navigateBrowser());
        urlRow.addView(urlInput);
        urlRow.addView(goBtn);
        browserChrome.addView(urlRow);
        LinearLayout modeRow = new LinearLayout(this);
        modeRow.setOrientation(LinearLayout.HORIZONTAL);
        modeToggle = toggle("Mode: Proxy", "Mode: Native");
        modeToggle.setChecked(true);
        interceptToggle = toggle("Intercept: ON", "Intercept: OFF");
        interceptToggle.setChecked(true);
        scopeToggle = toggle("Scope: Smart", "Scope: All");
        scopeToggle.setChecked(true);
        modeRow.addView(modeToggle);
        modeRow.addView(interceptToggle);
        modeRow.addView(scopeToggle);
        browserChrome.addView(modeRow);
        browserChrome.setVisibility(View.GONE);
        root.addView(browserChrome);

        // ---- Stage ----
        stage = new FrameLayout(this);
        stage.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        root.addView(stage);

        suiteWeb = makeWebView(false);
        suiteWeb.setWebViewClient(new WebViewClient());
        suiteWeb.loadUrl(SUITE_URL);
        stage.addView(suiteWeb);

        browserWeb = makeWebView(true);
        browserWeb.addJavascriptInterface(new BodyBridge(), "SSBridge");
        browserWeb.setVisibility(View.GONE);
        browserWeb.setWebViewClient(new ProxyClient());
        stage.addView(browserWeb);

        buildHistoryPanel();
        buildInterceptPanel();
        buildEditorPanel();
        buildDetailPanel();
        buildRepeaterPanel();
        buildSheet();
        stage.addView(historyPanel);
        stage.addView(interceptPanel);
        stage.addView(repeaterPanel);
        stage.addView(detailPanel);
        stage.addView(editorPanel);
        stage.addView(sheet);

        // ---- Bottom tabs ----
        LinearLayout tabs = new LinearLayout(this);
        tabs.setOrientation(LinearLayout.HORIZONTAL);
        tabs.setBackgroundColor(PANEL);
        tabSuite = tab("Suite");
        tabBrowser = tab("Browser");
        tabIntercept = tab("Intercept");
        tabHistory = tab("History");
        tabRepeater = tab("Repeater");
        tabSuite.setOnClickListener(v -> showTab(0));
        tabBrowser.setOnClickListener(v -> showTab(1));
        tabIntercept.setOnClickListener(v -> showTab(2));
        tabHistory.setOnClickListener(v -> showTab(3));
        tabRepeater.setOnClickListener(v -> showTab(4));
        tabs.addView(tabSuite);
        tabs.addView(tabBrowser);
        tabs.addView(tabIntercept);
        tabs.addView(tabHistory);
        tabs.addView(tabRepeater);
        root.addView(tabs);

        setContentView(root);
        Store.addListener(() -> runOnUiThread(this::refreshUi));
        showTab(0);
        refreshUi();
    }

    // ================= Panels =================

    private void buildSheet() {
        sheet = new LinearLayout(this);
        sheet.setOrientation(LinearLayout.VERTICAL);
        sheet.setBackgroundColor(PANEL2);
        sheet.setPadding(14, 10, 14, 10);
        FrameLayout.LayoutParams lp = new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.gravity = Gravity.BOTTOM;
        sheet.setLayoutParams(lp);
        TextView title = new TextView(this);
        title.setText("INTERCEPTED REQUEST");
        title.setTextColor(ORANGE);
        title.setTextSize(12);
        sheet.addView(title);
        sheetText = new TextView(this);
        sheetText.setTextColor(TEXT);
        sheetText.setTextSize(12);
        sheet.addView(sheetText);
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        Button fwd = smallButton("Forward");
        fwd.setOnClickListener(v -> { Entry e = Store.firstHeld(); if (e != null) { e.dropDecision = false; e.latch.countDown(); } });
        Button drop = smallButton("Drop");
        drop.setOnClickListener(v -> { Entry e = Store.firstHeld(); if (e != null) { e.dropDecision = true; e.latch.countDown(); } });
        Button edit = smallButton("Edit");
        edit.setOnClickListener(v -> { Entry e = Store.firstHeld(); if (e != null) { openEditor(e); showTab(2); } });
        row.addView(fwd);
        row.addView(drop);
        row.addView(edit);
        sheet.addView(row);
        sheet.setVisibility(View.GONE);
    }

    private void buildHistoryPanel() {
        historyPanel = panel();
        historyInfo = infoText("Nothing captured yet. Browse in the Browser tab (Proxy mode) or send from Repeater.");
        historyPanel.addView(historyInfo);
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        Button exportBtn = smallButton("Export JSON");
        exportBtn.setOnClickListener(v -> exportHistory());
        Button clearBtn = smallButton("Clear");
        clearBtn.setOnClickListener(v -> Store.clearHistory());
        row.addView(exportBtn);
        row.addView(clearBtn);
        historyPanel.addView(row);
        historyList = new ListView(this);
        historyAdapter = labelAdapter(historyLabels);
        historyList.setAdapter(historyAdapter);
        historyList.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        historyList.setOnItemClickListener((p, v, pos, id) -> {
            synchronized (Store.history) {
                if (pos < Store.history.size()) openDetail(Store.history.get(pos));
            }
        });
        historyPanel.addView(historyList);
        historyPanel.setVisibility(View.GONE);
    }

    private void buildInterceptPanel() {
        interceptPanel = panel();
        interceptInfo = infoText("Intercept queue is empty. Turn Intercept ON in the Browser tab and browse: matching requests will wait here and in the panel over the browser.");
        interceptPanel.addView(interceptInfo);
        queueList = new ListView(this);
        queueAdapter = labelAdapter(queueLabels);
        queueList.setAdapter(queueAdapter);
        queueList.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        queueList.setOnItemClickListener((p, v, pos, id) -> {
            synchronized (Store.queue) {
                if (pos < Store.queue.size()) openEditor(Store.queue.get(pos));
            }
        });
        interceptPanel.addView(queueList);
        interceptPanel.setVisibility(View.GONE);
    }

    private void buildEditorPanel() {
        editorPanel = panel();
        edTitle = infoText("Edit intercepted request");
        editorPanel.addView(edTitle);
        edUrl = field("URL");
        edHeaders = field("Headers, one per line: Name: value");
        edHeaders.setMinLines(4);
        edBody = field("Body");
        edBody.setMinLines(3);
        editorPanel.addView(edUrl);
        editorPanel.addView(edHeaders);
        editorPanel.addView(edBody);
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        Button save = smallButton("Save edits");
        save.setOnClickListener(v -> saveEdits(false));
        Button fwd = smallButton("Save + Forward");
        fwd.setOnClickListener(v -> saveEdits(true));
        Button drop = smallButton("Drop");
        drop.setOnClickListener(v -> {
            if (editingEntry != null) { saveEdits(false); editingEntry.dropDecision = true; editingEntry.latch.countDown(); }
            editorPanel.setVisibility(View.GONE);
            showTab(2);
        });
        Button back = smallButton("Back");
        back.setOnClickListener(v -> { editorPanel.setVisibility(View.GONE); showTab(2); });
        row.addView(save);
        row.addView(fwd);
        row.addView(drop);
        row.addView(back);
        editorPanel.addView(row);
        editorPanel.setVisibility(View.GONE);
    }

    private void buildDetailPanel() {
        detailPanel = panel();
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        Button back = smallButton("Back");
        back.setOnClickListener(v -> { detailPanel.setVisibility(View.GONE); showTab(3); });
        Button rep = smallButton("Send to Repeater");
        rep.setOnClickListener(v -> { if (detailEntry != null) { openRepeater(detailEntry); } });
        Button copy = smallButton("Copy URL");
        copy.setOnClickListener(v -> {
            if (detailEntry != null) {
                ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                cm.setPrimaryClip(ClipData.newPlainText("url", detailEntry.url));
                Toast.makeText(this, "URL copied", Toast.LENGTH_SHORT).show();
            }
        });
        row.addView(back);
        row.addView(rep);
        row.addView(copy);
        detailPanel.addView(row);
        ScrollView sv = new ScrollView(this);
        sv.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        detailText = new TextView(this);
        detailText.setTextColor(TEXT);
        detailText.setTextSize(12);
        detailText.setTextIsSelectable(true);
        sv.addView(detailText);
        detailPanel.addView(sv);
        detailPanel.setVisibility(View.GONE);
    }

    private void buildRepeaterPanel() {
        repeaterPanel = panel();
        TextView t = infoText("Repeater: edit and send any request with the app engine. The response lands below and in History.");
        repeaterPanel.addView(t);
        rpMethod = field("Method (GET, POST, ...)");
        rpMethod.setText("GET");
        rpUrl = field("https://your-target.example/path");
        rpHeaders = field("Headers, one per line: Name: value");
        rpHeaders.setMinLines(3);
        rpBody = field("Body");
        rpBody.setMinLines(3);
        repeaterPanel.addView(rpMethod);
        repeaterPanel.addView(rpUrl);
        repeaterPanel.addView(rpHeaders);
        repeaterPanel.addView(rpBody);
        Button send = smallButton("Send");
        send.setOnClickListener(v -> sendRepeater());
        repeaterPanel.addView(send);
        rpResponse = new EditText(this);
        rpResponse.setTextColor(TEXT);
        rpResponse.setTextSize(12);
        rpResponse.setFocusable(false);
        rpResponse.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        rpResponse.setHint("Response will appear here");
        rpResponse.setHintTextColor(MUTED);
        repeaterPanel.addView(rpResponse);
        repeaterPanel.setVisibility(View.GONE);
    }

    // ================= Helpers =================

    private LinearLayout panel() {
        LinearLayout p = new LinearLayout(this);
        p.setOrientation(LinearLayout.VERTICAL);
        p.setBackgroundColor(BG);
        p.setPadding(14, 12, 14, 12);
        return p;
    }

    private TextView infoText(String s) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextColor(MUTED);
        t.setTextSize(13);
        return t;
    }

    private EditText field(String hint) {
        EditText e = new EditText(this);
        e.setTextColor(TEXT);
        e.setHintTextColor(MUTED);
        e.setHint(hint);
        e.setTextSize(13);
        e.setBackgroundColor(PANEL);
        return e;
    }

    private Button smallButton(String label) {
        Button b = new Button(this);
        b.setText(label);
        b.setTextColor(TEXT);
        b.setBackgroundColor(PANEL2);
        return b;
    }

    private Button tab(String label) {
        Button b = new Button(this);
        b.setText(label);
        b.setTextSize(12);
        b.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        return b;
    }

    private ToggleButton toggle(String on, String off) {
        ToggleButton t = new ToggleButton(this);
        t.setTextOn(on);
        t.setTextOff(off);
        t.setTextSize(11);
        t.setTextColor(TEXT);
        t.setBackgroundColor(PANEL2);
        t.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        return t;
    }

    private ArrayAdapter<String> labelAdapter(List<String> labels) {
        return new ArrayAdapter<String>(this, android.R.layout.simple_list_item_1, labels) {
            @Override
            public View getView(int position, View convertView, ViewGroup parent) {
                TextView tv = (TextView) super.getView(position, convertView, parent);
                tv.setTextColor(TEXT);
                tv.setTextSize(12);
                return tv;
            }
        };
    }

    private WebView makeWebView(boolean browser) {
        WebView w = new WebView(this);
        WebSettings s = w.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setDatabaseEnabled(true);
        s.setAllowFileAccess(false);
        s.setLoadWithOverviewMode(true);
        s.setUseWideViewPort(true);
        s.setBuiltInZoomControls(true);
        s.setDisplayZoomControls(false);
        w.setBackgroundColor(BG);
        return w;
    }

    private void showTab(int which) {
        currentTab = which;
        editorPanel.setVisibility(View.GONE);
        detailPanel.setVisibility(View.GONE);
        suiteWeb.setVisibility(which == 0 ? View.VISIBLE : View.GONE);
        browserWeb.setVisibility(which == 1 ? View.VISIBLE : View.GONE);
        historyPanel.setVisibility(which == 3 ? View.VISIBLE : View.GONE);
        interceptPanel.setVisibility(which == 2 ? View.VISIBLE : View.GONE);
        repeaterPanel.setVisibility(which == 4 ? View.VISIBLE : View.GONE);
        browserChrome.setVisibility(which == 1 ? View.VISIBLE : View.GONE);
        tabSuite.setTextColor(which == 0 ? ORANGE : MUTED);
        tabBrowser.setTextColor(which == 1 ? ORANGE : MUTED);
        tabIntercept.setTextColor(which == 2 ? ORANGE : MUTED);
        tabHistory.setTextColor(which == 3 ? ORANGE : MUTED);
        tabRepeater.setTextColor(which == 4 ? ORANGE : MUTED);
        refreshUi();
    }

    private void refreshUi() {
        synchronized (Store.history) {
            historyLabels.clear();
            for (Entry e : Store.history) historyLabels.add(e.label());
            historyInfo.setText(Store.history.size() + " entries. Tap one for full request and response. In Native mode only request lines are logged, and POST bodies are not exposed by WebView.");
        }
        historyAdapter.notifyDataSetChanged();
        synchronized (Store.queue) {
            queueLabels.clear();
            for (Entry e : Store.queue) queueLabels.add(e.label());
            tabIntercept.setText(Store.queue.isEmpty() ? "Intercept" : "Intercept (" + Store.queue.size() + ")");
            interceptInfo.setText(Store.queue.isEmpty()
                ? "Intercept queue is empty. Turn Intercept ON in the Browser tab and browse: matching requests will wait here and in the panel over the browser."
                : Store.queue.size() + " request(s) held. Tap one to edit, forward or drop.");
            Entry held = Store.firstHeld();
            if (held != null && currentTab == 1) {
                sheetText.setText(held.method + "  " + held.url + (held.reqBody != null && !held.reqBody.isEmpty() ? "\nBody: " + truncate(held.reqBody, 160) : ""));
                sheet.setVisibility(View.VISIBLE);
            } else {
                sheet.setVisibility(View.GONE);
            }
        }
        queueAdapter.notifyDataSetChanged();
    }

    private String truncate(String s, int n) { return s.length() <= n ? s : s.substring(0, n) + "..."; }

    private void navigateBrowser() {
        String u = urlInput.getText().toString().trim();
        if (u.isEmpty()) return;
        if (!u.startsWith("http://") && !u.startsWith("https://")) u = "https://" + u;
        urlInput.setText(u);
        browserWeb.loadUrl(u);
    }

    private void openEditor(Entry e) {
        editingEntry = e;
        edTitle.setText("Edit intercepted request (held until you Forward or Drop)");
        edUrl.setText(e.url);
        edHeaders.setText(e.headersToText(e.reqHeaders));
        edBody.setText(e.reqBody == null ? "" : e.reqBody);
        showTab(2);
        editorPanel.setVisibility(View.VISIBLE);
        interceptPanel.setVisibility(View.GONE);
    }

    private void saveEdits(boolean forward) {
        if (editingEntry == null) return;
        editingEntry.url = edUrl.getText().toString().trim();
        editingEntry.reqHeaders = Entry.parseHeaders(edHeaders.getText().toString());
        String b = edBody.getText().toString();
        editingEntry.reqBody = b.isEmpty() ? editingEntry.reqBody : b;
        if (forward) {
            editingEntry.dropDecision = false;
            editingEntry.latch.countDown();
            editorPanel.setVisibility(View.GONE);
            showTab(1);
            Toast.makeText(this, "Forwarded", Toast.LENGTH_SHORT).show();
        } else {
            Toast.makeText(this, "Edits saved, request still held", Toast.LENGTH_SHORT).show();
        }
        Store.changed();
    }

    private void openDetail(Entry e) {
        detailEntry = e;
        StringBuilder sb = new StringBuilder();
        sb.append(e.method).append(" ").append(e.url).append("\n");
        sb.append("Time: ").append(e.time).append("   Source: ").append(e.source);
        if (e.status != null) sb.append("   Status: ").append(e.status);
        if (e.state == Entry.STATE_HELD) sb.append("   [HELD]");
        if (e.state == Entry.STATE_DROPPED) sb.append("   [DROPPED]");
        sb.append("\n\nREQUEST HEADERS\n").append(e.headersToText(e.reqHeaders));
        sb.append("\nREQUEST BODY\n").append(e.reqBody == null || e.reqBody.isEmpty() ? "(none captured)" : e.reqBody);
        sb.append("\n\nRESPONSE HEADERS\n").append(e.headersToText(e.respHeaders));
        sb.append("\nRESPONSE BODY\n").append(e.respBodyText == null || e.respBodyText.isEmpty() ? "(none captured)" : e.respBodyText);
        if (e.error != null) sb.append("\n\nERROR\n").append(e.error);
        if (e.note != null) sb.append("\n\nNOTE\n").append(e.note);
        detailText.setText(sb.toString());
        showTab(3);
        detailPanel.setVisibility(View.VISIBLE);
        historyPanel.setVisibility(View.GONE);
    }

    private void openRepeater(Entry e) {
        rpMethod.setText(e.method);
        rpUrl.setText(e.url);
        rpHeaders.setText(e.headersToText(e.reqHeaders));
        rpBody.setText(e.reqBody == null ? "" : e.reqBody);
        detailPanel.setVisibility(View.GONE);
        showTab(4);
    }

    private void sendRepeater() {
        Entry e = new Entry();
        e.id = Store.nextId();
        e.time = timeFmt.format(new Date());
        e.method = rpMethod.getText().toString().trim().toUpperCase();
        if (e.method.isEmpty()) e.method = "GET";
        e.url = rpUrl.getText().toString().trim();
        e.reqHeaders = Entry.parseHeaders(rpHeaders.getText().toString());
        String b = rpBody.getText().toString();
        e.reqBody = b.isEmpty() ? null : b;
        e.source = "repeater";
        if (e.url.isEmpty()) { Toast.makeText(this, "Enter a URL first", Toast.LENGTH_SHORT).show(); return; }
        rpResponse.setText("Sending...");
        new Thread(() -> {
            try {
                Engine.fetch(e);
                e.state = Entry.STATE_COMPLETED;
            } catch (Exception ex) {
                e.error = ex.getMessage();
            }
            Store.addHistory(e);
            runOnUiThread(() -> {
                String out = (e.status != null ? "HTTP " + e.status + "\n" : "")
                    + e.headersToText(e.respHeaders)
                    + "\n" + (e.respBodyText == null ? "" : e.respBodyText)
                    + (e.error != null ? "\nERROR: " + e.error : "");
                rpResponse.setText(out);
            });
        }).start();
    }

    private void exportHistory() {
        try {
            JSONArray arr = new JSONArray();
            synchronized (Store.history) {
                for (Entry e : Store.history) {
                    JSONObject o = new JSONObject();
                    o.put("time", e.time);
                    o.put("method", e.method);
                    o.put("url", e.url);
                    o.put("requestBody", e.reqBody == null ? "" : e.reqBody);
                    o.put("status", e.status == null ? JSONObject.NULL : e.status);
                    o.put("responseBody", e.respBodyText == null ? "" : e.respBodyText);
                    arr.put(o);
                }
            }
            Intent share = new Intent(Intent.ACTION_SEND);
            share.setType("text/plain");
            share.putExtra(Intent.EXTRA_SUBJECT, "SecuritySuite history");
            share.putExtra(Intent.EXTRA_TEXT, arr.toString(2));
            startActivity(Intent.createChooser(share, "Export history"));
        } catch (Exception e) {
            Toast.makeText(this, "Export failed", Toast.LENGTH_SHORT).show();
        }
    }

    // ================= Proxy engine =================

    private class ProxyClient extends WebViewClient {

        @Override
        public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
            String scheme = request.getUrl().getScheme();
            if (scheme == null || (!scheme.equals("http") && !scheme.equals("https"))) return null;

            Entry e = new Entry();
            e.id = Store.nextId();
            e.time = timeFmt.format(new Date());
            e.method = request.getMethod() == null ? "GET" : request.getMethod();
            e.url = request.getUrl().toString();
            e.mainFrame = request.isForMainFrame();
            e.source = "browser";
            Map<String, String> hm = request.getRequestHeaders();
            if (hm != null) for (Map.Entry<String, String> en : hm.entrySet()) e.reqHeaders.add(new String[]{en.getKey(), en.getValue()});

            boolean proxy = modeToggle.isChecked();
            if (!proxy || e.method.equals("PATCH")) {
                e.state = Entry.STATE_PASSTHROUGH;
                if (e.method.equals("PATCH")) e.note = "PATCH is passed through natively: the Android HTTP engine cannot send it, so this entry is request-line only.";
                Store.addHistory(e);
                return null;
            }

            if (e.method.equals("POST") || e.method.equals("PUT") || e.method.equals("DELETE")) {
                String body = Store.takeBody(e.method, e.url);
                if (body != null) e.reqBody = body;
            }

            Store.addHistory(e);

            if (interceptToggle.isChecked() && shouldHold(e)) {
                e.state = Entry.STATE_HELD;
                Store.hold(e);
                try { e.latch.await(120, TimeUnit.SECONDS); } catch (InterruptedException ignored) { }
                Store.unhold(e);
                if (e.dropDecision) {
                    e.state = Entry.STATE_DROPPED;
                    Store.changed();
                    return droppedResponse(e);
                }
            }

            try {
                Engine.Result r = Engine.fetch(e);
                e.state = Entry.STATE_COMPLETED;
                byte[] body = r.body;
                if (e.mainFrame && r.mime != null && r.mime.contains("html")) body = Shim.inject(body, r.charset);
                Store.changed();
                return new WebResourceResponse(r.mime, r.charset, r.status, sanitizeReason(r),
                        Engine.headersForWebView(r), new ByteArrayInputStream(body));
            } catch (Exception ex) {
                e.error = ex.getMessage();
                e.state = Entry.STATE_COMPLETED;
                Store.changed();
                String html = "<html><body style='background:#0a0e13;color:#e8eef5;font-family:sans-serif;padding:20px'><h3>SecuritySuite engine could not fetch this page</h3><p>"
                        + escapeHtml(e.url) + "</p><p>" + escapeHtml(String.valueOf(e.error)) + "</p><p>Try Native mode for this site, or check the target and your connection.</p></body></html>";
                if (e.mainFrame) {
                    return new WebResourceResponse("text/html", "utf-8", 200, "OK", null, new ByteArrayInputStream(html.getBytes()));
                }
                return new WebResourceResponse("text/plain", "utf-8", 502, "Bad Gateway", null, new ByteArrayInputStream(new byte[0]));
            }
        }

        private boolean shouldHold(Entry e) {
            if (e.mainFrame) return true;
            if (e.method.equals("POST") || e.method.equals("PUT") || e.method.equals("DELETE")) return true;
            if (!scopeToggle.isChecked()) return true; // Scope: All
            String dest = e.headerValue("Sec-Fetch-Dest");
            if (dest != null) return dest.equals("empty") || dest.equals("document") || dest.equals("iframe") || dest.equals("frame");
            String u = e.url.toLowerCase();
            String[] assets = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".css", ".woff", ".woff2", ".ttf", ".ico", ".mp4", ".webm", ".mp3"};
            for (String a : assets) if (u.contains(a)) return false;
            String accept = e.headerValue("Accept");
            if (accept != null && (accept.contains("image/") || accept.contains("text/css") || accept.contains("font/"))) return false;
            return false;
        }

        private WebResourceResponse droppedResponse(Entry e) {
            if (e.mainFrame) {
                String html = "<html><body style='background:#0a0e13;color:#e8eef5;font-family:sans-serif;padding:20px'><h3>Dropped by SecuritySuite Intercept</h3><p>" + escapeHtml(e.method + " " + e.url) + "</p></body></html>";
                return new WebResourceResponse("text/html", "utf-8", 200, "OK", null, new ByteArrayInputStream(html.getBytes()));
            }
            return new WebResourceResponse("text/plain", "utf-8", 200, "OK", null, new ByteArrayInputStream(new byte[0]));
        }

        private String sanitizeReason(Engine.Result r) {
            String s = r.reason == null ? "" : r.reason.replaceAll("[^\\x20-\\x7E]", "").trim();
            return s.isEmpty() ? Engine.defaultReason(r.status) : s;
        }

        private String escapeHtml(String s) {
            return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
        }

        @Override
        public void onPageFinished(WebView view, String url) {
            if (currentTab == 1) urlInput.setText(url);
        }
    }

    @Override
    public void onBackPressed() {
        if (editorPanel.getVisibility() == View.VISIBLE) { editorPanel.setVisibility(View.GONE); showTab(2); return; }
        if (detailPanel.getVisibility() == View.VISIBLE) { detailPanel.setVisibility(View.GONE); showTab(3); return; }
        WebView active = currentTab == 1 ? browserWeb : suiteWeb;
        if ((currentTab == 0 || currentTab == 1) && active != null && active.canGoBack()) active.goBack();
        else super.onBackPressed();
    }
}
