package app.securitysuite.mobile;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.CookieManager;
import android.webkit.JavascriptInterface;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MainActivity extends Activity {

    static final int ORANGE = Color.rgb(255, 102, 0);
    static final int DARK = Color.rgb(14, 14, 18);
    static final int PANEL = Color.rgb(22, 22, 28);
    static final int PANEL2 = Color.rgb(30, 30, 38);
    static final int BORDER = Color.rgb(52, 52, 62);
    static final int TEXT = Color.rgb(232, 232, 236);
    static final int MUTED = Color.rgb(150, 150, 160);
    static final int GREEN = Color.rgb(46, 204, 113);
    static final int RED = Color.rgb(231, 76, 60);
    static final int YELLOW = Color.rgb(241, 196, 15);
    static final int BLUE = Color.rgb(52, 152, 219);

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final SimpleDateFormat timeFmt = new SimpleDateFormat("HH:mm:ss", java.util.Locale.US);
    private final ExecutorService pool = Executors.newCachedThreadPool();
    private SharedPreferences prefs;

    private WebView suiteView;
    private WebView browser;
    private final ProxyClient proxyClient = new ProxyClient();
    private boolean proxyMode = true;

    private LinearLayout suitePanel, browserPanel, historyPanel, repeaterPanel, rulesPanel, detailPanel, intruderPanel, toolsPanel;
    private View browserBox, splitPanel;
    private Button[] tabButtons;
    private int currentTab = 1;

    // split panel
    private Spinner splitSelect;
    private ArrayAdapter<String> splitAdapter;
    private final List<Entry> splitItems = new ArrayList<>();
    private Button tabReqBtn, tabRespBtn;
    private boolean showResponse = false;
    private TextView splitStatus, splitBody;
    private EditText splitUrl;
    private Button viewModeBtn;
    private int viewMode = 0; // 0 split, 1 browser full, 2 panel full
    private CheckBox interceptToggle;
    private Spinner scopeSpinner;
    Entry selected;

    // history
    private ArrayAdapter<String> historyAdapter;
    private final List<String> historyLabels = new ArrayList<>();
    private final List<Entry> displayedHistory = new ArrayList<>();
    private EditText historySearch;

    // detail
    private TextView detailText;
    private EditText detailNote;
    private Spinner detailHighlight, detailOrg;
    private Entry detailEntry;

    // repeater
    private EditText repMethod, repUrl, repHeaders, repBody, repResponse;

    // intruder
    private EditText inUrl, inBody, inHeaders, inSet1, inSet2, inGrep, inDelay;
    private Spinner inAttack, inMethod;
    private ArrayAdapter<String> intruderAdapter;
    private final List<String> intruderLabels = new ArrayList<>();
    private final List<Entry> intruderResults = new ArrayList<>();
    private volatile boolean intruderRunning = false;
    private TextView intruderStatus;

    // tools
    private Spinner toolSelect;
    private LinearLayout decoderBox, comparerBox, sequencerBox, scannerBox, sitemapBox, oastBox;
    private EditText decInput, decOutput;
    private Spinner decOp;
    private EditText cmpA, cmpB, cmpOutput;
    private EditText seqUrl, seqCount, seqCookie, seqRegex, seqOutput;
    private EditText scanUrl, scanOutput;
    private TextView sitemapText;
    private EditText oastDomain, oastOutput;

    // rules + settings
    private EditText skipHostsEt, skipIpsEt, skipPathsEt, skipExtsEt, skipMethodsEt, onlyHostsEt, mrRulesEt;
    private EditText setUpstreamHost, setUpstreamPort, setUa, setTimeout;
    private CheckBox skipEnabledCb;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        prefs = getSharedPreferences("securitysuite", MODE_PRIVATE);
        Rules.load(prefs);
        Engine.upstreamHost = prefs.getString("upHost", "");
        Engine.upstreamPort = prefs.getInt("upPort", 0);
        Engine.uaOverride = prefs.getString("uaOverride", "");
        Engine.timeoutSec = prefs.getInt("timeoutSec", 20);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(DARK);

        LinearLayout brand = new LinearLayout(this);
        brand.setOrientation(LinearLayout.HORIZONTAL);
        brand.setPadding(dp(10), dp(6), dp(10), dp(6));
        brand.setBackgroundColor(PANEL);
        TextView brandT = new TextView(this);
        brandT.setText("SecuritySuite");
        brandT.setTextColor(ORANGE);
        brandT.setTextSize(17);
        brandT.setTypeface(Typeface.DEFAULT_BOLD);
        TextView brandV = new TextView(this);
        brandV.setText("  mobile security toolkit v4");
        brandV.setTextColor(MUTED);
        brandV.setTextSize(11);
        brand.addView(brandT);
        brand.addView(brandV);
        root.addView(brand);

        LinearLayout tabs = new LinearLayout(this);
        tabs.setOrientation(LinearLayout.HORIZONTAL);
        tabs.setPadding(dp(4), dp(4), dp(4), dp(4));
        String[] names = {"Suite", "Browser", "History", "Intruder", "Repeater", "Tools", "Rules"};
        tabButtons = new Button[names.length];
        for (int i = 0; i < names.length; i++) {
            final int idx = i;
            Button b = tabButton(names[i]);
            b.setOnClickListener(v -> showTab(idx));
            tabButtons[i] = b;
            tabs.addView(b, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        }
        root.addView(tabs);

        buildSuitePanel(root);
        buildBrowserPanel(root);
        buildHistoryPanel(root);
        buildIntruderPanel(root);
        buildRepeaterPanel(root);
        buildToolsPanel(root);
        buildRulesPanel(root);
        buildDetailPanel(root);

        Store.addListener(() -> ui.post(this::refreshUi));
        setContentView(root);
        showTab(1);
    }

    int dp(int v) { return (int) (v * getResources().getDisplayMetrics().density); }

    static String requestText(Entry e) {
        StringBuilder sb = new StringBuilder();
        sb.append(e.method).append(" ").append(e.url).append("\n");
        sb.append(e.headersToText(e.reqHeaders));
        sb.append("\n").append(e.reqBody == null || e.reqBody.isEmpty() ? "(no body captured)" : e.reqBody);
        return sb.toString();
    }

    static String responseText(Entry e) {
        StringBuilder sb = new StringBuilder();
        sb.append("Status: ").append(e.status == null ? "(none)" : e.status).append("\n");
        sb.append(e.headersToText(e.respHeaders));
        sb.append("\n").append(e.respBodyText == null || e.respBodyText.isEmpty() ? "(no body captured)" : e.respBodyText);
        if (e.error != null) sb.append("\n\nERROR: ").append(e.error);
        if (e.note != null) sb.append("\n\nNOTE: ").append(e.note);
        return sb.toString();
    }

    public class BodyBridge {
        @JavascriptInterface
        public void reportBody(String json) { Store.putBodyJson(json); }
    }

    GradientDrawable rounded(int fill, int radiusDp, int stroke) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(fill);
        g.setCornerRadius(dp(radiusDp));
        if (stroke != 0) g.setStroke(dp(1), stroke);
        return g;
    }

    Button tabButton(String text) {
        Button b = new Button(this);
        b.setText(text);
        b.setTextSize(11.5f);
        b.setAllCaps(false);
        b.setTextColor(TEXT);
        b.setBackground(rounded(PANEL2, 8, BORDER));
        b.setPadding(dp(2), dp(6), dp(2), dp(6));
        return b;
    }

    Button smallButton(String text) {
        Button b = new Button(this);
        b.setText(text);
        b.setTextSize(11.5f);
        b.setAllCaps(false);
        b.setTextColor(TEXT);
        b.setBackground(rounded(PANEL2, 8, BORDER));
        b.setPadding(dp(8), dp(5), dp(8), dp(5));
        return b;
    }

    Button accentButton(String text) {
        Button b = smallButton(text);
        b.setBackground(rounded(ORANGE, 8, 0));
        b.setTextColor(Color.WHITE);
        b.setTypeface(Typeface.DEFAULT_BOLD);
        return b;
    }

    EditText field(String hint, boolean multi) {
        EditText e = new EditText(this);
        e.setHint(hint);
        e.setHintTextColor(MUTED);
        e.setTextColor(TEXT);
        e.setTextSize(12.5f);
        e.setBackground(rounded(PANEL, 8, BORDER));
        e.setPadding(dp(8), dp(6), dp(8), dp(6));
        if (multi) {
            e.setSingleLine(false);
            e.setMinLines(3);
            e.setGravity(Gravity.TOP);
        }
        return e;
    }

    TextView label(String text, float size, int color) {
        TextView t = new TextView(this);
        t.setText(text);
        t.setTextColor(color);
        t.setTextSize(size);
        return t;
    }

    TextView sectionTitle(String text) {
        TextView t = label(text, 14, ORANGE);
        t.setTypeface(Typeface.DEFAULT_BOLD);
        t.setPadding(0, dp(10), 0, dp(4));
        return t;
    }

    Spinner styledSpinner(String[] items) {
        Spinner s = new Spinner(this);
        ArrayAdapter<String> a = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, items);
        a.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        s.setAdapter(a);
        s.setBackground(rounded(PANEL2, 8, BORDER));
        return s;
    }

    // ---------------- Suite ----------------
    private void buildSuitePanel(LinearLayout root) {
        suitePanel = new LinearLayout(this);
        suitePanel.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
        suiteView = new WebView(this);
        WebSettings ws = suiteView.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);
        suiteView.setWebViewClient(new WebViewClient());
        suiteView.loadUrl("https://securitysuite-woad.vercel.app");
        suitePanel.addView(suiteView, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        root.addView(suitePanel);
    }

    // ---------------- Browser + split interceptor ----------------
    private void buildBrowserPanel(LinearLayout root) {
        browserPanel = new LinearLayout(this);
        browserPanel.setOrientation(LinearLayout.VERTICAL);
        browserPanel.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));

        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setPadding(dp(4), dp(4), dp(4), dp(2));
        final EditText addr = field("https://example.com", false);
        addr.setSingleLine(true);
        Button go = accentButton("Go");
        go.setOnClickListener(v -> {
            String u = addr.getText().toString().trim();
            if (!u.startsWith("http")) u = "https://" + u;
            browser.loadUrl(u);
        });
        bar.addView(addr, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        bar.addView(go);
        browserPanel.addView(bar);

        LinearLayout ctrl = new LinearLayout(this);
        ctrl.setOrientation(LinearLayout.HORIZONTAL);
        ctrl.setPadding(dp(4), 0, dp(4), dp(2));
        final Button modeBtn = smallButton("Mode: Proxy");
        modeBtn.setOnClickListener(v -> {
            proxyMode = !proxyMode;
            modeBtn.setText(proxyMode ? "Mode: Proxy" : "Mode: Native");
            browser.setWebViewClient(proxyMode ? proxyClient : new WebViewClient());
            Toast.makeText(this, proxyMode ? "Proxy engine on: traffic is captured and can be held" : "Native mode: direct browsing, no capture", Toast.LENGTH_SHORT).show();
        });
        interceptToggle = new CheckBox(this);
        interceptToggle.setText("Intercept");
        interceptToggle.setTextColor(ORANGE);
        interceptToggle.setChecked(false);
        scopeSpinner = styledSpinner(new String[]{"Scope: Smart", "Scope: All"});
        viewModeBtn = smallButton("View: Split");
        viewModeBtn.setOnClickListener(v -> {
            viewMode = (viewMode + 1) % 3;
            applyViewMode();
        });
        ctrl.addView(modeBtn);
        ctrl.addView(interceptToggle);
        ctrl.addView(scopeSpinner, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        ctrl.addView(viewModeBtn);
        browserPanel.addView(ctrl);

        browser = new WebView(this);
        WebSettings bs = browser.getSettings();
        bs.setJavaScriptEnabled(true);
        bs.setDomStorageEnabled(true);
        bs.setLoadWithOverviewMode(true);
        bs.setUseWideViewPort(true);
        browser.setWebViewClient(proxyClient);
        browser.addJavascriptInterface(new BodyBridge(), "SSBridge");
        browserBox = browser;
        browserPanel.addView(browserBox, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));

        buildSplitPanel();
        browserPanel.addView(splitPanel, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
        root.addView(browserPanel);
    }

    private void applyViewMode() {
        if (viewMode == 0) {
            viewModeBtn.setText("View: Split");
            browserBox.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
            splitPanel.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
            browserBox.setVisibility(View.VISIBLE);
            splitPanel.setVisibility(View.VISIBLE);
        } else if (viewMode == 1) {
            viewModeBtn.setText("View: Browser");
            browserBox.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
            browserBox.setVisibility(View.VISIBLE);
            splitPanel.setVisibility(View.GONE);
        } else {
            viewModeBtn.setText("View: Panel");
            browserBox.setVisibility(View.GONE);
            splitPanel.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
            splitPanel.setVisibility(View.VISIBLE);
        }
    }

    private void buildSplitPanel() {
        splitPanel = new LinearLayout(this);
        ((LinearLayout) splitPanel).setOrientation(LinearLayout.VERTICAL);
        splitPanel.setBackground(rounded(PANEL, 10, BORDER));
        splitPanel.setPadding(dp(6), dp(4), dp(6), dp(4));

        LinearLayout row1 = new LinearLayout(this);
        row1.setOrientation(LinearLayout.HORIZONTAL);
        splitStatus = label("Interceptor: no traffic yet", 12, ORANGE);
        splitStatus.setTypeface(Typeface.DEFAULT_BOLD);
        row1.addView(splitStatus, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        splitSelect = new Spinner(this);
        splitAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, new ArrayList<>());
        splitAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        splitSelect.setAdapter(splitAdapter);
        splitSelect.setBackground(rounded(PANEL2, 8, BORDER));
        splitSelect.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent, View view, int pos, long id) {
                if (pos >= 0 && pos < splitItems.size()) { selected = splitItems.get(pos); renderSplit(); }
            }
            @Override public void onNothingSelected(AdapterView<?> parent) { }
        });
        row1.addView(splitSelect, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.4f));
        ((LinearLayout) splitPanel).addView(row1);

        splitUrl = field("Request URL (editable while held)", false);
        splitUrl.setSingleLine(true);
        ((LinearLayout) splitPanel).addView(splitUrl);

        LinearLayout row2 = new LinearLayout(this);
        row2.setOrientation(LinearLayout.HORIZONTAL);
        tabReqBtn = smallButton("Request");
        tabRespBtn = smallButton("Response");
        tabReqBtn.setOnClickListener(v -> { showResponse = false; renderSplit(); });
        tabRespBtn.setOnClickListener(v -> { showResponse = true; renderSplit(); });
        Button saveBtn = smallButton("Save edits");
        saveBtn.setOnClickListener(v -> saveSplitEdits());
        row2.addView(tabReqBtn);
        row2.addView(tabRespBtn);
        row2.addView(saveBtn);
        ((LinearLayout) splitPanel).addView(row2);

        splitBody = label("", 11.5f, TEXT);
        splitBody.setTypeface(Typeface.MONOSPACE);
        ScrollView sv = new ScrollView(this);
        sv.addView(splitBody);
        ((LinearLayout) splitPanel).addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));

        LinearLayout row3 = new LinearLayout(this);
        row3.setOrientation(LinearLayout.HORIZONTAL);
        Button fwd = accentButton("Forward");
        fwd.setOnClickListener(v -> forwardSelected());
        Button fwdAll = smallButton("Forward All");
        fwdAll.setOnClickListener(v -> forwardAll());
        Button drop = smallButton("Drop");
        drop.setOnClickListener(v -> dropSelected());
        Button dropAll = smallButton("Drop All");
        dropAll.setOnClickListener(v -> dropAll());
        Button toRep = smallButton("To Repeater");
        toRep.setOnClickListener(v -> { if (selected != null) { sendToRepeater(selected); showTab(4); } });
        row3.addView(fwd);
        row3.addView(fwdAll);
        row3.addView(drop);
        row3.addView(dropAll);
        row3.addView(toRep);
        ((LinearLayout) splitPanel).addView(row3);
    }

    private void renderSplit() {
        if (selected == null) {
            splitStatus.setText("Interceptor: no traffic yet");
            splitBody.setText("");
            return;
        }
        Entry e = selected;
        String stateTxt = e.state == Entry.STATE_HELD ? "HELD (page is waiting)" : e.state == Entry.STATE_DROPPED ? "DROPPED" : "DONE";
        splitStatus.setText("Interceptor: " + stateTxt + " - " + e.method + (e.status != null ? " - " + e.status : ""));
        splitStatus.setTextColor(e.state == Entry.STATE_HELD ? YELLOW : e.state == Entry.STATE_DROPPED ? RED : GREEN);
        if (splitUrl.getText().toString().isEmpty() || !splitUrl.getText().toString().equals(e.url)) splitUrl.setText(e.url);
        tabReqBtn.setTextColor(showResponse ? MUTED : ORANGE);
        tabRespBtn.setTextColor(showResponse ? ORANGE : MUTED);
        if (!showResponse) {
            splitBody.setText(requestText(e));
        } else if (e.state == Entry.STATE_HELD) {
            splitBody.setText("Response not available yet. This request is held: Forward it to see the response here.");
        } else if (e.state == Entry.STATE_DROPPED) {
            splitBody.setText("Request was dropped.");
        } else {
            splitBody.setText(responseText(e));
        }
    }

    private void saveSplitEdits() {
        if (selected == null) return;
        if (showResponse) {
            Toast.makeText(this, "Responses are view only here. Edit requests, or use Repeater.", Toast.LENGTH_SHORT).show();
            return;
        }
        saveSplitEditsQuiet();
        Toast.makeText(this, "Edits saved. They apply when you Forward.", Toast.LENGTH_SHORT).show();
    }

    private void saveSplitEditsQuiet() {
        if (selected == null || showResponse) return;
        selected.url = splitUrl.getText().toString().trim();
        String text = splitBody.getText().toString();
        String[] parts = text.split("\n\n", 2);
        String[] lines = parts[0].split("\n");
        StringBuilder hb = new StringBuilder();
        for (int i = 1; i < lines.length; i++) hb.append(lines[i]).append("\n");
        selected.reqHeaders = Entry.parseHeaders(hb.toString());
        String b = parts.length > 1 ? parts[1] : "";
        selected.reqBody = b.isEmpty() || b.equals("(no body captured)") ? null : b;
    }

    private void forwardSelected() {
        Entry target = (selected != null && selected.state == Entry.STATE_HELD) ? selected : Store.firstHeld();
        if (target == null) {
            Toast.makeText(this, "Nothing held is selected", Toast.LENGTH_SHORT).show();
            return;
        }
        if (target == selected) saveSplitEditsQuiet();
        target.dropDecision = false;
        target.latch.countDown();
    }

    private void forwardAll() {
        saveSplitEditsQuiet();
        List<Entry> held;
        synchronized (Store.queue) { held = new ArrayList<>(Store.queue); }
        for (Entry e : held) { e.dropDecision = false; e.latch.countDown(); }
        Toast.makeText(this, "Forwarded " + held.size() + " held request(s)", Toast.LENGTH_SHORT).show();
    }

    private void dropSelected() {
        Entry target = (selected != null && selected.state == Entry.STATE_HELD) ? selected : Store.firstHeld();
        if (target == null) {
            Toast.makeText(this, "Nothing held is selected", Toast.LENGTH_SHORT).show();
            return;
        }
        target.dropDecision = true;
        target.latch.countDown();
    }

    private void dropAll() {
        List<Entry> held;
        synchronized (Store.queue) { held = new ArrayList<>(Store.queue); }
        for (Entry e : held) { e.dropDecision = true; e.latch.countDown(); }
        Toast.makeText(this, "Dropped " + held.size() + " held request(s)", Toast.LENGTH_SHORT).show();
    }

    // ---------------- History ----------------
    private void buildHistoryPanel(LinearLayout root) {
        historyPanel = new LinearLayout(this);
        historyPanel.setOrientation(LinearLayout.VERTICAL);
        historyPanel.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
        historyPanel.setPadding(dp(6), dp(6), dp(6), dp(6));

        historySearch = field("Search history: host, path, method, status...", false);
        historySearch.setSingleLine(true);
        historySearch.addTextChangedListener(new android.text.TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int a, int b, int c) { }
            @Override public void onTextChanged(CharSequence s, int a, int b, int c) { refreshUi(); }
            @Override public void afterTextChanged(android.text.Editable s) { }
        });
        historyPanel.addView(historySearch);

        LinearLayout hr = new LinearLayout(this);
        hr.setOrientation(LinearLayout.HORIZONTAL);
        Button export = smallButton("Export JSON");
        export.setOnClickListener(v -> exportHistory());
        Button clear = smallButton("Clear");
        clear.setOnClickListener(v -> { Store.clearHistory(); selected = null; Toast.makeText(this, "History cleared", Toast.LENGTH_SHORT).show(); });
        hr.addView(export);
        hr.addView(clear);
        hr.addView(label("Tap an item for detail and actions.", 11, MUTED));
        historyPanel.addView(hr);

        ListView lv = new ListView(this);
        historyAdapter = new ArrayAdapter<String>(this, android.R.layout.simple_list_item_1, historyLabels) {
            @Override public View getView(int position, View convertView, ViewGroup parent) {
                View v = super.getView(position, convertView, parent);
                TextView t = (TextView) v;
                t.setTextSize(12);
                t.setBackgroundColor(PANEL);
                if (position < displayedHistory.size()) {
                    Entry e = displayedHistory.get(position);
                    int c = TEXT;
                    if (e.highlight == 1) c = RED;
                    else if (e.highlight == 2) c = YELLOW;
                    else if (e.highlight == 3) c = GREEN;
                    else if (e.highlight == 4) c = BLUE;
                    else if (e.status != null && e.status >= 500) c = RED;
                    else if (e.status != null && e.status >= 400) c = Color.rgb(230, 126, 34);
                    else if (e.status != null && e.status >= 300) c = YELLOW;
                    else if (e.status != null && e.status >= 200) c = Color.rgb(140, 220, 160);
                    t.setTextColor(c);
                }
                return v;
            }
        };
        lv.setAdapter(historyAdapter);
        lv.setOnItemClickListener((parent, view, position, id) -> {
            if (position < displayedHistory.size()) openDetail(displayedHistory.get(position));
        });
        historyPanel.addView(lv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
        root.addView(historyPanel);
    }

    // ---------------- Detail ----------------
    private void buildDetailPanel(LinearLayout root) {
        detailPanel = new LinearLayout(this);
        detailPanel.setOrientation(LinearLayout.VERTICAL);
        detailPanel.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
        detailPanel.setPadding(dp(8), dp(8), dp(8), dp(8));

        LinearLayout r1 = new LinearLayout(this);
        r1.setOrientation(LinearLayout.HORIZONTAL);
        Button back = smallButton("Back");
        back.setOnClickListener(v -> showTab(2));
        Button toRep = smallButton("To Repeater");
        toRep.setOnClickListener(v -> { if (detailEntry != null) { sendToRepeater(detailEntry); showTab(4); } });
        Button toInt = smallButton("To Intruder");
        toInt.setOnClickListener(v -> { if (detailEntry != null) { sendToIntruder(detailEntry); showTab(3); } });
        Button toCmp = smallButton("To Comparer");
        toCmp.setOnClickListener(v -> { if (detailEntry != null) { cmpA.setText(responseText(detailEntry)); showTab(5); toolSelect.setSelection(1); showTool(1); } });
        Button scan = smallButton("Passive scan");
        scan.setOnClickListener(v -> {
            if (detailEntry != null) {
                StringBuilder sb = new StringBuilder(detailText.getText().toString());
                sb.append("\n\n==== PASSIVE SCAN ====\n");
                for (String issue : Features.passiveScan(detailEntry)) sb.append(issue).append("\n");
                detailText.setText(sb.toString());
            }
        });
        r1.addView(back);
        r1.addView(toRep);
        r1.addView(toInt);
        r1.addView(toCmp);
        r1.addView(scan);
        detailPanel.addView(r1);

        LinearLayout r2 = new LinearLayout(this);
        r2.setOrientation(LinearLayout.HORIZONTAL);
        r2.addView(label("Highlight:", 12, MUTED));
        detailHighlight = styledSpinner(new String[]{"None", "Red", "Yellow", "Green", "Blue"});
        r2.addView(detailHighlight);
        r2.addView(label(" Status:", 12, MUTED));
        detailOrg = styledSpinner(new String[]{"New", "In Progress", "Done", "Ignored"});
        r2.addView(detailOrg);
        Button saveAnn = smallButton("Save note");
        saveAnn.setOnClickListener(v -> {
            if (detailEntry != null) {
                detailEntry.note2 = detailNote.getText().toString();
                detailEntry.highlight = detailHighlight.getSelectedItemPosition();
                detailEntry.orgStatus = (String) detailOrg.getSelectedItem();
                Toast.makeText(this, "Annotation saved", Toast.LENGTH_SHORT).show();
                refreshUi();
            }
        });
        r2.addView(saveAnn);
        detailPanel.addView(r2);

        detailNote = field("Add a note about this request (organizer)...", false);
        detailNote.setSingleLine(true);
        detailPanel.addView(detailNote);

        detailText = label("", 11.5f, TEXT);
        detailText.setTypeface(Typeface.MONOSPACE);
        ScrollView sv = new ScrollView(this);
        sv.addView(detailText);
        detailPanel.addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
        root.addView(detailPanel);
    }

    private void openDetail(Entry e) {
        detailEntry = e;
        detailNote.setText(e.note2 == null ? "" : e.note2);
        detailHighlight.setSelection(e.highlight);
        int orgIdx = 0;
        String[] orgs = {"New", "In Progress", "Done", "Ignored"};
        for (int i = 0; i < orgs.length; i++) if (orgs[i].equals(e.orgStatus)) orgIdx = i;
        detailOrg.setSelection(orgIdx);
        detailText.setText("Source: " + e.source + "   Time: " + e.time + "\n\nREQUEST\n" + requestText(e) + "\n\nRESPONSE\n" + responseText(e));
        detailPanel.setVisibility(View.VISIBLE);
        suitePanel.setVisibility(View.GONE);
        browserPanel.setVisibility(View.GONE);
        historyPanel.setVisibility(View.GONE);
        repeaterPanel.setVisibility(View.GONE);
        rulesPanel.setVisibility(View.GONE);
        intruderPanel.setVisibility(View.GONE);
        toolsPanel.setVisibility(View.GONE);
    }

    // ---------------- Repeater ----------------
    private void buildRepeaterPanel(LinearLayout root) {
        repeaterPanel = new LinearLayout(this);
        repeaterPanel.setOrientation(LinearLayout.VERTICAL);
        repeaterPanel.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
        repeaterPanel.setPadding(dp(8), dp(8), dp(8), dp(8));

        LinearLayout r = new LinearLayout(this);
        r.setOrientation(LinearLayout.HORIZONTAL);
        repMethod = field("GET", false);
        repMethod.setSingleLine(true);
        repUrl = field("https://example.com/path", false);
        repUrl.setSingleLine(true);
        Button send = accentButton("Send");
        send.setOnClickListener(v -> sendRepeater());
        r.addView(repMethod, new LinearLayout.LayoutParams(dp(70), ViewGroup.LayoutParams.WRAP_CONTENT));
        r.addView(repUrl, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        r.addView(send);
        repeaterPanel.addView(r);

        repeaterPanel.addView(label("Headers (one per line, Name: value)", 12, MUTED));
        repHeaders = field("User-Agent: SecuritySuite Android", true);
        repHeaders.setMinLines(3);
        repeaterPanel.addView(repHeaders);
        repeaterPanel.addView(label("Body", 12, MUTED));
        repBody = field("Request body (optional)", true);
        repBody.setMinLines(2);
        repeaterPanel.addView(repBody);
        repeaterPanel.addView(label("Response", 12, MUTED));
        repResponse = field("", true);
        repResponse.setMinLines(8);
        repResponse.setKeyListener(null);
        repeaterPanel.addView(repResponse, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
        root.addView(repeaterPanel);
    }

    private void sendToRepeater(Entry e) {
        repMethod.setText(e.method);
        repUrl.setText(e.url);
        repHeaders.setText(e.headersToText(e.reqHeaders));
        repBody.setText(e.reqBody == null ? "" : e.reqBody);
        repResponse.setText("");
    }

    private void sendRepeater() {
        final Entry e = new Entry();
        e.id = Store.nextId();
        e.time = timeFmt.format(new Date());
        e.method = repMethod.getText().toString().trim().toUpperCase();
        if (e.method.isEmpty()) e.method = "GET";
        e.url = repUrl.getText().toString().trim();
        e.reqHeaders = Entry.parseHeaders(repHeaders.getText().toString());
        String b = repBody.getText().toString();
        e.reqBody = b.isEmpty() ? null : b;
        e.source = "repeater";
        if (e.url.isEmpty()) { Toast.makeText(this, "Enter a URL first", Toast.LENGTH_SHORT).show(); return; }
        repResponse.setText("Sending...");
        pool.execute(() -> {
            long t0 = System.currentTimeMillis();
            try { Engine.fetch(e); e.state = Entry.STATE_COMPLETED; }
            catch (Exception ex) { e.error = ex.getMessage(); }
            long dt = System.currentTimeMillis() - t0;
            final String res = responseText(e) + "\n\nTime: " + dt + " ms";
            Store.addHistory(e);
            ui.post(() -> repResponse.setText(res));
        });
    }

    // ---------------- Intruder ----------------
    private void buildIntruderPanel(LinearLayout root) {
        intruderPanel = new LinearLayout(this);
        intruderPanel.setOrientation(LinearLayout.VERTICAL);
        intruderPanel.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));

        ScrollView sv = new ScrollView(this);
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(dp(8), dp(8), dp(8), dp(8));

        col.addView(sectionTitle("Intruder"));
        col.addView(label("Mark payload positions with the section sign in the URL or body, like: id=§1§ and name=§test§. The text between the signs is the base value.", 11.5f, MUTED));
        LinearLayout mr = new LinearLayout(this);
        mr.setOrientation(LinearLayout.HORIZONTAL);
        inMethod = styledSpinner(new String[]{"GET", "POST", "PUT", "DELETE", "PATCH"});
        inUrl = field("https://target.test/item?id=§1§", false);
        inUrl.setSingleLine(true);
        mr.addView(inMethod);
        mr.addView(inUrl, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        col.addView(mr);
        inHeaders = field("Headers (Name: value per line)", true);
        inHeaders.setMinLines(2);
        col.addView(inHeaders);
        inBody = field("Body, e.g. user=§admin§ and pass=§test§", true);
        inBody.setMinLines(2);
        col.addView(inBody);

        LinearLayout ar = new LinearLayout(this);
        ar.setOrientation(LinearLayout.HORIZONTAL);
        ar.addView(label("Attack type: ", 12, MUTED));
        inAttack = styledSpinner(new String[]{"Sniper", "Battering Ram", "Pitchfork", "Cluster Bomb"});
        ar.addView(inAttack, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        col.addView(ar);
        col.addView(label("Sniper and Battering Ram use Set 1. Pitchfork pairs Set 1 and Set 2 per position. Cluster Bomb combines Set 1 x Set 2. Hard cap: 200 requests per run.", 11, MUTED));

        col.addView(label("Payload Set 1 (one per line)", 12, MUTED));
        inSet1 = field("payload per line", true);
        inSet1.setMinLines(3);
        col.addView(inSet1);
        LinearLayout br = new LinearLayout(this);
        br.setOrientation(LinearLayout.HORIZONTAL);
        Button bNum = smallButton("Numbers 0-50");
        bNum.setOnClickListener(v -> { StringBuilder sb = new StringBuilder(); for (int i = 0; i <= 50; i++) sb.append(i).append("\n"); inSet1.setText(sb.toString()); });
        Button bSqli = smallButton("SQLi list");
        bSqli.setOnClickListener(v -> inSet1.setText("' OR '1'='1\n' OR 1=1--\n' UNION SELECT NULL--\nadmin'--\n' OR 'a'='a\n' AND SLEEP(5)--\n"));
        Button bXss = smallButton("XSS list");
        bXss.setOnClickListener(v -> inSet1.setText("<script>alert(1)</script>\n\"><svg onload=alert(1)>\n<img src=x onerror=alert(1)>\njavascript:alert(1)\n"));
        Button bTrav = smallButton("Traversal list");
        bTrav.setOnClickListener(v -> inSet1.setText("../etc/passwd\n../../etc/passwd\n../../../etc/passwd\n....//....//etc/passwd\n/etc/passwd\n"));
        br.addView(bNum);
        br.addView(bSqli);
        br.addView(bXss);
        br.addView(bTrav);
        col.addView(br);
        col.addView(label("Payload Set 2 (Pitchfork / Cluster Bomb)", 12, MUTED));
        inSet2 = field("payload per line", true);
        inSet2.setMinLines(2);
        col.addView(inSet2);

        LinearLayout gr = new LinearLayout(this);
        gr.setOrientation(LinearLayout.HORIZONTAL);
        inGrep = field("Grep match: comma separated strings to flag in responses", false);
        inGrep.setSingleLine(true);
        inDelay = field("Delay ms", false);
        inDelay.setSingleLine(true);
        inDelay.setText("0");
        gr.addView(inGrep, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        gr.addView(inDelay, new LinearLayout.LayoutParams(dp(80), ViewGroup.LayoutParams.WRAP_CONTENT));
        col.addView(gr);

        LinearLayout runRow = new LinearLayout(this);
        runRow.setOrientation(LinearLayout.HORIZONTAL);
        Button start = accentButton("Start attack");
        start.setOnClickListener(v -> runIntruder());
        Button stop = smallButton("Stop");
        stop.setOnClickListener(v -> { intruderRunning = false; intruderStatus.setText("Stopping..."); });
        intruderStatus = label("Idle. Results appear below; tap a result for the full response.", 11.5f, MUTED);
        runRow.addView(start);
        runRow.addView(stop);
        runRow.addView(intruderStatus);
        col.addView(runRow);

        ListView lv = new ListView(this);
        intruderAdapter = new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, intruderLabels);
        lv.setAdapter(intruderAdapter);
        lv.setOnItemClickListener((parent, view, position, id) -> { if (position < intruderResults.size()) openDetail(intruderResults.get(position)); });
        col.addView(lv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(320)));
        sv.addView(col);
        intruderPanel.addView(sv);
        root.addView(intruderPanel);
    }

    private void sendToIntruder(Entry e) {
        String m = e.method;
        int idx = 0;
        String[] ms = {"GET", "POST", "PUT", "DELETE", "PATCH"};
        for (int i = 0; i < ms.length; i++) if (ms[i].equals(m)) idx = i;
        inMethod.setSelection(idx);
        inUrl.setText(e.url);
        inHeaders.setText(e.headersToText(e.reqHeaders));
        inBody.setText(e.reqBody == null ? "" : e.reqBody);
        Toast.makeText(this, "Loaded into Intruder. Add section-sign positions, then Start.", Toast.LENGTH_SHORT).show();
    }

    private static List<String> parseParts(String template) {
        List<String> parts = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        for (int i = 0; i < template.length(); i++) {
            char c = template.charAt(i);
            if (c == '§') {
                parts.add(cur.toString());
                cur = new StringBuilder();
            } else cur.append(c);
        }
        parts.add(cur.toString());
        return parts;
    }

    private static String buildFromParts(List<String> parts, Map<Integer, String> replacements) {
        StringBuilder sb = new StringBuilder();
        int posIdx = 0;
        for (int i = 0; i < parts.size(); i++) {
            if (i % 2 == 1) {
                String rep = replacements.get(posIdx);
                sb.append(rep != null ? rep : parts.get(i));
                posIdx++;
            } else sb.append(parts.get(i));
        }
        return sb.toString();
    }

    private void runIntruder() {
        if (intruderRunning) { Toast.makeText(this, "An attack is already running", Toast.LENGTH_SHORT).show(); return; }
        final String urlT = inUrl.getText().toString();
        final String bodyT = inBody.getText().toString();
        final String headers = inHeaders.getText().toString();
        final String method = (String) inMethod.getSelectedItem();
        final String attack = (String) inAttack.getSelectedItem();
        final List<String> set1 = lines(inSet1.getText().toString());
        final List<String> set2 = lines(inSet2.getText().toString());
        final List<String> greps = new ArrayList<>();
        for (String g : inGrep.getText().toString().split(",")) if (!g.trim().isEmpty()) greps.add(g.trim());
        int delay = 0;
        try { delay = Integer.parseInt(inDelay.getText().toString().trim()); } catch (Exception ignored) { }
        final int delayMs = delay;

        final List<String> urlParts = parseParts(urlT);
        final List<String> bodyParts = parseParts(bodyT);
        final int urlPos = (urlParts.size() - 1) / 2;
        final int bodyPos = (bodyParts.size() - 1) / 2;
        final int totalPositions = urlPos + bodyPos;
        if (totalPositions == 0) { Toast.makeText(this, "No positions marked. Add section signs around a value first.", Toast.LENGTH_LONG).show(); return; }
        if (set1.isEmpty()) { Toast.makeText(this, "Payload Set 1 is empty", Toast.LENGTH_SHORT).show(); return; }

        final List<Map<String, String>> jobs = new ArrayList<>();
        if (attack.equals("Sniper")) {
            for (int p = 0; p < totalPositions; p++) {
                for (String pay : set1) {
                    Map<String, String> m = new HashMap<>();
                    m.put("pos" + p, pay);
                    m.put("label", pay);
                    jobs.add(m);
                }
            }
        } else if (attack.equals("Battering Ram")) {
            for (String pay : set1) {
                Map<String, String> m = new HashMap<>();
                for (int p = 0; p < totalPositions; p++) m.put("pos" + p, pay);
                m.put("label", pay);
                jobs.add(m);
            }
        } else if (attack.equals("Pitchfork")) {
            int n = set2.isEmpty() ? set1.size() : Math.min(set1.size(), set2.size());
            for (int k = 0; k < n; k++) {
                Map<String, String> m = new HashMap<>();
                for (int p = 0; p < totalPositions; p++) {
                    m.put("pos" + p, p % 2 == 0 ? set1.get(k) : (set2.isEmpty() ? set1.get(k) : set2.get(k)));
                }
                m.put("label", set1.get(k) + (set2.isEmpty() ? "" : " | " + set2.get(k)));
                jobs.add(m);
            }
        } else {
            List<String> second = set2.isEmpty() ? set1 : set2;
            outer:
            for (String a : set1) {
                for (String b : second) {
                    Map<String, String> m = new HashMap<>();
                    m.put("pos0", a);
                    if (totalPositions > 1) m.put("pos1", b);
                    m.put("label", a + " | " + b);
                    jobs.add(m);
                    if (jobs.size() >= 200) break outer;
                }
            }
        }
        if (jobs.size() > 200) {
            Toast.makeText(this, "Capped at 200 requests (was " + jobs.size() + ")", Toast.LENGTH_SHORT).show();
            while (jobs.size() > 200) jobs.remove(jobs.size() - 1);
        }

        intruderResults.clear();
        intruderLabels.clear();
        intruderAdapter.notifyDataSetChanged();
        intruderRunning = true;
        intruderStatus.setText("Running " + jobs.size() + " requests (" + attack + ")...");
        final int totalJobs = jobs.size();

        pool.execute(() -> {
            int done = 0;
            for (Map<String, String> job : jobs) {
                if (!intruderRunning) break;
                Map<Integer, String> urlRep = new HashMap<>();
                Map<Integer, String> bodyRep = new HashMap<>();
                for (Map.Entry<String, String> kv : job.entrySet()) {
                    if (!kv.getKey().startsWith("pos")) continue;
                    int p = Integer.parseInt(kv.getKey().substring(3));
                    if (p < urlPos) urlRep.put(p, kv.getValue());
                    else bodyRep.put(p - urlPos, kv.getValue());
                }
                Entry e = new Entry();
                e.id = Store.nextId();
                e.time = timeFmt.format(new Date());
                e.method = method;
                e.url = buildFromParts(urlParts, urlRep);
                String builtBody = buildFromParts(bodyParts, bodyRep);
                e.reqBody = builtBody.isEmpty() ? null : builtBody;
                e.reqHeaders = Entry.parseHeaders(headers);
                e.source = "intruder";
                long t0 = System.currentTimeMillis();
                try { Engine.fetch(e); e.state = Entry.STATE_COMPLETED; } catch (Exception ex) { e.error = ex.getMessage(); }
                long dt = System.currentTimeMillis() - t0;
                String grepHit = "";
                if (!greps.isEmpty() && e.respBodyText != null) {
                    for (String g : greps) if (e.respBodyText.contains(g)) { grepHit = " [GREP: " + g + "]"; break; }
                }
                int len = e.respBodyText == null ? 0 : e.respBodyText.length();
                final String lab = "#" + (done + 1) + "  " + job.get("label") + "  ->  " + e.status + "  " + len + " bytes  " + dt + " ms" + grepHit + (e.error != null ? "  ERR" : "");
                synchronized (intruderResults) {
                    intruderResults.add(e);
                    intruderLabels.add(lab);
                }
                Store.addHistory(e);
                done++;
                final int d = done;
                ui.post(() -> {
                    intruderAdapter.notifyDataSetChanged();
                    intruderStatus.setText("Running... " + d + " / " + totalJobs);
                });
                if (delayMs > 0) { try { Thread.sleep(delayMs); } catch (InterruptedException ignored) { } }
            }
            intruderRunning = false;
            ui.post(() -> intruderStatus.setText("Done. " + intruderResults.size() + " results. Tap one for the full response."));
        });
    }

    private static List<String> lines(String text) {
        List<String> out = new ArrayList<>();
        for (String l : text.split("\n")) if (!l.isEmpty()) out.add(l);
        return out;
    }

    // ---------------- Tools ----------------
    private void buildToolsPanel(LinearLayout root) {
        toolsPanel = new LinearLayout(this);
        toolsPanel.setOrientation(LinearLayout.VERTICAL);
        toolsPanel.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
        toolsPanel.setPadding(dp(8), dp(8), dp(8), dp(8));

        toolSelect = styledSpinner(new String[]{"Decoder", "Comparer", "Sequencer", "Scanner", "Site Map", "OAST payloads"});
        toolSelect.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent, View view, int pos, long id) { showTool(pos); }
            @Override public void onNothingSelected(AdapterView<?> parent) { }
        });
        toolsPanel.addView(toolSelect);

        ScrollView sv = new ScrollView(this);
        LinearLayout holder = new LinearLayout(this);
        holder.setOrientation(LinearLayout.VERTICAL);
        buildDecoderBox(holder);
        buildComparerBox(holder);
        buildSequencerBox(holder);
        buildScannerBox(holder);
        buildSitemapBox(holder);
        buildOastBox(holder);
        sv.addView(holder);
        toolsPanel.addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
        root.addView(toolsPanel);
    }

    private void showTool(int pos) {
        if (decoderBox == null) return;
        decoderBox.setVisibility(pos == 0 ? View.VISIBLE : View.GONE);
        comparerBox.setVisibility(pos == 1 ? View.VISIBLE : View.GONE);
        sequencerBox.setVisibility(pos == 2 ? View.VISIBLE : View.GONE);
        scannerBox.setVisibility(pos == 3 ? View.VISIBLE : View.GONE);
        sitemapBox.setVisibility(pos == 4 ? View.VISIBLE : View.GONE);
        oastBox.setVisibility(pos == 5 ? View.VISIBLE : View.GONE);
        if (pos == 4) refreshSitemap();
    }

    private void buildDecoderBox(LinearLayout holder) {
        decoderBox = new LinearLayout(this);
        decoderBox.setOrientation(LinearLayout.VERTICAL);
        decoderBox.addView(sectionTitle("Decoder"));
        decInput = field("Text to encode, decode or hash...", true);
        decoderBox.addView(decInput);
        LinearLayout r = new LinearLayout(this);
        r.setOrientation(LinearLayout.HORIZONTAL);
        decOp = styledSpinner(Features.DECODER_OPS);
        Button run = accentButton("Run");
        run.setOnClickListener(v -> {
            try { decOutput.setText(Features.decode((String) decOp.getSelectedItem(), decInput.getText().toString())); }
            catch (Exception e) { decOutput.setText("Error: " + e.getMessage()); }
        });
        Button chain = smallButton("Output to input");
        chain.setOnClickListener(v -> decInput.setText(decOutput.getText().toString()));
        r.addView(decOp, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        r.addView(run);
        r.addView(chain);
        decoderBox.addView(r);
        decOutput = field("", true);
        decOutput.setMinLines(6);
        decOutput.setKeyListener(null);
        decoderBox.addView(decOutput);
        holder.addView(decoderBox);
    }

    private void buildComparerBox(LinearLayout holder) {
        comparerBox = new LinearLayout(this);
        comparerBox.setOrientation(LinearLayout.VERTICAL);
        comparerBox.addView(sectionTitle("Comparer"));
        comparerBox.addView(label("Paste two responses, or send one here from a history item's detail view, then compare.", 11.5f, MUTED));
        cmpA = field("Left text", true);
        cmpA.setMinLines(3);
        comparerBox.addView(cmpA);
        cmpB = field("Right text", true);
        cmpB.setMinLines(3);
        comparerBox.addView(cmpB);
        LinearLayout r = new LinearLayout(this);
        r.setOrientation(LinearLayout.HORIZONTAL);
        Button words = accentButton("Compare words");
        words.setOnClickListener(v -> cmpOutput.setText(Features.wordDiff(cmpA.getText().toString(), cmpB.getText().toString())));
        Button bytes = smallButton("Compare bytes");
        bytes.setOnClickListener(v -> cmpOutput.setText(Features.byteDiff(cmpA.getText().toString(), cmpB.getText().toString())));
        r.addView(words);
        r.addView(bytes);
        comparerBox.addView(r);
        cmpOutput = field("", true);
        cmpOutput.setMinLines(6);
        cmpOutput.setKeyListener(null);
        comparerBox.addView(cmpOutput);
        holder.addView(comparerBox);
    }

    private void buildSequencerBox(LinearLayout holder) {
        sequencerBox = new LinearLayout(this);
        sequencerBox.setOrientation(LinearLayout.VERTICAL);
        sequencerBox.addView(sectionTitle("Sequencer (token analysis)"));
        sequencerBox.addView(label("Fetches a URL repeatedly and analyses the tokens it issues: uniqueness, length, character entropy, predictability. Give a cookie name OR a regex with one capture group.", 11.5f, MUTED));
        seqUrl = field("https://target.test/login", false);
        seqUrl.setSingleLine(true);
        sequencerBox.addView(seqUrl);
        LinearLayout r = new LinearLayout(this);
        r.setOrientation(LinearLayout.HORIZONTAL);
        seqCount = field("Count (max 100)", false);
        seqCount.setSingleLine(true);
        seqCount.setText("20");
        seqCookie = field("Cookie name (e.g. session)", false);
        seqCookie.setSingleLine(true);
        r.addView(seqCount, new LinearLayout.LayoutParams(dp(110), ViewGroup.LayoutParams.WRAP_CONTENT));
        r.addView(seqCookie, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        sequencerBox.addView(r);
        seqRegex = field("Or regex, e.g. token=([A-Za-z0-9._-]+)", false);
        seqRegex.setSingleLine(true);
        sequencerBox.addView(seqRegex);
        Button run = accentButton("Capture and analyse");
        run.setOnClickListener(v -> runSequencer());
        sequencerBox.addView(run);
        seqOutput = field("", true);
        seqOutput.setMinLines(6);
        seqOutput.setKeyListener(null);
        sequencerBox.addView(seqOutput);
        holder.addView(sequencerBox);
    }

    private void runSequencer() {
        final String url = seqUrl.getText().toString().trim();
        if (url.isEmpty()) { Toast.makeText(this, "Enter a URL", Toast.LENGTH_SHORT).show(); return; }
        int count = 20;
        try { count = Math.min(100, Integer.parseInt(seqCount.getText().toString().trim())); } catch (Exception ignored) { }
        final int n = count;
        final String cookieName = seqCookie.getText().toString().trim();
        final String regex = seqRegex.getText().toString().trim();
        seqOutput.setText("Capturing " + n + " tokens...");
        pool.execute(() -> {
            List<String> tokens = new ArrayList<>();
            Pattern pat = null;
            if (!regex.isEmpty()) { try { pat = Pattern.compile(regex); } catch (Exception ignored) { } }
            for (int i = 0; i < n; i++) {
                Entry e = new Entry();
                e.id = Store.nextId();
                e.time = timeFmt.format(new Date());
                e.method = "GET";
                e.url = url;
                e.source = "sequencer";
                try { Engine.fetch(e); } catch (Exception ex) { break; }
                Store.addHistory(e);
                String found = null;
                if (!cookieName.isEmpty()) {
                    for (String[] h : e.respHeaders) {
                        if (h[0].equalsIgnoreCase("Set-Cookie") && h[1].startsWith(cookieName + "=")) {
                            String v = h[1].substring(cookieName.length() + 1);
                            int semi = v.indexOf(';');
                            found = semi >= 0 ? v.substring(0, semi) : v;
                            break;
                        }
                    }
                } else if (pat != null) {
                    Matcher m = pat.matcher(e.respBodyText == null ? "" : e.respBodyText);
                    if (m.find()) found = m.group(1);
                    if (found == null) {
                        StringBuilder hb = new StringBuilder();
                        for (String[] h : e.respHeaders) hb.append(h[0]).append(": ").append(h[1]).append("\n");
                        m = pat.matcher(hb.toString());
                        if (m.find()) found = m.group(1);
                    }
                }
                if (found != null) tokens.add(found);
            }
            final String out = tokens.isEmpty()
                ? "No tokens captured. Check the cookie name or regex against a real response (open one in History)."
                : Features.tokenStats(tokens);
            ui.post(() -> seqOutput.setText(out));
        });
    }

    private void buildScannerBox(LinearLayout holder) {
        scannerBox = new LinearLayout(this);
        scannerBox.setOrientation(LinearLayout.VERTICAL);
        scannerBox.addView(sectionTitle("Scanner (passive)"));
        scannerBox.addView(label("Fetches a URL and runs passive checks: security headers, cookie flags, CORS, version disclosure, secret patterns. Leave the URL empty to scan the most recent history entry. Active scanning is not faked here: use Intruder with your own payloads for active tests.", 11.5f, MUTED));
        scanUrl = field("https://target.test/ (empty = latest history entry)", false);
        scanUrl.setSingleLine(true);
        scannerBox.addView(scanUrl);
        Button run = accentButton("Fetch and scan");
        run.setOnClickListener(v -> runScanner());
        scannerBox.addView(run);
        scanOutput = field("", true);
        scanOutput.setMinLines(6);
        scanOutput.setKeyListener(null);
        scannerBox.addView(scanOutput);
        holder.addView(scannerBox);
    }

    private void runScanner() {
        final String url = scanUrl.getText().toString().trim();
        if (url.isEmpty()) {
            Entry latest = null;
            synchronized (Store.history) { if (!Store.history.isEmpty()) latest = Store.history.get(0); }
            if (latest == null) { scanOutput.setText("No history yet. Browse something first, or enter a URL."); return; }
            StringBuilder sb = new StringBuilder("Passive scan of " + latest.method + " " + latest.url + "\n\n");
            for (String issue : Features.passiveScan(latest)) sb.append(issue).append("\n");
            scanOutput.setText(sb.toString());
            return;
        }
        scanOutput.setText("Fetching and scanning...");
        pool.execute(() -> {
            Entry e = new Entry();
            e.id = Store.nextId();
            e.time = timeFmt.format(new Date());
            e.method = "GET";
            e.url = url;
            e.source = "scanner";
            try { Engine.fetch(e); } catch (Exception ex) { e.error = ex.getMessage(); }
            Store.addHistory(e);
            StringBuilder sb = new StringBuilder("Passive scan of GET " + url + " -> " + e.status + "\n\n");
            if (e.error != null) sb.append("Error: ").append(e.error).append("\n");
            for (String issue : Features.passiveScan(e)) sb.append(issue).append("\n");
            final String out = sb.toString();
            ui.post(() -> scanOutput.setText(out));
        });
    }

    private void buildSitemapBox(LinearLayout holder) {
        sitemapBox = new LinearLayout(this);
        sitemapBox.setOrientation(LinearLayout.VERTICAL);
        sitemapBox.addView(sectionTitle("Site Map (Target)"));
        sitemapText = label("", 12, TEXT);
        sitemapText.setTypeface(Typeface.MONOSPACE);
        sitemapBox.addView(sitemapText);
        holder.addView(sitemapBox);
    }

    private void refreshSitemap() {
        if (sitemapText == null) return;
        Map<String, TreeSet<String>> map = new TreeMap<>();
        synchronized (Store.history) {
            for (Entry e : Store.history) {
                try {
                    Uri u = Uri.parse(e.url);
                    String host = u.getHost() == null ? "(unknown)" : u.getHost();
                    String path = (u.getPath() == null || u.getPath().isEmpty() ? "/" : u.getPath());
                    TreeSet<String> set = map.get(host);
                    if (set == null) { set = new TreeSet<>(); map.put(host, set); }
                    set.add(e.method + " " + path);
                } catch (Exception ignored) { }
            }
        }
        if (map.isEmpty()) { sitemapText.setText("No traffic yet. Browse a site in Proxy mode and its structure appears here."); return; }
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, TreeSet<String>> en : map.entrySet()) {
            sb.append(en.getKey()).append("  (").append(en.getValue().size()).append(" paths)\n");
            for (String p : en.getValue()) sb.append("   ").append(p).append("\n");
            sb.append("\n");
        }
        sitemapText.setText(sb.toString());
    }

    private void buildOastBox(LinearLayout holder) {
        oastBox = new LinearLayout(this);
        oastBox.setOrientation(LinearLayout.VERTICAL);
        oastBox.addView(sectionTitle("OAST / Collaborator payloads"));
        oastBox.addView(label("Out-of-band testing needs a server that records DNS and HTTP interactions. SecuritySuite does not run one, and nothing here is faked. If you run your own OAST server (for example an interactsh server), enter its domain and generate unique payload subdomains to place in requests. Interactions then appear on YOUR server.", 11.5f, MUTED));
        oastDomain = field("your-oast-domain.example.com", false);
        oastDomain.setSingleLine(true);
        oastBox.addView(oastDomain);
        Button gen = accentButton("Generate payloads");
        gen.setOnClickListener(v -> {
            String d = oastDomain.getText().toString().trim();
            if (d.isEmpty()) { Toast.makeText(this, "Enter your OAST domain first", Toast.LENGTH_SHORT).show(); return; }
            String id = Long.toString(System.currentTimeMillis(), 36);
            StringBuilder sb = new StringBuilder();
            sb.append("Payloads for this test session (id ").append(id).append("):\n\n");
            sb.append("http://ss").append(id).append(".").append(d).append("/\n");
            sb.append("https://ss").append(id).append(".").append(d).append("/\n");
            sb.append("Email: ss").append(id).append("@").append(d).append("\n\n");
            sb.append("Use them as values in Repeater or Intruder (SSRF, XXE, blind XSS targets). Then check your OAST server for DNS/HTTP interactions with this id.");
            oastOutput.setText(sb.toString());
        });
        oastBox.addView(gen);
        oastOutput = field("", true);
        oastOutput.setMinLines(5);
        oastOutput.setKeyListener(null);
        oastBox.addView(oastOutput);
        holder.addView(oastBox);
    }

    // ---------------- Rules + settings ----------------
    private void buildRulesPanel(LinearLayout root) {
        rulesPanel = new LinearLayout(this);
        rulesPanel.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
        ScrollView sv = new ScrollView(this);
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(dp(10), dp(10), dp(10), dp(10));

        col.addView(sectionTitle("Skip and scope rules"));
        col.addView(label("Skipped traffic is auto-forwarded even with Intercept on, but still logged in History with the rule noted. One entry per line.", 11.5f, MUTED));
        skipEnabledCb = new CheckBox(this);
        skipEnabledCb.setText("Enable skip rules");
        skipEnabledCb.setTextColor(TEXT);
        skipEnabledCb.setChecked(Rules.enabled);
        col.addView(skipEnabledCb);
        col.addView(label("Skip hosts (supports *.example.com)", 12, MUTED));
        skipHostsEt = field("*.google-analytics.com", true);
        skipHostsEt.setMinLines(2);
        skipHostsEt.setText(Rules.join(Rules.skipHosts));
        col.addView(skipHostsEt);
        col.addView(label("Skip IPs / CIDRs (e.g. 192.168.1.0/24)", 12, MUTED));
        skipIpsEt = field("192.168.1.0/24", true);
        skipIpsEt.setMinLines(2);
        skipIpsEt.setText(Rules.join(Rules.skipIps));
        col.addView(skipIpsEt);
        col.addView(label("Skip paths / directories (substring, e.g. /static/)", 12, MUTED));
        skipPathsEt = field("/static/", true);
        skipPathsEt.setMinLines(2);
        skipPathsEt.setText(Rules.join(Rules.skipPaths));
        col.addView(skipPathsEt);
        col.addView(label("Skip extensions", 12, MUTED));
        skipExtsEt = field("png, jpg, css", false);
        skipExtsEt.setSingleLine(true);
        skipExtsEt.setText(Rules.join(Rules.skipExts));
        col.addView(skipExtsEt);
        col.addView(label("Skip methods", 12, MUTED));
        skipMethodsEt = field("OPTIONS", false);
        skipMethodsEt.setSingleLine(true);
        skipMethodsEt.setText(Rules.join(Rules.skipMethods));
        col.addView(skipMethodsEt);
        col.addView(label("Only intercept these hosts (empty = all in scope)", 12, MUTED));
        onlyHostsEt = field("target.test", true);
        onlyHostsEt.setMinLines(2);
        onlyHostsEt.setText(Rules.join(Rules.onlyHosts));
        col.addView(onlyHostsEt);

        col.addView(sectionTitle("Match and replace"));
        col.addView(label("Applied to proxied traffic. One rule per line: req|find|replace or resp|find|replace. Plain text match. Requests: applied to URL and body. Responses: applied to text bodies.", 11.5f, MUTED));
        mrRulesEt = field("req|oldValue|newValue", true);
        mrRulesEt.setMinLines(3);
        mrRulesEt.setText(prefs.getString("mrRules", ""));
        col.addView(mrRulesEt);

        col.addView(sectionTitle("Settings"));
        col.addView(label("Upstream proxy (optional, for the app's own requests). Leave host empty for direct.", 12, MUTED));
        LinearLayout ur = new LinearLayout(this);
        ur.setOrientation(LinearLayout.HORIZONTAL);
        setUpstreamHost = field("Proxy host", false);
        setUpstreamHost.setSingleLine(true);
        setUpstreamHost.setText(prefs.getString("upHost", ""));
        setUpstreamPort = field("Port", false);
        setUpstreamPort.setSingleLine(true);
        int up = prefs.getInt("upPort", 0);
        setUpstreamPort.setText(up > 0 ? String.valueOf(up) : "");
        ur.addView(setUpstreamHost, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        ur.addView(setUpstreamPort, new LinearLayout.LayoutParams(dp(90), ViewGroup.LayoutParams.WRAP_CONTENT));
        col.addView(ur);
        col.addView(label("User-Agent override (tools; the browser keeps its own)", 12, MUTED));
        setUa = field("Custom User-Agent", false);
        setUa.setSingleLine(true);
        setUa.setText(prefs.getString("uaOverride", ""));
        col.addView(setUa);
        col.addView(label("Request timeout (seconds)", 12, MUTED));
        setTimeout = field("20", false);
        setTimeout.setSingleLine(true);
        setTimeout.setText(String.valueOf(prefs.getInt("timeoutSec", 20)));
        col.addView(setTimeout);

        Button save = accentButton("Save rules and settings");
        save.setOnClickListener(v -> {
            Rules.enabled = skipEnabledCb.isChecked();
            Rules.skipHosts = Rules.split(skipHostsEt.getText().toString());
            Rules.skipIps = Rules.split(skipIpsEt.getText().toString());
            Rules.skipPaths = Rules.split(skipPathsEt.getText().toString());
            Rules.skipExts = Rules.split(skipExtsEt.getText().toString());
            Rules.skipMethods = Rules.split(skipMethodsEt.getText().toString());
            Rules.onlyHosts = Rules.split(onlyHostsEt.getText().toString());
            Rules.save(prefs);
            String upHost = setUpstreamHost.getText().toString().trim();
            int upPort = 0;
            try { upPort = Integer.parseInt(setUpstreamPort.getText().toString().trim()); } catch (Exception ignored) { }
            int tsec = 20;
            try { tsec = Integer.parseInt(setTimeout.getText().toString().trim()); } catch (Exception ignored) { }
            prefs.edit()
                .putString("mrRules", mrRulesEt.getText().toString())
                .putString("upHost", upHost)
                .putInt("upPort", upPort)
                .putString("uaOverride", setUa.getText().toString().trim())
                .putInt("timeoutSec", tsec)
                .apply();
            Engine.upstreamHost = upHost;
            Engine.upstreamPort = upPort;
            Engine.uaOverride = setUa.getText().toString().trim();
            Engine.timeoutSec = tsec;
            Toast.makeText(this, "Rules and settings saved", Toast.LENGTH_SHORT).show();
        });
        col.addView(save);
        col.addView(label("Honest limits: only this app's own browser traffic is captured, not other apps. PATCH requests pass through natively (Android's HTTP engine cannot send them). Heavy JavaScript, WebSocket and streaming sites may break in Proxy mode; use Native mode for those. The web Suite tab has the full desktop-style tools in the browser.", 11, MUTED));

        sv.addView(col);
        rulesPanel.addView(sv);
        root.addView(rulesPanel);
    }

    // ---------------- Tabs / refresh ----------------
    private void showTab(int idx) {
        currentTab = idx;
        detailPanel.setVisibility(View.GONE);
        suitePanel.setVisibility(idx == 0 ? View.VISIBLE : View.GONE);
        browserPanel.setVisibility(idx == 1 ? View.VISIBLE : View.GONE);
        historyPanel.setVisibility(idx == 2 ? View.VISIBLE : View.GONE);
        intruderPanel.setVisibility(idx == 3 ? View.VISIBLE : View.GONE);
        repeaterPanel.setVisibility(idx == 4 ? View.VISIBLE : View.GONE);
        toolsPanel.setVisibility(idx == 5 ? View.VISIBLE : View.GONE);
        rulesPanel.setVisibility(idx == 6 ? View.VISIBLE : View.GONE);
        for (int i = 0; i < tabButtons.length; i++) {
            boolean active = i == idx;
            tabButtons[i].setBackground(rounded(active ? ORANGE : PANEL2, 8, active ? 0 : BORDER));
            tabButtons[i].setTextColor(active ? Color.WHITE : TEXT);
        }
        if (idx == 5 && toolSelect != null) showTool(toolSelect.getSelectedItemPosition());
        refreshUi();
    }

    private void refreshUi() {
        String q = historySearch == null ? "" : historySearch.getText().toString().toLowerCase().trim();
        displayedHistory.clear();
        historyLabels.clear();
        synchronized (Store.history) {
            for (Entry e : Store.history) { // newest first
                if (!q.isEmpty()) {
                    String hay = (e.method + " " + e.url + " " + e.status + " " + e.source).toLowerCase();
                    if (!hay.contains(q)) continue;
                }
                displayedHistory.add(e);
                String state = e.state == Entry.STATE_HELD ? "HELD " : e.state == Entry.STATE_DROPPED ? "DROPPED " : "";
                String noteMark = e.note2 != null && !e.note2.isEmpty() ? " [note]" : "";
                historyLabels.add(state + e.method + "  " + (e.status == null ? "..." : e.status) + "  " + e.url
                    + (e.error != null ? "  ERR" : "") + noteMark + "  [" + e.orgStatus + "]");
            }
        }
        if (historyAdapter != null) historyAdapter.notifyDataSetChanged();

        Entry keep = selected;
        splitItems.clear();
        List<String> labels = new ArrayList<>();
        synchronized (Store.queue) {
            for (Entry e : Store.queue) { splitItems.add(e); labels.add("HELD: " + e.method + " " + shortUrl(e.url)); }
        }
        synchronized (Store.history) {
            for (Entry e : Store.history) {
                if (splitItems.size() >= 30) break;
                if (e.state != Entry.STATE_HELD && !splitItems.contains(e)) { splitItems.add(e); labels.add(e.method + " " + (e.status == null ? "..." : e.status) + " " + shortUrl(e.url)); }
            }
        }
        if (splitAdapter != null) {
            splitAdapter.clear();
            splitAdapter.addAll(labels);
            splitAdapter.notifyDataSetChanged();
        }
        if (keep != null && splitItems.contains(keep)) {
            selected = keep;
            if (splitSelect != null) splitSelect.setSelection(splitItems.indexOf(keep));
        } else if (!splitItems.isEmpty()) {
            selected = splitItems.get(0);
            if (splitSelect != null) splitSelect.setSelection(0);
        } else {
            selected = null;
        }
        if (splitBody != null) renderSplit();
    }

    private static String shortUrl(String u) {
        return u.length() > 52 ? u.substring(0, 52) + "..." : u;
    }

    private void exportHistory() {
        try {
            JSONArray arr = new JSONArray();
            synchronized (Store.history) {
                for (Entry e : Store.history) {
                    JSONObject o = new JSONObject();
                    o.put("method", e.method);
                    o.put("url", e.url);
                    o.put("status", e.status == null ? JSONObject.NULL : e.status);
                    o.put("source", e.source);
                    o.put("requestHeaders", e.headersToText(e.reqHeaders));
                    o.put("requestBody", e.reqBody == null ? "" : e.reqBody);
                    o.put("responseBody", e.respBodyText == null ? "" : (e.respBodyText.length() > 4000 ? e.respBodyText.substring(0, 4000) : e.respBodyText));
                    o.put("note", e.note2 == null ? "" : e.note2);
                    o.put("organizerStatus", e.orgStatus);
                    o.put("time", e.time);
                    arr.put(o);
                }
            }
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            cm.setPrimaryClip(ClipData.newPlainText("SecuritySuite history", arr.toString(2)));
            Toast.makeText(this, "History JSON copied to clipboard (" + arr.length() + " entries)", Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            Toast.makeText(this, "Export failed: " + e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    // ---------------- Proxy WebView client ----------------
    class ProxyClient extends WebViewClient {
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

            if (!proxyMode || e.method.equals("PATCH")) {
                e.state = Entry.STATE_PASSTHROUGH;
                if (e.method.equals("PATCH")) e.note = "PATCH passed through natively: the Android HTTP engine cannot send it, so this entry is request-line only.";
                Store.addHistory(e);
                return null;
            }

            if (e.method.equals("POST") || e.method.equals("PUT") || e.method.equals("DELETE")) {
                String body = Store.takeBody(e.method, e.url);
                if (body != null) e.reqBody = body;
            }

            // Match and replace on the request (URL and body)
            String mr = prefs.getString("mrRules", "");
            if (!mr.isEmpty()) {
                e.url = Features.applyMatchReplace(mr, true, e.url);
                if (e.reqBody != null) e.reqBody = Features.applyMatchReplace(mr, true, e.reqBody);
            }

            Store.addHistory(e);

            String skip = Rules.skipReason(e);
            if (skip != null) e.note = "Not held, " + skip + ".";

            boolean smartScope = scopeSpinner != null && scopeSpinner.getSelectedItemPosition() == 0;
            if (skip == null && interceptToggle != null && interceptToggle.isChecked() && shouldHold(e, smartScope)) {
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
                // Match and replace on text responses
                if (!mr.isEmpty() && r.mime != null && (r.mime.contains("text") || r.mime.contains("json") || r.mime.contains("javascript") || r.mime.contains("xml"))) {
                    try {
                        Charset cs = Charset.forName(r.charset == null ? "UTF-8" : r.charset);
                        String bt = new String(body, cs);
                        String replaced = Features.applyMatchReplace(mr, false, bt);
                        if (!replaced.equals(bt)) {
                            body = replaced.getBytes(cs);
                            e.respBodyText = replaced.length() > 256 * 1024 ? replaced.substring(0, 256 * 1024) : replaced;
                        }
                    } catch (Exception ignored) { }
                }
                if (e.mainFrame && r.mime != null && r.mime.contains("html")) body = Shim.inject(body, r.charset);
                Store.changed();
                return new WebResourceResponse(r.mime, r.charset, r.status, sanitizeReason(r),
                        Engine.headersForWebView(r), new ByteArrayInputStream(body));
            } catch (Exception ex) {
                e.error = ex.getMessage();
                e.state = Entry.STATE_COMPLETED;
                Store.changed();
                String html = "<html><body style='background:#0e0e12;color:#e8e8ec;font-family:sans-serif;padding:20px'><h3>SecuritySuite engine could not fetch this page</h3><p>"
                        + escapeHtml(e.url) + "</p><p>" + escapeHtml(String.valueOf(e.error)) + "</p><p>Try Native mode for this site, or check the target and your connection.</p></body></html>";
                if (e.mainFrame) return new WebResourceResponse("text/html", "utf-8", 200, "OK", null, new ByteArrayInputStream(html.getBytes(Charset.forName("UTF-8"))));
                return new WebResourceResponse("text/plain", "utf-8", 502, "Bad Gateway", null, new ByteArrayInputStream(new byte[0]));
            }
        }

        private boolean shouldHold(Entry e, boolean smartScope) {
            if (e.mainFrame) return true;
            if (e.method.equals("POST") || e.method.equals("PUT") || e.method.equals("DELETE")) return true;
            if (!smartScope) return true; // Scope: All
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
                String html = "<html><body style='background:#0e0e12;color:#e8e8ec;font-family:sans-serif;padding:20px'><h3>Dropped by SecuritySuite Intercept</h3><p>" + escapeHtml(e.method + " " + e.url) + "</p></body></html>";
                return new WebResourceResponse("text/html", "utf-8", 200, "OK", null, new ByteArrayInputStream(html.getBytes(Charset.forName("UTF-8"))));
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
    }

    @Override
    public void onBackPressed() {
        if (detailPanel.getVisibility() == View.VISIBLE) {
            showTab(2);
            return;
        }
        if (currentTab == 1 && browser != null && browser.canGoBack()) {
            browser.goBack();
            return;
        }
        super.onBackPressed();
    }

    @Override
    protected void onDestroy() {
        pool.shutdownNow();
        super.onDestroy();
    }
}
