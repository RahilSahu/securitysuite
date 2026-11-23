package app.securitysuite.mobile;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.EditorInfo;
import android.webkit.JavascriptInterface;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ScrollView;
import android.widget.Spinner;
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
    private LinearLayout browserSplit;
    private LinearLayout splitPanel;
    private EditText urlInput;
    private ToggleButton interceptToggle, modeToggle, scopeToggle;
    private Button layoutBtn;
    private int layoutMode = 0; // 0 split, 1 browser full, 2 panel full

    // Split interceptor panel
    private TextView splitStatus;
    private Spinner queueSpinner;
    private ArrayAdapter<String> queueSpinAdapter;
    private final List<String> queueSpinLabels = new ArrayList<>();
    private EditText spUrl, spHeaders, spBody;
    private TextView spResponse;
    private FrameLayout spContent;
    private LinearLayout spReqBox;
    private ScrollView spRespBox;
    private Button spReqTab, spRespTab;
    private Entry selectedEntry;
    private boolean followLatest = true;

    // History
    private LinearLayout historyPanel;
    private ListView historyList;
    private TextView historyInfo;
    private ArrayAdapter<String> historyAdapter;
    private final List<String> historyLabels = new ArrayList<>();

    // Detail
    private LinearLayout detailPanel;
    private TextView detailText;
    private Entry detailEntry;

    // Repeater
    private LinearLayout repeaterPanel;
    private EditText rpMethod, rpUrl, rpHeaders, rpBody, rpResponse;

    // Rules
    private LinearLayout rulesPanel;
    private EditText ruSkipHosts, ruSkipIps, ruSkipPaths, ruSkipExts, ruSkipMethods, ruOnlyHosts;

    private Button tabSuite, tabBrowser, tabHistory, tabRepeater, tabRules;
    private int currentTab = 1;
    private final SimpleDateFormat timeFmt = new SimpleDateFormat("HH:mm:ss", Locale.US);

    public class BodyBridge {
        @JavascriptInterface
        public void reportBody(String json) { Store.putBodyJson(json); }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        SharedPreferences prefs = getSharedPreferences("securitysuite", MODE_PRIVATE);
        Rules.load(prefs);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BG);

        // ---- Browser chrome ----
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
        modeToggle = toggle("Proxy", "Native");
        modeToggle.setChecked(true);
        interceptToggle = toggle("Intercept ON", "Intercept OFF");
        interceptToggle.setChecked(true);
        scopeToggle = toggle("Smart", "All");
        scopeToggle.setChecked(true);
        layoutBtn = smallButton("View: Split");
        layoutBtn.setOnClickListener(v -> cycleLayout());
        modeRow.addView(modeToggle);
        modeRow.addView(interceptToggle);
        modeRow.addView(scopeToggle);
        modeRow.addView(layoutBtn);
        browserChrome.addView(modeRow);
        root.addView(browserChrome);

        // ---- Stage ----
        stage = new FrameLayout(this);
        stage.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        root.addView(stage);

        suiteWeb = makeWebView();
        suiteWeb.setWebViewClient(new WebViewClient());
        suiteWeb.loadUrl(SUITE_URL);
        stage.addView(suiteWeb);

        // ---- Split: browser top, interceptor bottom ----
        browserSplit = new LinearLayout(this);
        browserSplit.setOrientation(LinearLayout.VERTICAL);
        browserWeb = makeWebView();
        browserWeb.addJavascriptInterface(new BodyBridge(), "SSBridge");
        browserWeb.setWebViewClient(new ProxyClient());
        browserWeb.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        browserSplit.addView(browserWeb);
        buildSplitPanel();
        browserSplit.addView(splitPanel);
        stage.addView(browserSplit);

        buildHistoryPanel();
        buildDetailPanel();
        buildRepeaterPanel();
        buildRulesPanel(prefs);
        stage.addView(historyPanel);
        stage.addView(repeaterPanel);
        stage.addView(rulesPanel);
        stage.addView(detailPanel);

        // ---- Bottom tabs ----
        LinearLayout tabs = new LinearLayout(this);
        tabs.setOrientation(LinearLayout.HORIZONTAL);
        tabs.setBackgroundColor(PANEL);
        tabSuite = tab("Suite");
        tabBrowser = tab("Browser");
        tabHistory = tab("History");
        tabRepeater = tab("Repeater");
        tabRules = tab("Rules");
        tabSuite.setOnClickListener(v -> showTab(0));
        tabBrowser.setOnClickListener(v -> showTab(1));
        tabHistory.setOnClickListener(v -> showTab(3));
        tabRepeater.setOnClickListener(v -> showTab(4));
        tabRules.setOnClickListener(v -> showTab(5));
        tabs.addView(tabSuite);
        tabs.addView(tabBrowser);
        tabs.addView(tabHistory);
        tabs.addView(tabRepeater);
        tabs.addView(tabRules);
        root.addView(tabs);

        setContentView(root);
        Store.addListener(() -> runOnUiThread(this::refreshUi));
        showTab(1);
        refreshUi();
    }

    // ================= Split interceptor panel =================

    private void buildSplitPanel() {
        splitPanel = new LinearLayout(this);
        splitPanel.setOrientation(LinearLayout.VERTICAL);
        splitPanel.setBackgroundColor(PANEL);
        splitPanel.setPadding(10, 6, 10, 6);
        splitPanel.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        LinearLayout actionRow = new LinearLayout(this);
        actionRow.setOrientation(LinearLayout.HORIZONTAL);
        splitStatus = new TextView(this);
        splitStatus.setTextColor(ORANGE);
        splitStatus.setTextSize(12);
        splitStatus.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        splitStatus.setText("Interceptor ready");
        Button fwd = smallButton("Forward");
        fwd.setOnClickListener(v -> forwardSelected());
        Button fwdAll = smallButton("Forward All");
        fwdAll.setOnClickListener(v -> forwardAll(false));
        Button drop = smallButton("Drop");
        drop.setOnClickListener(v -> dropSelected());
        Button dropAll = smallButton("Drop All");
        dropAll.setOnClickListener(v -> forwardAll(true));
        actionRow.addView(splitStatus);
        actionRow.addView(fwd);
        actionRow.addView(fwdAll);
        actionRow.addView(drop);
        actionRow.addView(dropAll);
        splitPanel.addView(actionRow);

        queueSpinner = new Spinner(this);
        queueSpinAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, queueSpinLabels);
        queueSpinAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        queueSpinner.setAdapter(queueSpinAdapter);
        queueSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> p, View v, int pos, long id) {
                Entry e = entryAtSpinnerPos(pos);
                if (e != null) { followLatest = false; selectEntry(e, false); }
            }
            @Override public void onNothingSelected(AdapterView<?> p) { }
        });
        splitPanel.addView(queueSpinner);

        LinearLayout tabRow = new LinearLayout(this);
        tabRow.setOrientation(LinearLayout.HORIZONTAL);
        spReqTab = smallButton("Request");
        spRespTab = smallButton("Response");
        spReqTab.setOnClickListener(v -> showSplitContent(true));
        spRespTab.setOnClickListener(v -> showSplitContent(false));
        Button save = smallButton("Save edits");
        save.setOnClickListener(v -> saveSplitEdits());
        Button toRep = smallButton("To Repeater");
        toRep.setOnClickListener(v -> { if (selectedEntry != null) openRepeater(selectedEntry); });
        tabRow.addView(spReqTab);
        tabRow.addView(spRespTab);
        tabRow.addView(save);
        tabRow.addView(toRep);
        splitPanel.addView(tabRow);

        spContent = new FrameLayout(this);
        spContent.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        spReqBox = new LinearLayout(this);
        spReqBox.setOrientation(LinearLayout.VERTICAL);
        spUrl = field("URL");
        spUrl.setSingleLine(true);
        spHeaders = field("Headers: Name: value, one per line");
        spHeaders.setMinLines(2);
        spBody = field("Body");
        spBody.setMinLines(2);
        spReqBox.addView(spUrl);
        spReqBox.addView(spHeaders);
        spReqBox.addView(spBody);
        spContent.addView(spReqBox);
        spRespBox = new ScrollView(this);
        spResponse = new TextView(this);
        spResponse.setTextColor(TEXT);
        spResponse.setTextSize(12);
        spResponse.setTextIsSelectable(true);
        spResponse.setText("No response yet. Held requests show their response here after Forward.");
        spRespBox.addView(spResponse);
        spRespBox.setVisibility(View.GONE);
        spContent.addView(spRespBox);
        splitPanel.addView(spContent);
    }

    private void showSplitContent(boolean request) {
        spReqBox.setVisibility(request ? View.VISIBLE : View.GONE);
        spRespBox.setVisibility(request ? View.GONE : View.VISIBLE);
        spReqTab.setTextColor(request ? ORANGE : MUTED);
        spRespTab.setTextColor(request ? MUTED : ORANGE);
    }

    private Entry entryAtSpinnerPos(int pos) {
        // Spinner lists held queue first, then a "latest traffic" entry
        synchronized (Store.queue) {
            if (pos < Store.queue.size()) return Store.queue.get(pos);
        }
        synchronized (Store.history) {
            if (!Store.history.isEmpty()) return Store.history.get(0);
        }
        return null;
    }

    private void selectEntry(Entry e, boolean auto) {
        selectedEntry = e;
        spUrl.setText(e.url);
        spHeaders.setText(e.headersToText(e.reqHeaders));
        spBody.setText(e.reqBody == null ? "" : e.reqBody);
        updateSplitResponse();
        splitStatus.setText(e.state == Entry.STATE_HELD
            ? "HELD: " + e.method + " (edit below, then Forward / Drop)"
            : e.method + " " + (e.status != null ? e.status : "") + (auto ? " (latest)" : ""));
    }

    private void updateSplitResponse() {
        if (selectedEntry == null) return;
        Entry e = selectedEntry;
        if (e.state == Entry.STATE_DROPPED) { spResponse.setText("Dropped by intercept."); return; }
        if (e.status == null && e.error == null) { spResponse.setText(e.state == Entry.STATE_HELD ? "Held. Forward it to see the response here." : "No response captured yet."); return; }
        String out = (e.status != null ? "HTTP " + e.status + "\n" : "")
            + e.headersToText(e.respHeaders)
            + "\n" + (e.respBodyText == null ? "" : e.respBodyText)
            + (e.error != null ? "\nERROR: " + e.error : "")
            + (e.note != null ? "\nNOTE: " + e.note : "");
        spResponse.setText(out);
    }

    private void saveSplitEdits() {
        if (selectedEntry == null) return;
        if (selectedEntry.state != Entry.STATE_HELD) {
            Toast.makeText(this, "This request was already sent. Use Repeater to resend an edited copy.", Toast.LENGTH_SHORT).show();
            return;
        }
        selectedEntry.url = spUrl.getText().toString().trim();
        selectedEntry.reqHeaders = Entry.parseHeaders(spHeaders.getText().toString());
        String b = spBody.getText().toString();
        if (!b.isEmpty()) selectedEntry.reqBody = b;
        Toast.makeText(this, "Edits saved on the held request", Toast.LENGTH_SHORT).show();
        Store.changed();
    }

    private void forwardSelected() {
        if (selectedEntry != null && selectedEntry.state == Entry.STATE_HELD) {
            saveSplitEditsSilent();
            selectedEntry.dropDecision = false;
            selectedEntry.latch.countDown();
        } else {
            Entry e = Store.firstHeld();
            if (e != null) { e.dropDecision = false; e.latch.countDown(); }
            else Toast.makeText(this, "Nothing is held right now", Toast.LENGTH_SHORT).show();
        }
    }

    private void dropSelected() {
        if (selectedEntry != null && selectedEntry.state == Entry.STATE_HELD) {
            selectedEntry.dropDecision = true;
            selectedEntry.latch.countDown();
        } else {
            Entry e = Store.firstHeld();
            if (e != null) { e.dropDecision = true; e.latch.countDown(); }
        }
    }

    private void saveSplitEditsSilent() {
        if (selectedEntry == null || selectedEntry.state != Entry.STATE_HELD) return;
        selectedEntry.url = spUrl.getText().toString().trim();
        selectedEntry.reqHeaders = Entry.parseHeaders(spHeaders.getText().toString());
        String b = spBody.getText().toString();
        if (!b.isEmpty()) selectedEntry.reqBody = b;
    }

    private void forwardAll(boolean drop) {
        List<Entry> copy;
        synchronized (Store.queue) { copy = new ArrayList<>(Store.queue); }
        if (copy.isEmpty()) { Toast.makeText(this, "Queue is empty", Toast.LENGTH_SHORT).show(); return; }
        for (Entry e : copy) { e.dropDecision = drop; e.latch.countDown(); }
        Toast.makeText(this, (drop ? "Dropped " : "Forwarded ") + copy.size() + " request(s)", Toast.LENGTH_SHORT).show();
    }

    private void cycleLayout() {
        layoutMode = (layoutMode + 1) % 3;
        applyLayout();
    }

    private void applyLayout() {
        if (layoutMode == 0) {
            browserWeb.setVisibility(View.VISIBLE);
            splitPanel.setVisibility(View.VISIBLE);
            layoutBtn.setText("View: Split");
        } else if (layoutMode == 1) {
            browserWeb.setVisibility(View.VISIBLE);
            splitPanel.setVisibility(View.GONE);
            layoutBtn.setText("View: Browser");
        } else {
            browserWeb.setVisibility(View.GONE);
            splitPanel.setVisibility(View.VISIBLE);
            layoutBtn.setText("View: Panel");
        }
    }

    // ================= Other panels =================

    private void buildHistoryPanel() {
        historyPanel = panel();
        historyInfo = infoText("");
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

    private void buildDetailPanel() {
        detailPanel = panel();
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        Button back = smallButton("Back");
        back.setOnClickListener(v -> { detailPanel.setVisibility(View.GONE); showTab(3); });
        Button rep = smallButton("Send to Repeater");
        rep.setOnClickListener(v -> { if (detailEntry != null) openRepeater(detailEntry); });
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
        repeaterPanel.addView(infoText("Repeater: edit and send any request with the app engine. The response lands below and in History."));
        rpMethod = field("Method (GET, POST, ...)");
        rpMethod.setText("GET");
        rpUrl = field("https://your-target.example/path");
        rpHeaders = field("Headers: Name: value, one per line");
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

    private void buildRulesPanel(SharedPreferences prefs) {
        rulesPanel = panel();
        rulesPanel.addView(infoText("Intercept rules: matching requests are forwarded automatically without being held (still logged in History). One entry per line. Hosts support *.example.com. IPs support single addresses and CIDR like 192.168.1.0/24. Paths match any part of the URL, so /static/ also works as a directory skip."));
        ruSkipHosts = rulesField("Skip hosts, e.g. *.google-analytics.com", prefs.getString("skipHosts", ""));
        ruSkipIps = rulesField("Skip IPs / CIDRs, e.g. 192.168.1.0/24", prefs.getString("skipIps", ""));
        ruSkipPaths = rulesField("Skip paths / directories, e.g. /static/ or /images/", prefs.getString("skipPaths", ""));
        ruSkipExts = rulesField("Skip extensions, e.g. .png", prefs.getString("skipExts", ".png\n.jpg\n.jpeg\n.gif\n.webp\n.svg\n.ico\n.woff\n.woff2\n.ttf"));
        ruSkipMethods = rulesField("Skip methods, e.g. GET", prefs.getString("skipMethods", ""));
        ruOnlyHosts = rulesField("Only intercept these hosts (scope). Empty means all hosts.", prefs.getString("onlyHosts", ""));
        ScrollView sv = new ScrollView(this);
        sv.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.addView(ruSkipHosts);
        box.addView(ruSkipIps);
        box.addView(ruSkipPaths);
        box.addView(ruSkipExts);
        box.addView(ruSkipMethods);
        box.addView(ruOnlyHosts);
        sv.addView(box);
        rulesPanel.addView(sv);
        Button save = smallButton("Save rules");
        save.setOnClickListener(v -> {
            Rules.skipHosts = Rules.split(ruSkipHosts.getText().toString());
            Rules.skipIps = Rules.split(ruSkipIps.getText().toString());
            Rules.skipPaths = Rules.split(ruSkipPaths.getText().toString());
            Rules.skipExts = Rules.split(ruSkipExts.getText().toString());
            Rules.skipMethods = Rules.split(ruSkipMethods.getText().toString());
            Rules.onlyHosts = Rules.split(ruOnlyHosts.getText().toString());
            Rules.save(prefs);
            Toast.makeText(this, "Rules saved and active", Toast.LENGTH_SHORT).show();
        });
        rulesPanel.addView(save);
        rulesPanel.setVisibility(View.GONE);
    }

    private EditText rulesField(String hint, String value) {
        EditText e = field(hint);
        e.setMinLines(2);
        e.setText(value);
        return e;
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
        b.setTextSize(11);
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
        t.setText(on);
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

    private WebView makeWebView() {
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
        detailPanel.setVisibility(View.GONE);
        suiteWeb.setVisibility(which == 0 ? View.VISIBLE : View.GONE);
        browserSplit.setVisibility(which == 1 ? View.VISIBLE : View.GONE);
        historyPanel.setVisibility(which == 3 ? View.VISIBLE : View.GONE);
        repeaterPanel.setVisibility(which == 4 ? View.VISIBLE : View.GONE);
        rulesPanel.setVisibility(which == 5 ? View.VISIBLE : View.GONE);
        browserChrome.setVisibility(which == 1 ? View.VISIBLE : View.GONE);
        tabSuite.setTextColor(which == 0 ? ORANGE : MUTED);
        tabBrowser.setTextColor(which == 1 ? ORANGE : MUTED);
        tabHistory.setTextColor(which == 3 ? ORANGE : MUTED);
        tabRepeater.setTextColor(which == 4 ? ORANGE : MUTED);
        tabRules.setTextColor(which == 5 ? ORANGE : MUTED);
        refreshUi();
    }

    private void refreshUi() {
        synchronized (Store.history) {
            historyLabels.clear();
            for (Entry e : Store.history) historyLabels.add(e.label());
            historyInfo.setText(Store.history.size() + " entries. Tap one for full request and response.");
        }
        historyAdapter.notifyDataSetChanged();

        // Spinner: held queue first, then latest traffic marker
        List<Entry> heldCopy;
        synchronized (Store.queue) { heldCopy = new ArrayList<>(Store.queue); }
        queueSpinLabels.clear();
        for (Entry e : heldCopy) queueSpinLabels.add("HELD  " + e.method + "  " + e.url);
        synchronized (Store.history) {
            if (!Store.history.isEmpty()) queueSpinLabels.add("Latest  " + Store.history.get(0).method + "  " + Store.history.get(0).url);
        }
        if (queueSpinLabels.isEmpty()) queueSpinLabels.add("No traffic yet");
        queueSpinAdapter.notifyDataSetChanged();
        tabHistory.setText(heldCopy.isEmpty() ? "History" : "History*");

        // Follow behaviour: a newly held request takes over the panel; otherwise follow latest
        Entry first = Store.firstHeld();
        if (first != null && (selectedEntry == null || selectedEntry.state != Entry.STATE_HELD || selectedEntry == first || followLatest)) {
            if (selectedEntry != first) selectEntry(first, false);
            else updateSplitResponse();
            followLatest = false;
        } else if (first == null) {
            if (selectedEntry != null && selectedEntry.state == Entry.STATE_HELD) {
                updateSplitResponse();
                splitStatus.setText(selectedEntry.method + " " + (selectedEntry.status != null ? selectedEntry.status : "done"));
            } else {
                synchronized (Store.history) {
                    if (!Store.history.isEmpty()) {
                        Entry latest = Store.history.get(0);
                        if (selectedEntry != latest) selectEntry(latest, true);
                        else updateSplitResponse();
                    }
                }
            }
        } else {
            updateSplitResponse();
        }
    }

    private void navigateBrowser() {
        String u = urlInput.getText().toString().trim();
        if (u.isEmpty()) return;
        if (!u.startsWith("http://") && !u.startsWith("https://")) u = "https://" + u;
        urlInput.setText(u);
        followLatest = true;
        browserWeb.loadUrl(u);
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
            try { Engine.fetch(e); e.state = Entry.STATE_COMPLETED; }
            catch (Exception ex) { e.error = ex.getMessage(); }
            Store.addHistory(e);
            runOnUiThread(() -> rpResponse.setText(
                (e.status != null ? "HTTP " + e.status + "\n" : "")
                + e.headersToText(e.respHeaders)
                + "\n" + (e.respBodyText == null ? "" : e.respBodyText)
                + (e.error != null ? "\nERROR: " + e.error : "")));
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
                if (e.method.equals("PATCH")) e.note = "PATCH passed through natively: the Android HTTP engine cannot send it, so this entry is request-line only.";
                Store.addHistory(e);
                return null;
            }

            if (e.method.equals("POST") || e.method.equals("PUT") || e.method.equals("DELETE")) {
                String body = Store.takeBody(e.method, e.url);
                if (body != null) e.reqBody = body;
            }

            Store.addHistory(e);

            String skip = Rules.skipReason(e);
            if (skip != null) e.note = "Not held, " + skip + ".";

            if (skip == null && interceptToggle.isChecked() && shouldHold(e)) {
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
                if (e.mainFrame) return new WebResourceResponse("text/html", "utf-8", 200, "OK", null, new ByteArrayInputStream(html.getBytes()));
                return new WebResourceResponse("text/plain", "utf-8", 502, "Bad Gateway", null, new ByteArrayInputStream(new byte[0]));
            }
        }

        private boolean shouldHold(Entry e) {
            if (e.mainFrame) return true;
            if (e.method.equals("POST") || e.method.equals("PUT") || e.method.equals("DELETE")) return true;
            if (!scopeToggle.isChecked()) return true; // All
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
        if (detailPanel.getVisibility() == View.VISIBLE) { detailPanel.setVisibility(View.GONE); showTab(3); return; }
        WebView active = currentTab == 1 ? browserWeb : suiteWeb;
        if ((currentTab == 0 || currentTab == 1) && active != null && active.canGoBack()) active.goBack();
        else super.onBackPressed();
    }
}
