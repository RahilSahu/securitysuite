package app.securitysuite.mobile;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.EditorInfo;
import android.webkit.WebResourceError;
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
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class MainActivity extends Activity {

    private static final String SUITE_URL = "https://securitysuite-woad.vercel.app";
    private static final int BG = Color.rgb(10, 14, 19);
    private static final int PANEL = Color.rgb(18, 26, 36);
    private static final int ORANGE = Color.rgb(255, 106, 26);
    private static final int TEXT = Color.rgb(232, 238, 245);
    private static final int MUTED = Color.rgb(157, 176, 195);

    private WebView suiteWeb;
    private WebView browserWeb;
    private FrameLayout stage;
    private LinearLayout browserBar;
    private LinearLayout capturesPanel;
    private EditText urlInput;
    private ListView capturesList;
    private TextView capturesInfo;
    private Button tabSuite, tabBrowser, tabCaptures;

    private final List<JSONObject> captures = new ArrayList<>();
    private final List<String> captureLabels = new ArrayList<>();
    private ArrayAdapter<String> capturesAdapter;
    private int currentTab = 0; // 0 suite, 1 browser, 2 captures
    private final SimpleDateFormat timeFmt = new SimpleDateFormat("HH:mm:ss", Locale.US);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BG);

        // ---- Browser address bar (visible on Browser tab) ----
        browserBar = new LinearLayout(this);
        browserBar.setOrientation(LinearLayout.HORIZONTAL);
        browserBar.setBackgroundColor(PANEL);
        browserBar.setPadding(12, 10, 12, 10);
        urlInput = new EditText(this);
        urlInput.setSingleLine(true);
        urlInput.setTextColor(TEXT);
        urlInput.setHintTextColor(MUTED);
        urlInput.setHint("https://your-target.example");
        urlInput.setImeOptions(EditorInfo.IME_ACTION_GO);
        urlInput.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        urlInput.setOnEditorActionListener((v, actionId, event) -> { navigateBrowser(); return true; });
        Button goBtn = makeButton("Go");
        goBtn.setOnClickListener(v -> navigateBrowser());
        browserBar.addView(urlInput);
        browserBar.addView(goBtn);
        browserBar.setVisibility(View.GONE);
        root.addView(browserBar);

        // ---- Stage ----
        stage = new FrameLayout(this);
        stage.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        root.addView(stage);

        suiteWeb = makeWebView();
        suiteWeb.setWebViewClient(new WebViewClient());
        suiteWeb.loadUrl(SUITE_URL);
        stage.addView(suiteWeb);

        browserWeb = makeWebView();
        browserWeb.setVisibility(View.GONE);
        browserWeb.setWebViewClient(new WebViewClient() {
            @Override
            public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
                try {
                    JSONObject e = new JSONObject();
                    e.put("time", timeFmt.format(new Date()));
                    e.put("method", request.getMethod());
                    e.put("url", request.getUrl().toString());
                    e.put("mainFrame", request.isForMainFrame());
                    JSONObject h = new JSONObject();
                    Map<String, String> headers = request.getRequestHeaders();
                    if (headers != null) {
                        for (Map.Entry<String, String> en : headers.entrySet()) h.put(en.getKey(), en.getValue());
                    }
                    e.put("headers", h);
                    synchronized (captures) {
                        captures.add(0, e);
                        captureLabels.add(0, e.getString("method") + "  " + e.getString("url") + "   " + e.getString("time"));
                        while (captures.size() > 500) { captures.remove(captures.size() - 1); captureLabels.remove(captureLabels.size() - 1); }
                    }
                    runOnUiThread(() -> {
                        if (capturesAdapter != null) capturesAdapter.notifyDataSetChanged();
                        if (capturesInfo != null) capturesInfo.setText(captures.size() + " requests captured from the Browser tab. Tap one to copy its URL for Repeater. Note: Android WebView does not expose POST bodies or response bodies for pages it loads itself, use the Suite Relay / Repeater for full bodies.");
                        if (tabCaptures != null) tabCaptures.setText("Captures (" + captures.size() + ")");
                    });
                } catch (Exception ignored) { }
                return null; // let WebView load it normally
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                urlInput.setText(url);
            }

            @Override
            public void onReceivedHttpError(WebView view, WebResourceRequest request, WebResourceResponse errorResponse) {
                try {
                    JSONObject e = new JSONObject();
                    e.put("time", timeFmt.format(new Date()));
                    e.put("method", request.getMethod());
                    e.put("url", request.getUrl().toString());
                    e.put("httpStatus", errorResponse.getStatusCode());
                    synchronized (captures) {
                        captures.add(0, e);
                        captureLabels.add(0, request.getMethod() + "  " + request.getUrl().toString() + "   HTTP " + errorResponse.getStatusCode());
                    }
                    runOnUiThread(() -> { if (capturesAdapter != null) capturesAdapter.notifyDataSetChanged(); });
                } catch (Exception ignored) { }
            }
        });
        stage.addView(browserWeb);

        // ---- Captures panel ----
        capturesPanel = new LinearLayout(this);
        capturesPanel.setOrientation(LinearLayout.VERTICAL);
        capturesPanel.setBackgroundColor(BG);
        capturesPanel.setPadding(16, 16, 16, 16);
        capturesPanel.setVisibility(View.GONE);
        capturesInfo = new TextView(this);
        capturesInfo.setTextColor(MUTED);
        capturesInfo.setText("No captures yet. Browse a target in the Browser tab and its requests will appear here.");
        capturesPanel.addView(capturesInfo);
        LinearLayout capBtns = new LinearLayout(this);
        capBtns.setOrientation(LinearLayout.HORIZONTAL);
        Button exportBtn = makeButton("Export JSON");
        exportBtn.setOnClickListener(v -> exportCaptures());
        Button clearBtn = makeButton("Clear");
        clearBtn.setOnClickListener(v -> {
            synchronized (captures) { captures.clear(); captureLabels.clear(); }
            capturesAdapter.notifyDataSetChanged();
            tabCaptures.setText("Captures");
            capturesInfo.setText("No captures yet. Browse a target in the Browser tab and its requests will appear here.");
        });
        capBtns.addView(exportBtn);
        capBtns.addView(clearBtn);
        capturesPanel.addView(capBtns);
        capturesList = new ListView(this);
        capturesAdapter = new ArrayAdapter<String>(this, android.R.layout.simple_list_item_1, captureLabels) {
            @Override
            public View getView(int position, View convertView, ViewGroup parent) {
                TextView tv = (TextView) super.getView(position, convertView, parent);
                tv.setTextColor(TEXT);
                tv.setTextSize(12);
                return tv;
            }
        };
        capturesList.setAdapter(capturesAdapter);
        capturesList.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        capturesList.setOnItemClickListener((parent, view, position, id) -> {
            try {
                String url = captures.get(position).getString("url");
                ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                cm.setPrimaryClip(ClipData.newPlainText("url", url));
                Toast.makeText(this, "URL copied, paste it in the Suite Repeater", Toast.LENGTH_SHORT).show();
            } catch (Exception ignored) { }
        });
        capturesPanel.addView(capturesList);
        stage.addView(capturesPanel);

        // ---- Bottom tab bar ----
        LinearLayout tabs = new LinearLayout(this);
        tabs.setOrientation(LinearLayout.HORIZONTAL);
        tabs.setBackgroundColor(PANEL);
        tabSuite = makeTab("Suite");
        tabBrowser = makeTab("Browser");
        tabCaptures = makeTab("Captures");
        tabSuite.setOnClickListener(v -> showTab(0));
        tabBrowser.setOnClickListener(v -> showTab(1));
        tabCaptures.setOnClickListener(v -> showTab(2));
        tabs.addView(tabSuite);
        tabs.addView(tabBrowser);
        tabs.addView(tabCaptures);
        root.addView(tabs);

        setContentView(root);
        showTab(0);
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

    private Button makeButton(String label) {
        Button b = new Button(this);
        b.setText(label);
        b.setTextColor(TEXT);
        b.setBackgroundColor(PANEL);
        return b;
    }

    private Button makeTab(String label) {
        Button b = new Button(this);
        b.setText(label);
        b.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        b.setGravity(Gravity.CENTER);
        return b;
    }

    private void showTab(int which) {
        currentTab = which;
        suiteWeb.setVisibility(which == 0 ? View.VISIBLE : View.GONE);
        browserWeb.setVisibility(which == 1 ? View.VISIBLE : View.GONE);
        capturesPanel.setVisibility(which == 2 ? View.VISIBLE : View.GONE);
        browserBar.setVisibility(which == 1 ? View.VISIBLE : View.GONE);
        tabSuite.setTextColor(which == 0 ? ORANGE : MUTED);
        tabBrowser.setTextColor(which == 1 ? ORANGE : MUTED);
        tabCaptures.setTextColor(which == 2 ? ORANGE : MUTED);
    }

    private void navigateBrowser() {
        String u = urlInput.getText().toString().trim();
        if (u.isEmpty()) return;
        if (!u.startsWith("http://") && !u.startsWith("https://")) u = "https://" + u;
        urlInput.setText(u);
        browserWeb.loadUrl(u);
    }

    private void exportCaptures() {
        try {
            JSONArray arr = new JSONArray();
            synchronized (captures) { for (JSONObject e : captures) arr.put(e); }
            Intent share = new Intent(Intent.ACTION_SEND);
            share.setType("text/plain");
            share.putExtra(Intent.EXTRA_SUBJECT, "SecuritySuite captures");
            share.putExtra(Intent.EXTRA_TEXT, arr.toString(2));
            startActivity(Intent.createChooser(share, "Export captures"));
        } catch (Exception e) {
            Toast.makeText(this, "Export failed", Toast.LENGTH_SHORT).show();
        }
    }

    @Override
    public void onBackPressed() {
        WebView active = currentTab == 1 ? browserWeb : suiteWeb;
        if (currentTab != 2 && active != null && active.canGoBack()) active.goBack();
        else super.onBackPressed();
    }

    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (keyCode == KeyEvent.KEYCODE_BACK) { onBackPressed(); return true; }
        return super.onKeyDown(keyCode, event);
    }
}
