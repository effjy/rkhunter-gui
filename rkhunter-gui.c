/*
 * rkhunter-gui - a friendly GTK3 front-end for rkhunter (Rootkit Hunter)
 *
 * Runs `rkhunter --check` and shows the scan live, line by line, coloring the
 * status tag at the end of each line:
 *   green  = OK / Not found / None found / Clean / Not affected
 *   yellow = Warning / Update available / Skipped
 *   red    = a genuine detection (Possible rootkits > 0)
 *   blue   = section headers ("Checking system commands...")
 *   gray   = informational / skipped detail
 *
 * rkhunter quirks handled here:
 *   - it pauses for <ENTER> between sections   -> we pass --skip-keypress
 *   - it prints its own ANSI colors            -> we pass --nocolor and do our own
 *   - its status tags are right-aligned [ ... ]-> we parse the trailing bracket
 *   - it floods the view with hundreds of OK lines -> "Show only problems" toggle
 *   - it needs root                            -> launched via pkexec when needed
 *
 * Copyright (c) 2026. Released under the MIT license.
 */

#include <gtk/gtk.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <sys/wait.h>

typedef struct {
    GtkWidget     *window;
    GtkWidget     *textview;
    GtkTextBuffer *buffer;
    GtkWidget     *scan_btn;
    GtkWidget     *stop_btn;
    GtkWidget     *clear_btn;
    GtkWidget     *only_problems;   /* checkbox: hide passed/info lines */
    GtkWidget     *spinner;
    GtkWidget     *statusbar;
    guint          status_ctx;

    /* running scan state */
    GPid           pid;
    GIOChannel    *out_chan;
    GIOChannel    *err_chan;
    guint          out_watch;
    guint          err_watch;
    guint          child_watch;
    gboolean       running;

    /* live tallies */
    int warnings;
    int rootkits;
    int hidden;          /* lines suppressed by "only problems" */

    char *rkhunter_path; /* discovered at startup */
} App;

/* ---- helpers ---------------------------------------------------------- */

/* Locate the rkhunter binary (it usually lives in sbin). */
static char *find_rkhunter(void)
{
    const char *cands[] = {
        "/usr/bin/rkhunter", "/usr/sbin/rkhunter",
        "/usr/local/bin/rkhunter", "/usr/local/sbin/rkhunter",
        "/bin/rkhunter", "/sbin/rkhunter", NULL
    };
    for (int i = 0; cands[i]; i++)
        if (g_file_test(cands[i], G_FILE_TEST_IS_EXECUTABLE))
            return g_strdup(cands[i]);
    return g_find_program_in_path("rkhunter"); /* may be NULL */
}

/* Extract the content of the trailing "[ ... ]" status tag, if any.
 * Returns a newly allocated, trimmed string, or NULL. */
static char *extract_tag(const char *line)
{
    const char *close = strrchr(line, ']');
    if (!close) return NULL;
    /* find the matching '[' before it */
    const char *open = close;
    while (open > line && *open != '[') open--;
    if (*open != '[') return NULL;
    /* the tag must sit at (or very near) the end of the line */
    for (const char *p = close + 1; *p; p++)
        if (!isspace((unsigned char)*p)) return NULL;

    char *raw = g_strndup(open + 1, (gsize)(close - open - 1));
    char *tag = g_strdup(g_strstrip(raw));
    g_free(raw);
    return tag;
}

static gboolean tag_is(const char *tag, const char *want)
{
    return g_ascii_strcasecmp(tag, want) == 0;
}

/* Decide the color tag for a line. *is_problem set TRUE for warn/red. */
static const char *classify_line(const char *line, gboolean *is_problem)
{
    *is_problem = FALSE;

    char *tag = extract_tag(line);
    if (tag) {
        const char *result;
        if (tag_is(tag, "Warning") || tag_is(tag, "Update available")) {
            *is_problem = TRUE;
            result = "warn";
        } else if (tag_is(tag, "OK")           || tag_is(tag, "Not found") ||
                   tag_is(tag, "None found")   || tag_is(tag, "Clean") ||
                   tag_is(tag, "Not installed")|| tag_is(tag, "Not affected") ||
                   tag_is(tag, "Found")        || tag_is(tag, "No update") ||
                   tag_is(tag, "Updated")      || tag_is(tag, "Whitelisted")) {
            result = "ok";
        } else if (tag_is(tag, "Skipped")  || tag_is(tag, "Disabled") ||
                   tag_is(tag, "No")       || tag_is(tag, "None")) {
            result = "info";
        } else {
            /* version banner "[ Rootkit Hunter version ... ]" etc. */
            result = "info";
        }
        g_free(tag);
        return result;
    }

    /* Bracket-less lines: summary and headers. Strip the leading indent
     * rkhunter puts on summary lines before matching. */
    const char *s = line;
    while (*s && isspace((unsigned char)*s)) s++;

    if (g_str_has_prefix(s, "Possible rootkits:")) {
        int n = atoi(s + strlen("Possible rootkits:"));
        if (n > 0) { *is_problem = TRUE; return "infected"; }
        return "ok";
    }
    if (g_strstr_len(line, -1, "Warnings found")) {
        int n = 0;
        const char *c = line;
        for (; *c; c++) if (isdigit((unsigned char)*c)) { n = atoi(c); break; }
        if (n > 0) { *is_problem = TRUE; return "warn"; }
        return "ok";
    }
    if (g_strstr_len(line, -1, "Suspect files:")) {
        *is_problem = TRUE; return "warn";
    }

    /* Section headers: non-indented lines ending in "..." or ":" */
    if (line[0] && !isspace((unsigned char)line[0])) {
        size_t len = strlen(line);
        if ((len >= 3 && strcmp(line + len - 3, "...") == 0) ||
            g_str_has_prefix(line, "Checking") ||
            g_str_has_prefix(line, "Performing") ||
            g_str_has_prefix(line, "System checks"))
            return "header";
    }
    return NULL;
}

/* Should a non-problem line still be shown? Headers/summaries yes. */
static gboolean is_structural(const char *line)
{
    if (line[0] == '\0') return TRUE; /* keep blank spacers */
    const char *s = line;
    while (*s && isspace((unsigned char)*s)) s++;
    if (g_str_has_prefix(s, "Checking")     ||
        g_str_has_prefix(s, "Performing")   ||
        g_str_has_prefix(s, "System checks")||
        g_str_has_prefix(s, "Possible rootkits") ||
        g_str_has_prefix(s, "Rootkits checked")  ||
        g_str_has_prefix(s, "Rootkit checks")    ||
        g_str_has_prefix(s, "Applications checks") ||
        g_str_has_prefix(s, "File properties")   ||
        g_str_has_prefix(s, "Files checked")     ||
        g_str_has_prefix(s, "Suspect files")     ||
        g_strstr_len(s, -1, "summary")  ||
        g_strstr_len(s, -1, "Warnings found") ||
        g_strstr_len(s, -1, "version"))
        return TRUE;
    return FALSE;
}

static void append_line(App *app, const char *line, const char *tag)
{
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(app->buffer, &end);
    if (tag)
        gtk_text_buffer_insert_with_tags_by_name(app->buffer, &end,
                                                 line, -1, tag, NULL);
    else
        gtk_text_buffer_insert(app->buffer, &end, line, -1);
    gtk_text_buffer_insert(app->buffer, &end, "\n", -1);

    GtkTextMark *mark = gtk_text_buffer_get_insert(app->buffer);
    gtk_text_view_scroll_mark_onscreen(GTK_TEXT_VIEW(app->textview), mark);
}

static void update_status(App *app)
{
    char msg[256];
    if (app->running)
        g_snprintf(msg, sizeof msg,
                   "Scanning…   warnings: %d   possible rootkits: %d",
                   app->warnings, app->rootkits);
    else if (app->rootkits > 0)
        g_snprintf(msg, sizeof msg,
                   "Finished — %d POSSIBLE ROOTKIT(S), %d warning(s). Review the red/yellow lines!",
                   app->rootkits, app->warnings);
    else if (app->warnings > 0)
        g_snprintf(msg, sizeof msg,
                   "Finished — no rootkits, but %d warning(s) to review.",
                   app->warnings);
    else
        g_snprintf(msg, sizeof msg, "Ready.");

    gtk_statusbar_pop(GTK_STATUSBAR(app->statusbar), app->status_ctx);
    gtk_statusbar_push(GTK_STATUSBAR(app->statusbar), app->status_ctx, msg);
}

/* Classify, tally, filter, then print. */
static void handle_output_line(App *app, const char *line, const char *forced)
{
    gboolean problem = FALSE;
    const char *tag = forced ? forced : classify_line(line, &problem);
    if (forced) problem = TRUE;

    /* Authoritative tallies: trust rkhunter's own summary number for
     * rootkits, and count each per-line "[ Warning ]" tag for warnings. */
    const char *t = line;
    while (*t && isspace((unsigned char)*t)) t++;
    if (g_str_has_prefix(t, "Possible rootkits:")) {
        app->rootkits = atoi(t + strlen("Possible rootkits:"));
    } else {
        char *bt = extract_tag(line);
        if (bt) {
            if (tag_is(bt, "Warning")) app->warnings++;
            g_free(bt);
        } else if (forced) {
            app->warnings++;   /* a line from stderr */
        }
    }

    gboolean only = gtk_toggle_button_get_active(
        GTK_TOGGLE_BUTTON(app->only_problems));
    if (only && !problem && !is_structural(line)) {
        app->hidden++;
        return;
    }
    append_line(app, line, tag);
}

/* ---- scan lifecycle --------------------------------------------------- */

static void set_running_ui(App *app, gboolean running)
{
    app->running = running;
    gtk_widget_set_sensitive(app->scan_btn, !running);
    gtk_widget_set_sensitive(app->stop_btn, running);
    if (running) {
        gtk_spinner_start(GTK_SPINNER(app->spinner));
        gtk_widget_show(app->spinner);
    } else {
        gtk_spinner_stop(GTK_SPINNER(app->spinner));
        gtk_widget_hide(app->spinner);
    }
    update_status(app);
}

static gboolean on_io(GIOChannel *src, GIOCondition cond, gpointer data)
{
    App *app = data;
    guint *watch_id = (src == app->err_chan) ? &app->err_watch
                                             : &app->out_watch;
    if (cond & (G_IO_HUP | G_IO_ERR)) {
        *watch_id = 0;
        return FALSE;
    }

    char *line = NULL;
    gsize len = 0;
    GError *err = NULL;
    GIOStatus st = g_io_channel_read_line(src, &line, &len, NULL, &err);

    if (st == G_IO_STATUS_NORMAL && line) {
        g_strchomp(line);
        const char *forced = (src == app->err_chan) ? "warn" : NULL;
        handle_output_line(app, line, forced);
        update_status(app);
        g_free(line);
        return TRUE;
    }
    if (line) g_free(line);
    if (err) g_error_free(err);
    if (st == G_IO_STATUS_AGAIN) return TRUE;
    *watch_id = 0;
    return FALSE;
}

static void cleanup_scan(App *app)
{
    if (app->out_watch) { g_source_remove(app->out_watch); app->out_watch = 0; }
    if (app->err_watch) { g_source_remove(app->err_watch); app->err_watch = 0; }
    if (app->out_chan)  { g_io_channel_unref(app->out_chan); app->out_chan = NULL; }
    if (app->err_chan)  { g_io_channel_unref(app->err_chan); app->err_chan = NULL; }
    if (app->pid)       { g_spawn_close_pid(app->pid); app->pid = 0; }
}

static void on_child_exit(GPid pid, gint status, gpointer data)
{
    (void)pid; (void)status;
    App *app = data;
    app->child_watch = 0;

    if (app->hidden > 0) {
        char buf[160];
        g_snprintf(buf, sizeof buf,
            "  \xE2\x84\xB9 %d passed/info line(s) hidden (untick \xE2\x80\x9CShow only problems\xE2\x80\x9D to see them).",
            app->hidden);
        append_line(app, buf, "info");
    }

    GtkTextIter end;
    gtk_text_buffer_get_end_iter(app->buffer, &end);
    gtk_text_buffer_insert(app->buffer, &end, "\n", -1);

    char summary[160];
    if (app->rootkits > 0)
        g_snprintf(summary, sizeof summary,
                   "=== Scan complete: %d possible rootkit(s), %d warning(s) ===",
                   app->rootkits, app->warnings);
    else
        g_snprintf(summary, sizeof summary,
                   "=== Scan complete: no rootkits found, %d warning(s) ===",
                   app->warnings);
    append_line(app, summary, app->rootkits ? "infected"
                              : (app->warnings ? "warn" : "ok"));

    cleanup_scan(app);
    set_running_ui(app, FALSE);
}

static void start_scan(App *app)
{
    if (app->running) return;

    if (!app->rkhunter_path) {
        append_line(app,
            "rkhunter is not installed. Install it first, e.g.:  sudo apt install rkhunter",
            "infected");
        return;
    }

    app->warnings = 0;
    app->rootkits = 0;
    app->hidden = 0;

    GPtrArray *argv = g_ptr_array_new();
    gboolean need_priv = (geteuid() != 0);
    if (need_priv)
        g_ptr_array_add(argv, "pkexec");
    g_ptr_array_add(argv, app->rkhunter_path);
    g_ptr_array_add(argv, "--check");
    g_ptr_array_add(argv, "--skip-keypress");   /* don't pause between sections */
    g_ptr_array_add(argv, "--nocolor");         /* we add our own colors */
    g_ptr_array_add(argv, "--no-mail-on-warning");
    g_ptr_array_add(argv, NULL);

    gint out_fd = -1, err_fd = -1;
    GError *err = NULL;
    gboolean ok = g_spawn_async_with_pipes(
        NULL, (char **)argv->pdata, NULL,
        G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_SEARCH_PATH,
        NULL, NULL, &app->pid, NULL, &out_fd, &err_fd, &err);
    g_ptr_array_free(argv, TRUE);

    if (!ok) {
        char buf[512];
        g_snprintf(buf, sizeof buf, "Failed to launch rkhunter: %s",
                   err ? err->message : "unknown error");
        append_line(app, buf, "infected");
        if (err) g_error_free(err);
        return;
    }

    char hdr[256];
    g_snprintf(hdr, sizeof hdr, "Starting rkhunter --check%s …",
               need_priv ? " (asking for administrator password)" : "");
    append_line(app, hdr, "header");

    app->out_chan = g_io_channel_unix_new(out_fd);
    app->err_chan = g_io_channel_unix_new(err_fd);
    g_io_channel_set_flags(app->out_chan, G_IO_FLAG_NONBLOCK, NULL);
    g_io_channel_set_flags(app->err_chan, G_IO_FLAG_NONBLOCK, NULL);
    g_io_channel_set_close_on_unref(app->out_chan, TRUE);
    g_io_channel_set_close_on_unref(app->err_chan, TRUE);

    app->out_watch = g_io_add_watch(app->out_chan,
                                    G_IO_IN | G_IO_HUP | G_IO_ERR, on_io, app);
    app->err_watch = g_io_add_watch(app->err_chan,
                                    G_IO_IN | G_IO_HUP | G_IO_ERR, on_io, app);
    app->child_watch = g_child_watch_add(app->pid, on_child_exit, app);

    set_running_ui(app, TRUE);
}

static void stop_scan(App *app)
{
    if (!app->running || !app->pid) return;
    kill((pid_t)app->pid, SIGTERM);
    append_line(app, "Scan stopped by user.", "warn");
}

/* ---- callbacks -------------------------------------------------------- */

static void on_scan_clicked(GtkButton *b, gpointer d) { (void)b; start_scan(d); }
static void on_stop_clicked(GtkButton *b, gpointer d) { (void)b; stop_scan(d); }

static void on_clear_clicked(GtkButton *b, gpointer data)
{
    (void)b;
    App *app = data;
    gtk_text_buffer_set_text(app->buffer, "", -1);
    app->warnings = app->rootkits = app->hidden = 0;
    update_status(app);
}

static void on_save_clicked(GtkButton *b, gpointer data)
{
    (void)b;
    App *app = data;
    GtkWidget *dlg = gtk_file_chooser_dialog_new(
        "Save scan report", GTK_WINDOW(app->window),
        GTK_FILE_CHOOSER_ACTION_SAVE,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Save", GTK_RESPONSE_ACCEPT, NULL);
    gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dlg), TRUE);
    gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dlg), "rkhunter-report.txt");

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        char *fname = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
        GtkTextIter s, e;
        gtk_text_buffer_get_bounds(app->buffer, &s, &e);
        char *text = gtk_text_buffer_get_text(app->buffer, &s, &e, FALSE);
        g_file_set_contents(fname, text, -1, NULL);
        g_free(text);
        g_free(fname);
    }
    gtk_widget_destroy(dlg);
}

static gboolean on_delete(GtkWidget *w, GdkEvent *e, gpointer data)
{
    (void)w; (void)e;
    App *app = data;
    if (app->running && app->pid)
        kill((pid_t)app->pid, SIGTERM);
    return FALSE;
}

/* ---- UI construction -------------------------------------------------- */

/* Cyber palette — neon accents on a deep, near-black backdrop. */
#define CY_BG        "#0a0e14"   /* terminal background        */
#define CY_GREEN     "#39ff14"   /* clean / OK — neon green    */
#define CY_CYAN      "#00e5ff"   /* headers — electric cyan    */
#define CY_AMBER     "#ffb000"   /* warnings — amber           */
#define CY_RED       "#ff2d55"   /* infected — hot red         */
#define CY_DIM       "#5c6f8a"   /* info / muted               */

static void setup_tags(App *app)
{
    gtk_text_buffer_create_tag(app->buffer, "infected",
        "foreground", "#ffffff", "background", CY_RED,
        "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(app->buffer, "warn",
        "foreground", CY_AMBER, "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(app->buffer, "ok",
        "foreground", CY_GREEN, NULL);
    gtk_text_buffer_create_tag(app->buffer, "header",
        "foreground", CY_CYAN, "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(app->buffer, "info",
        "foreground", CY_DIM, "style", PANGO_STYLE_ITALIC, NULL);
}

/* Install a global dark "cyber" stylesheet for the whole app. */
static void apply_cyber_theme(void)
{
    static const char *css =
        "window, .background {"
        "  background-color: #070a0f;"
        "  color: #c7d3e3;"
        "}"
        "headerbar, headerbar.titlebar {"
        "  background: linear-gradient(180deg, #0e1622, #0a0f18);"
        "  border-bottom: 1px solid #00e5ff;"
        "  box-shadow: 0 1px 8px rgba(0,229,255,0.25);"
        "  min-height: 42px;"
        "  padding: 0 8px;"
        "}"
        "headerbar .title {"
        "  color: #00e5ff;"
        "  font-weight: bold;"
        "  letter-spacing: 2px;"
        "  text-shadow: 0 0 8px rgba(0,229,255,0.6);"
        "}"
        "headerbar .subtitle { color: #5c6f8a; letter-spacing: 1px; }"
        "button {"
        "  background: #0f1622;"
        "  color: #c7d3e3;"
        "  border: 1px solid #1d3147;"
        "  border-radius: 4px;"
        "  padding: 5px 14px;"
        "  font-weight: bold;"
        "  letter-spacing: 1px;"
        "}"
        "button:hover {"
        "  border-color: #00e5ff;"
        "  color: #00e5ff;"
        "  box-shadow: 0 0 8px rgba(0,229,255,0.35);"
        "}"
        "button:active { background: #122033; }"
        "button:disabled { color: #3a475a; border-color: #15202e; }"
        "button#scan {"
        "  border-color: #39ff14; color: #39ff14;"
        "}"
        "button#scan:hover {"
        "  box-shadow: 0 0 10px rgba(57,255,20,0.5);"
        "}"
        "button#stop { border-color: #ff2d55; color: #ff7a90; }"
        "button#stop:hover { box-shadow: 0 0 10px rgba(255,45,85,0.5); }"
        "checkbutton { color: #8aa0bd; }"
        "checkbutton check {"
        "  background: #0f1622; border: 1px solid #1d3147;"
        "}"
        "checkbutton check:checked {"
        "  background: #00e5ff; border-color: #00e5ff;"
        "}"
        "textview, textview text {"
        "  background-color: " CY_BG ";"
        "  color: #aeb9c9;"
        "  caret-color: #39ff14;"
        "}"
        "textview { padding: 6px; }"
        "scrolledwindow {"
        "  border: 1px solid #14202e;"
        "}"
        "statusbar {"
        "  background: #0a0f18;"
        "  color: #5c6f8a;"
        "  border-top: 1px solid #14202e;"
        "  font-size: 90%;"
        "  letter-spacing: 1px;"
        "}"
        "spinner { color: #00e5ff; }";

    GtkCssProvider *prov = gtk_css_provider_new();
    gtk_css_provider_load_from_data(prov, css, -1, NULL);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(prov),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(prov);
}

static void build_ui(App *app)
{
    app->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(app->window),
                         "rkhunter — Rootkit Hunter");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 860, 580);
    gtk_window_set_icon_name(GTK_WINDOW(app->window), "rkhunter-gui");
    g_signal_connect(app->window, "delete-event", G_CALLBACK(on_delete), app);
    g_signal_connect(app->window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    /* cyber-styled header bar */
    GtkWidget *hbar = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(hbar), TRUE);
    gtk_header_bar_set_title(GTK_HEADER_BAR(hbar), "\xE2\x9A\xA1 RKHUNTER");
    gtk_header_bar_set_subtitle(GTK_HEADER_BAR(hbar),
                                "rootkit hunter console");
    gtk_window_set_titlebar(GTK_WINDOW(app->window), hbar);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(app->window), vbox);

    GtkWidget *bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_container_set_border_width(GTK_CONTAINER(bar), 6);
    gtk_box_pack_start(GTK_BOX(vbox), bar, FALSE, FALSE, 0);

    app->scan_btn  = gtk_button_new_with_label("\xE2\x96\xB6 START SCAN");
    app->stop_btn  = gtk_button_new_with_label("\xE2\x96\xA0 STOP");
    app->clear_btn = gtk_button_new_with_label("CLEAR");
    GtkWidget *save_btn = gtk_button_new_with_label("SAVE REPORT");
    gtk_widget_set_sensitive(app->stop_btn, FALSE);

    /* widget names so the stylesheet can give scan/stop their accent colors */
    gtk_widget_set_name(app->scan_btn, "scan");
    gtk_widget_set_name(app->stop_btn, "stop");

    app->only_problems = gtk_check_button_new_with_label("Show only problems");
    gtk_widget_set_tooltip_text(app->only_problems,
        "Hide the hundreds of passing 'OK' checks and only show warnings,\n"
        "detections and section headers. Applies to the next scan.");

    app->spinner = gtk_spinner_new();

    gtk_box_pack_start(GTK_BOX(bar), app->scan_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(bar), app->stop_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(bar), app->clear_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(bar), save_btn, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(bar), app->spinner, FALSE, FALSE, 6);
    gtk_box_pack_end(GTK_BOX(bar), app->only_problems, FALSE, FALSE, 6);

    g_signal_connect(app->scan_btn, "clicked", G_CALLBACK(on_scan_clicked), app);
    g_signal_connect(app->stop_btn, "clicked", G_CALLBACK(on_stop_clicked), app);
    g_signal_connect(app->clear_btn, "clicked", G_CALLBACK(on_clear_clicked), app);
    g_signal_connect(save_btn, "clicked", G_CALLBACK(on_save_clicked), app);

    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_box_pack_start(GTK_BOX(vbox), scroll, TRUE, TRUE, 0);

    app->textview = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(app->textview), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(app->textview), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(app->textview), TRUE);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(app->textview), 8);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(app->textview), 8);
    gtk_container_add(GTK_CONTAINER(scroll), app->textview);
    app->buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->textview));
    setup_tags(app);

    GtkWidget *legend = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(legend),
        "  <span foreground='" CY_GREEN "'>\xE2\x97\x8f OK</span>   "
        "<span foreground='" CY_AMBER "'>\xE2\x97\x8f Warning</span>   "
        "<span background='" CY_RED "' foreground='#ffffff'>\xE2\x97\x8f rootkit found</span>   "
        "<span foreground='" CY_DIM "'>\xE2\x97\x8f info/skipped</span>");
    gtk_widget_set_halign(legend, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(vbox), legend, FALSE, FALSE, 4);

    app->statusbar = gtk_statusbar_new();
    app->status_ctx = gtk_statusbar_get_context_id(
        GTK_STATUSBAR(app->statusbar), "main");
    gtk_box_pack_start(GTK_BOX(vbox), app->statusbar, FALSE, FALSE, 0);

    update_status(app);

    if (!app->rkhunter_path)
        append_line(app,
            "Note: rkhunter was not found on this system. Install it with "
            "'sudo apt install rkhunter' (or your distro's package manager), "
            "then press Start scan.",
            "warn");
}

/* Re-launch ourselves as root via pkexec, preserving just enough of the
 * environment that the GTK window can still reach the display (works for
 * both X11 and Wayland). Returns TRUE if an elevated instance ran to
 * completion (caller should then exit), FALSE to fall back to running
 * unprivileged (e.g. pkexec missing or the user cancelled the prompt). */
static gboolean elevate_with_pkexec(void)
{
    char *pkexec = g_find_program_in_path("pkexec");
    if (!pkexec) return FALSE;

    char self[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
    if (n <= 0) { g_free(pkexec); return FALSE; }
    self[n] = '\0';

    const char *disp  = g_getenv("DISPLAY");
    const char *xauth = g_getenv("XAUTHORITY");
    const char *wl    = g_getenv("WAYLAND_DISPLAY");
    const char *xrd   = g_getenv("XDG_RUNTIME_DIR");

    /* X11 without XAUTHORITY set: fall back to the user's ~/.Xauthority so
     * the root process is allowed to open the display. */
    char *xauth_fallback = NULL;
    if (disp && !xauth) {
        xauth_fallback = g_build_filename(g_get_home_dir(), ".Xauthority", NULL);
        if (g_file_test(xauth_fallback, G_FILE_TEST_EXISTS))
            xauth = xauth_fallback;
    }

    GPtrArray *a = g_ptr_array_new_with_free_func(g_free);
    g_ptr_array_add(a, g_strdup(pkexec));
    g_ptr_array_add(a, g_strdup("env"));
    if (disp)  g_ptr_array_add(a, g_strdup_printf("DISPLAY=%s", disp));
    if (xauth) g_ptr_array_add(a, g_strdup_printf("XAUTHORITY=%s", xauth));
    if (wl)    g_ptr_array_add(a, g_strdup_printf("WAYLAND_DISPLAY=%s", wl));
    if (xrd)   g_ptr_array_add(a, g_strdup_printf("XDG_RUNTIME_DIR=%s", xrd));
    g_ptr_array_add(a, g_strdup(self));
    g_ptr_array_add(a, NULL);

    pid_t pid = fork();
    if (pid < 0) {                       /* fork failed */
        g_ptr_array_free(a, TRUE);
        g_free(pkexec);
        g_free(xauth_fallback);
        return FALSE;
    }
    if (pid == 0) {                      /* child: become the elevated GUI */
        execvp(pkexec, (char **)a->pdata);
        _exit(127);                      /* exec failed */
    }

    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) { }

    g_ptr_array_free(a, TRUE);
    g_free(pkexec);
    g_free(xauth_fallback);

    /* Exit code 126/127 = pkexec couldn't run / auth dismissed -> fall back. */
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

int main(int argc, char **argv)
{
    /* If we are not root, ask for admin credentials up front so the program
     * works when launched from the application menu (no terminal needed). */
    if (geteuid() != 0) {
        if (elevate_with_pkexec())
            return 0;   /* the elevated instance handled everything */
        /* else: pkexec unavailable or cancelled — keep running as the user;
         * each scan will still try to elevate via pkexec on its own. */
    }

    gtk_init(&argc, &argv);
    apply_cyber_theme();

    App app;
    memset(&app, 0, sizeof app);
    app.rkhunter_path = find_rkhunter();

    build_ui(&app);
    gtk_widget_show_all(app.window);
    gtk_widget_hide(app.spinner);

    gtk_main();

    g_free(app.rkhunter_path);
    return 0;
}
