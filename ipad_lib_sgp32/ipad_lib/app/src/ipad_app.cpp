/**
 * @file ipad_app.cpp
 * @brief IPAd — Application de test IHM (ncurses TUI)
 *
 * Interface terminal interactive pour tester les services de la bibliothèque IPAd.
 * Compilation: cmake -DBUILD_APP=ON ..
 * Dépendances: libncurses, libipad
 */

#include <ncurses.h>
#include <cstring>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <thread>
#include <mutex>
#include <deque>
#include <atomic>
#include <chrono>
#include <functional>

#include "ipad/ipad.h"

/* ──────────────────────────────────────────────────────────────────────────────
 * Color pairs
 * ────────────────────────────────────────────────────────────────────────── */
#define CP_TITLE    1
#define CP_MENU_SEL 2
#define CP_MENU_NRM 3
#define CP_STATUS   4
#define CP_ERROR    5
#define CP_SUCCESS  6
#define CP_LOG      7
#define CP_HEADER   8

/* ──────────────────────────────────────────────────────────────────────────────
 * Application state
 * ────────────────────────────────────────────────────────────────────────── */
struct AppState {
    ipad_handle_t     hdl{nullptr};
    ipad_euicc_info_t euicc{};
    bool              euicc_loaded{false};

    std::vector<ipad_profile_t> profiles;
    int                         selected_profile{0};

    std::mutex        log_mutex;
    std::deque<std::string> log_entries;
    static constexpr size_t LOG_MAX = 200;

    std::atomic<bool> running{true};
    std::string       status_msg;
    bool              status_ok{true};
    bool              telsdk_mock{false};
};

static AppState g_app;

/* ──────────────────────────────────────────────────────────────────────────────
 * Logging
 * ────────────────────────────────────────────────────────────────────────── */
void app_log(const std::string &msg, bool ok = true) {
    auto now = std::chrono::system_clock::now();
    auto t   = std::chrono::system_clock::to_time_t(now);
    char ts[20]; strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&t));
    std::string entry = std::string(ts) + (ok ? " [OK] " : " [!!] ") + msg;
    std::lock_guard<std::mutex> lk(g_app.log_mutex);
    g_app.log_entries.push_front(entry);
    if (g_app.log_entries.size() > AppState::LOG_MAX) g_app.log_entries.pop_back();
    g_app.status_msg = msg;
    g_app.status_ok  = ok;
}

static void ipad_log_bridge(ipad_loglevel_t level, const char *module,
                             const char *msg, void *) {
    if (level <= IPAD_LOG_WARN)
        app_log(std::string("[") + module + "] " + msg, level != IPAD_LOG_ERROR);
}

/* ──────────────────────────────────────────────────────────────────────────────
 * Event callback
 * ────────────────────────────────────────────────────────────────────────── */
static void on_event(ipad_handle_t, const ipad_event_t *evt, void *) {
    std::string s;
    switch (evt->type) {
        case IPAD_EVT_PROFILE_INSTALLED:  s = "Profile installed";           break;
        case IPAD_EVT_PROFILE_ENABLED:    s = "Profile ENABLED";             break;
        case IPAD_EVT_PROFILE_DISABLED:   s = "Profile DISABLED";            break;
        case IPAD_EVT_PROFILE_DELETED:    s = "Profile DELETED";             break;
        case IPAD_EVT_DOWNLOAD_PROGRESS:
            s = "Download " + std::to_string(evt->progress_pct) + "%";       break;
        case IPAD_EVT_EIM_CONNECTED:      s = "eIM connected";               break;
        case IPAD_EVT_EIM_DISCONNECTED:   s = "eIM disconnected";            break;
        case IPAD_EVT_NETWORK_ATTACHED:   s = "Network attached";            break;
        case IPAD_EVT_ERROR:              s = "Error: " + std::string(evt->detail); break;
        default:                          s = "Event " + std::to_string(evt->type); break;
    }
    app_log(s, evt->status == IPAD_OK);
}

/* ──────────────────────────────────────────────────────────────────────────────
 * ncurses helpers
 * ────────────────────────────────────────────────────────────────────────── */
struct Rect { int y, x, h, w; };

static void draw_box(WINDOW *win, const Rect &r, const char *title) {
    wattron(win, COLOR_PAIR(CP_HEADER));
    mvwhline(win, r.y, r.x, ACS_HLINE, r.w);
    mvwhline(win, r.y + r.h - 1, r.x, ACS_HLINE, r.w);
    mvwvline(win, r.y, r.x, ACS_VLINE, r.h);
    mvwvline(win, r.y, r.x + r.w - 1, ACS_VLINE, r.h);
    mvwaddch(win, r.y, r.x, ACS_ULCORNER);
    mvwaddch(win, r.y, r.x + r.w - 1, ACS_URCORNER);
    mvwaddch(win, r.y + r.h - 1, r.x, ACS_LLCORNER);
    mvwaddch(win, r.y + r.h - 1, r.x + r.w - 1, ACS_LRCORNER);
    if (title && title[0]) {
        wattron(win, A_BOLD);
        mvwprintw(win, r.y, r.x + 2, " %s ", title);
        wattroff(win, A_BOLD);
    }
    wattroff(win, COLOR_PAIR(CP_HEADER));
}

static std::string readline_popup(WINDOW *parent, const char *prompt,
                                   int maxlen = 200) {
    int rows, cols;
    getmaxyx(parent, rows, cols);
    int pw = 60, ph = 5;
    int py = (rows - ph) / 2, px = (cols - pw) / 2;

    WINDOW *pop = newwin(ph, pw, py, px);
    box(pop, 0, 0);
    wattron(pop, COLOR_PAIR(CP_TITLE) | A_BOLD);
    mvwprintw(pop, 0, 2, " Entrée ");
    wattroff(pop, COLOR_PAIR(CP_TITLE) | A_BOLD);
    mvwprintw(pop, 1, 2, "%s", prompt);
    mvwprintw(pop, 2, 2, "> ");
    wrefresh(pop);

    echo(); curs_set(1);
    char buf[256] = {};
    mvwgetnstr(pop, 2, 4, buf, std::min(maxlen, 250));
    noecho(); curs_set(0);

    delwin(pop);
    touchwin(parent);
    wrefresh(parent);
    return std::string(buf);
}

static bool confirm_popup(WINDOW *parent, const char *msg) {
    int rows, cols;
    getmaxyx(parent, rows, cols);
    WINDOW *pop = newwin(5, 50, (rows-5)/2, (cols-50)/2);
    box(pop, 0, 0);
    wattron(pop, COLOR_PAIR(CP_ERROR) | A_BOLD);
    mvwprintw(pop, 0, 2, " Confirmation ");
    wattroff(pop, COLOR_PAIR(CP_ERROR) | A_BOLD);
    mvwprintw(pop, 1, 2, "%s", msg);
    mvwprintw(pop, 3, 2, "[O]ui  [N]on");
    wrefresh(pop);
    int c = wgetch(pop);
    delwin(pop);
    touchwin(parent); wrefresh(parent);
    return (c == 'o' || c == 'O' || c == 'y' || c == 'Y');
}

/* ──────────────────────────────────────────────────────────────────────────────
 * Refresh helpers
 * ────────────────────────────────────────────────────────────────────────── */
static void refresh_profiles() {
    if (!g_app.hdl) return;
    uint8_t count = 16;
    ipad_profile_t list[16];
    if (ipad_profile_list(g_app.hdl, list, &count) == IPAD_OK) {
        g_app.profiles.assign(list, list + count);
        if (g_app.selected_profile >= (int)g_app.profiles.size())
            g_app.selected_profile = (int)g_app.profiles.size() - 1;
        if (g_app.selected_profile < 0) g_app.selected_profile = 0;
    }
}

static void refresh_euicc() {
    if (!g_app.hdl) return;
    if (ipad_get_euicc_info(g_app.hdl, &g_app.euicc) == IPAD_OK)
        g_app.euicc_loaded = true;
}

/* ──────────────────────────────────────────────────────────────────────────────
 * Main UI
 * ────────────────────────────────────────────────────────────────────────── */
static void draw_ui(WINDOW *win) {
    int rows, cols;
    getmaxyx(win, rows, cols);
    werase(win);

    /* ── Title bar ────────────────────────────────────────────────────── */
    wattron(win, COLOR_PAIR(CP_TITLE) | A_BOLD);
    mvwhline(win, 0, 0, ' ', cols);
    mvwprintw(win, 0, 2, " IPAd Test Application  [GSMA SGP.32 — Qualcomm SA525 TelSDK] ");
    mvwprintw(win, 0, cols - 20, g_app.telsdk_mock ? " [MOCK] " : " [HW]   ");
    wattroff(win, COLOR_PAIR(CP_TITLE) | A_BOLD);

    /* ── eUICC info panel ─────────────────────────────────────────────── */
    Rect r_eid = {1, 0, 4, cols};
    draw_box(win, r_eid, "eUICC Info");
    if (g_app.euicc_loaded) {
        mvwprintw(win, 2, 2, "EID : %.32s", g_app.euicc.eid_str);
        mvwprintw(win, 2, cols/2, "Profils : %u/%u",
                  (unsigned)g_app.profiles.size(),
                  g_app.euicc.profile_capacity);
    } else {
        wattron(win, COLOR_PAIR(CP_ERROR));
        mvwprintw(win, 2, 2, "Non connecté — appuyez sur 'i' pour initialiser");
        wattroff(win, COLOR_PAIR(CP_ERROR));
    }

    /* ── Profile list ─────────────────────────────────────────────────── */
    int list_h = rows - 15;
    Rect r_lst = {5, 0, list_h, cols * 2 / 3};
    draw_box(win, r_lst, "Profils eSIM");

    /* Header */
    wattron(win, COLOR_PAIR(CP_HEADER) | A_BOLD);
    mvwprintw(win, 6, 2, "%-3s %-22s %-12s %-18s %-8s",
              "#", "ICCID", "État", "Fournisseur", "Nickname");
    wattroff(win, COLOR_PAIR(CP_HEADER) | A_BOLD);

    for (int i = 0; i < (int)g_app.profiles.size() && i < list_h - 4; ++i) {
        auto &p = g_app.profiles[i];
        char iccid_s[21]; ipad_iccid_to_str(p.iccid, iccid_s);
        const char *state_str;
        int cp;
        switch (p.state) {
            case IPAD_PROFILE_ENABLED:  state_str = "ACTIF   "; cp = CP_SUCCESS; break;
            case IPAD_PROFILE_DISABLED: state_str = "inactif "; cp = CP_LOG;     break;
            default:                    state_str = "pending "; cp = CP_STATUS;  break;
        }
        if (i == g_app.selected_profile)
            wattron(win, COLOR_PAIR(CP_MENU_SEL) | A_BOLD);
        else
            wattron(win, COLOR_PAIR(CP_MENU_NRM));

        mvwprintw(win, 7 + i, 2, "%-3d %-22s ", i + 1, iccid_s);
        wattroff(win, COLOR_PAIR(CP_MENU_SEL) | COLOR_PAIR(CP_MENU_NRM));
        wattron(win, COLOR_PAIR(cp) | (i == g_app.selected_profile ? A_BOLD : 0));
        wprintw(win, "%-12s ", state_str);
        wattroff(win, COLOR_PAIR(cp) | A_BOLD);

        if (i == g_app.selected_profile) wattron(win, COLOR_PAIR(CP_MENU_SEL) | A_BOLD);
        wprintw(win, "%-18.18s %-8.8s", p.provider, p.nickname);
        wattroff(win, COLOR_PAIR(CP_MENU_SEL) | A_BOLD | COLOR_PAIR(CP_MENU_NRM));
    }

    if (g_app.profiles.empty()) {
        wattron(win, COLOR_PAIR(CP_LOG));
        mvwprintw(win, 7, 4, "(aucun profil installé)");
        wattroff(win, COLOR_PAIR(CP_LOG));
    }

    /* ── Menu panel ───────────────────────────────────────────────────── */
    int menu_x = cols * 2 / 3 + 1;
    int menu_w = cols - menu_x;
    Rect r_menu = {5, menu_x, list_h, menu_w};
    draw_box(win, r_menu, "Actions");

    struct MenuItem { char key; const char *label; };
    static const MenuItem items[] = {
        {'i', "Initialiser"},
        {'r', "Rafraîchir"},
        {'d', "Télécharger profil"},
        {'e', "Activer sélection"},
        {'x', "Désactiver sélection"},
        {'D', "Supprimer sélection"},
        {'n', "Renommer profil"},
        {'s', "Self-test"},
        {'j', "Export diagnostics"},
        {'+', "Profil suivant"},
        {'-', "Profil précédent"},
        {'q', "Quitter"},
    };
    for (int i = 0; i < (int)(sizeof(items)/sizeof(items[0])); ++i) {
        wattron(win, COLOR_PAIR(CP_MENU_SEL) | A_BOLD);
        mvwprintw(win, 6 + i, menu_x + 2, "[%c]", items[i].key);
        wattroff(win, COLOR_PAIR(CP_MENU_SEL) | A_BOLD);
        wattron(win, COLOR_PAIR(CP_MENU_NRM));
        wprintw(win, " %s", items[i].label);
        wattroff(win, COLOR_PAIR(CP_MENU_NRM));
    }

    /* ── Log panel ────────────────────────────────────────────────────── */
    int log_y = 5 + list_h;
    int log_h = rows - log_y - 2;
    Rect r_log = {log_y, 0, log_h, cols};
    draw_box(win, r_log, "Journal événements");
    {
        std::lock_guard<std::mutex> lk(g_app.log_mutex);
        for (int i = 0; i < log_h - 2 && i < (int)g_app.log_entries.size(); ++i) {
            bool ok = g_app.log_entries[i].find("[!!]") == std::string::npos;
            wattron(win, COLOR_PAIR(ok ? CP_LOG : CP_ERROR));
            mvwprintw(win, log_y + 1 + i, 2, "%-*.*s",
                      cols - 4, cols - 4, g_app.log_entries[i].c_str());
            wattroff(win, COLOR_PAIR(ok ? CP_LOG : CP_ERROR));
        }
    }

    /* ── Status bar ───────────────────────────────────────────────────── */
    wattron(win, COLOR_PAIR(g_app.status_ok ? CP_SUCCESS : CP_ERROR) | A_BOLD);
    mvwhline(win, rows - 1, 0, ' ', cols);
    mvwprintw(win, rows - 1, 1, " %s", g_app.status_msg.c_str());
    wattroff(win, COLOR_PAIR(CP_SUCCESS) | COLOR_PAIR(CP_ERROR) | A_BOLD);

    wrefresh(win);
}

/* ──────────────────────────────────────────────────────────────────────────────
 * Actions
 * ────────────────────────────────────────────────────────────────────────── */
static void action_init(WINDOW *win) {
    if (g_app.hdl) {
        ipad_deinit(g_app.hdl);
        g_app.hdl = nullptr;
        g_app.euicc_loaded = false;
        g_app.profiles.clear();
    }
    ipad_config_t cfg{};
    cfg.timeout_ms = 10000;
    cfg.log_level  = IPAD_LOG_INFO;
    cfg.slot_id    = 0;

    ipad_status_t rc = ipad_init(&cfg, &g_app.hdl);
    if (rc != IPAD_OK) {
        app_log("Init échoué : " + std::string(ipad_strerror(rc)), false);
        return;
    }
    ipad_log_set_handler(g_app.hdl, ipad_log_bridge, nullptr);
    ipad_event_subscribe(g_app.hdl, IPAD_EVT_ALL, on_event, nullptr);
    refresh_euicc();
    refresh_profiles();
    app_log("IPAd initialisé — EID: " + std::string(g_app.euicc.eid_str));
}

static void action_download(WINDOW *win) {
    if (!g_app.hdl) { app_log("Non initialisé", false); return; }
    std::string ac = readline_popup(win,
        "Activation Code (LPA:1$host$matchid) :", 180);
    if (ac.empty()) return;

    app_log("Téléchargement en cours…");

    /* Run in background thread to keep UI responsive */
    std::thread([ac]{
        ipad_dl_params_t params{};
        params.activation_code = ac.c_str();
        params.auto_enable     = false;
        ipad_iccid_t iccid{};
        ipad_status_t rc = ipad_profile_download(g_app.hdl, &params, iccid);
        if (rc == IPAD_OK) {
            char s[21]; ipad_iccid_to_str(iccid, s);
            app_log("Profil installé : " + std::string(s));
            refresh_profiles();
        } else {
            app_log("Échec download : " + std::string(ipad_strerror(rc)), false);
        }
    }).detach();
}

static void action_enable(WINDOW *) {
    if (!g_app.hdl || g_app.profiles.empty()) return;
    auto &p  = g_app.profiles[g_app.selected_profile];
    ipad_status_t rc = ipad_profile_enable(g_app.hdl, p.iccid);
    if (rc == IPAD_OK) { app_log("Profil activé"); refresh_profiles(); }
    else app_log("Erreur activation : " + std::string(ipad_strerror(rc)), false);
}

static void action_disable(WINDOW *) {
    if (!g_app.hdl || g_app.profiles.empty()) return;
    auto &p  = g_app.profiles[g_app.selected_profile];
    ipad_status_t rc = ipad_profile_disable(g_app.hdl, p.iccid);
    if (rc == IPAD_OK) { app_log("Profil désactivé"); refresh_profiles(); }
    else app_log("Erreur désactivation : " + std::string(ipad_strerror(rc)), false);
}

static void action_delete(WINDOW *win) {
    if (!g_app.hdl || g_app.profiles.empty()) return;
    if (!confirm_popup(win, "Supprimer ce profil ? (irréversible)")) return;
    auto &p = g_app.profiles[g_app.selected_profile];
    ipad_status_t rc = ipad_profile_delete(g_app.hdl, p.iccid);
    if (rc == IPAD_OK) { app_log("Profil supprimé"); refresh_profiles(); }
    else app_log("Erreur suppression : " + std::string(ipad_strerror(rc)), false);
}

static void action_rename(WINDOW *win) {
    if (!g_app.hdl || g_app.profiles.empty()) return;
    std::string nick = readline_popup(win, "Nouveau nom du profil :", 63);
    if (nick.empty()) return;
    auto &p = g_app.profiles[g_app.selected_profile];
    ipad_status_t rc = ipad_profile_set_nickname(g_app.hdl, p.iccid, nick.c_str());
    if (rc == IPAD_OK) { app_log("Nom mis à jour"); refresh_profiles(); }
    else app_log("Erreur rename : " + std::string(ipad_strerror(rc)), false);
}

static void action_selftest(WINDOW *) {
    if (!g_app.hdl) { app_log("Non initialisé", false); return; }
    uint32_t result = 0;
    ipad_status_t rc = ipad_selftest(g_app.hdl, &result);
    if (rc == IPAD_OK) {
        std::ostringstream oss;
        oss << "Self-test OK, bitmask=0x" << std::hex << result;
        app_log(oss.str());
    } else {
        app_log("Self-test échoué : " + std::string(ipad_strerror(rc)), false);
    }
}

static void action_diag(WINDOW *) {
    if (!g_app.hdl) { app_log("Non initialisé", false); return; }
    char buf[2048];
    ipad_status_t rc = ipad_diag_export_json(g_app.hdl, buf, sizeof(buf));
    if (rc == IPAD_OK) app_log("Diag: " + std::string(buf));
    else app_log("Diag échoué", false);
}

/* ──────────────────────────────────────────────────────────────────────────────
 * Event pump thread
 * ────────────────────────────────────────────────────────────────────────── */
static void event_thread_fn() {
    while (g_app.running) {
        if (g_app.hdl) ipad_event_pump(g_app.hdl, 100);
        else std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

/* ──────────────────────────────────────────────────────────────────────────────
 * Main
 * ────────────────────────────────────────────────────────────────────────── */
int main(int argc, char **argv) {
    /* Check for --mock flag */
    for (int i = 1; i < argc; ++i)
        if (std::string(argv[i]) == "--mock") g_app.telsdk_mock = true;

    /* Init ncurses */
    initscr();
    start_color(); use_default_colors();
    noecho(); cbreak(); curs_set(0);
    keypad(stdscr, TRUE);
    timeout(200);  /* non-blocking getch */

    init_pair(CP_TITLE,    COLOR_WHITE, COLOR_BLUE);
    init_pair(CP_MENU_SEL, COLOR_BLACK, COLOR_CYAN);
    init_pair(CP_MENU_NRM, COLOR_CYAN,  -1);
    init_pair(CP_STATUS,   COLOR_YELLOW,-1);
    init_pair(CP_ERROR,    COLOR_RED,   -1);
    init_pair(CP_SUCCESS,  COLOR_GREEN, -1);
    init_pair(CP_LOG,      COLOR_WHITE, -1);
    init_pair(CP_HEADER,   COLOR_BLUE,  -1);

    WINDOW *main_win = newwin(0, 0, 0, 0);
    keypad(main_win, TRUE);

    app_log("Prêt — appuyez sur 'i' pour initialiser IPAd");

    /* Start event pump thread */
    std::thread ev_thread(event_thread_fn);

    while (g_app.running) {
        draw_ui(main_win);
        int c = wgetch(main_win);

        switch (c) {
            case 'q': case 'Q':
                if (confirm_popup(main_win, "Quitter l'application ?"))
                    g_app.running = false;
                break;
            case 'i': action_init(main_win);    break;
            case 'r': refresh_profiles(); refresh_euicc(); app_log("Rafraîchi"); break;
            case 'd': action_download(main_win); break;
            case 'e': action_enable(main_win);  break;
            case 'x': action_disable(main_win); break;
            case 'D': action_delete(main_win);  break;
            case 'n': action_rename(main_win);  break;
            case 's': action_selftest(main_win); break;
            case 'j': action_diag(main_win);    break;
            case '+': case KEY_DOWN:
                if (!g_app.profiles.empty())
                    g_app.selected_profile = (g_app.selected_profile + 1) % (int)g_app.profiles.size();
                break;
            case '-': case KEY_UP:
                if (!g_app.profiles.empty())
                    g_app.selected_profile = (g_app.selected_profile - 1 + (int)g_app.profiles.size()) % (int)g_app.profiles.size();
                break;
            case KEY_RESIZE:
                wresize(main_win, LINES, COLS);
                break;
        }
    }

    ev_thread.join();
    if (g_app.hdl) ipad_deinit(g_app.hdl);
    delwin(main_win);
    endwin();
    return 0;
}
