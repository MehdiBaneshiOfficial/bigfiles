#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <uxtheme.h>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <algorithm>

#define WM_SCAN_DONE (WM_APP + 1)
enum { ID_BTN = 1, ID_LIST = 2, ID_STATUS = 3 };

struct Entry { ULONGLONG size; std::wstring path; };

static std::vector<Entry> g_entries;
static HWND g_wnd, g_list, g_btn, g_status;
static HFONT g_font;
static int g_dpi = 96;
static std::atomic<long long> g_files{0};
static std::atomic<bool> g_scanning{false};
static ULONGLONG g_freed = 0;

static const ULONGLONG MIN_SIZE = 1ull << 20;  // فایل‌های زیر ۱ مگابایت نادیده گرفته می‌شوند
static const size_t TOP_N = 300;               // تعداد فایل‌های نمایش‌داده‌شده

static int S(int v) { return MulDiv(v, g_dpi, 96); }

static void FmtSize(ULONGLONG s, wchar_t* b, size_t n) {
    double d = (double)s;
    if (s >= (1ull << 30)) _snwprintf(b, n, L"%.2f GB", d / 1073741824.0);
    else if (s >= (1ull << 20)) _snwprintf(b, n, L"%.1f MB", d / 1048576.0);
    else _snwprintf(b, n, L"%.0f KB", d / 1024.0);
    b[n - 1] = 0;
}

// پوشه‌های سیستمی (فقط در ریشه درایو بررسی می‌شوند)
static bool Excluded(const wchar_t* n) {
    static const wchar_t* kSkip[] = {
        L"Windows", L"Program Files", L"Program Files (x86)", L"ProgramData",
        L"$Recycle.Bin", L"System Volume Information", L"Recovery",
        L"$WinREAgent", L"Windows.old", L"$Windows.~BT", L"$Windows.~WS"};
    for (auto s : kSkip) if (_wcsicmp(n, s) == 0) return true;
    return false;
}

static void Trim(std::vector<Entry>& v) {
    if (v.size() > TOP_N) {
        std::partial_sort(v.begin(), v.begin() + TOP_N, v.end(),
                          [](const Entry& a, const Entry& b) { return a.size > b.size; });
        v.resize(TOP_N);
    }
}

struct Shared {
    std::mutex m;
    std::condition_variable cv;
    std::vector<std::wstring> dirs;
    int active = 0;
    std::vector<Entry> all;
};

static void ScanDir(const std::wstring& dir, std::vector<Entry>& loc, std::vector<std::wstring>& sub) {
    std::wstring base = dir;
    if (base.back() != L'\\') base += L'\\';
    bool root = base.size() == 3;
    std::wstring pat = base + L'*';
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileExW(pat.c_str(), FindExInfoBasic, &fd, FindExSearchNameMatch,
                                nullptr, FIND_FIRST_EX_LARGE_FETCH);
    if (h == INVALID_HANDLE_VALUE) return;
    long long cnt = 0;
    do {
        const wchar_t* n = fd.cFileName;
        if (n[0] == L'.' && (n[1] == 0 || (n[1] == L'.' && n[2] == 0))) continue;
        DWORD a = fd.dwFileAttributes;
        if (a & FILE_ATTRIBUTE_DIRECTORY) {
            if (a & FILE_ATTRIBUTE_REPARSE_POINT) continue;
            if (root && Excluded(n)) continue;
            sub.push_back(base + n);
        } else {
            cnt++;
            if (a & FILE_ATTRIBUTE_SYSTEM) continue;
            if (a & (FILE_ATTRIBUTE_OFFLINE | 0x00400000 | 0x00040000)) continue;  // فایل‌های ابری
            ULONGLONG sz = ((ULONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            if (sz < MIN_SIZE) continue;
            loc.push_back({sz, base + n});
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    g_files += cnt;
}

static void Worker(Shared* sh) {
    std::vector<Entry> loc;
    std::vector<std::wstring> sub;
    std::unique_lock<std::mutex> lk(sh->m);
    for (;;) {
        if (!sh->dirs.empty()) {
            std::wstring dir = std::move(sh->dirs.back());
            sh->dirs.pop_back();
            sh->active++;
            lk.unlock();
            sub.clear();
            ScanDir(dir, loc, sub);
            if (loc.size() >= 1500) Trim(loc);
            lk.lock();
            sh->active--;
            if (!sub.empty()) {
                for (auto& s : sub) sh->dirs.push_back(std::move(s));
                sh->cv.notify_all();
            } else if (sh->dirs.empty() && sh->active == 0) {
                sh->cv.notify_all();
            }
        } else if (sh->active == 0) {
            break;
        } else {
            sh->cv.wait(lk);
        }
    }
    Trim(loc);
    for (auto& e : loc) sh->all.push_back(std::move(e));
}

static void ScanMain() {
    Shared sh;
    DWORD mask = GetLogicalDrives();
    for (int i = 0; i < 26; i++) {
        if (!(mask & (1u << i))) continue;
        wchar_t r[4] = {(wchar_t)(L'A' + i), L':', L'\\', 0};
        if (GetDriveTypeW(r) == DRIVE_FIXED) sh.dirs.push_back(r);
    }
    unsigned n = std::max(4u, std::thread::hardware_concurrency() * 2);
    std::vector<std::thread> th;
    for (unsigned i = 0; i < n; i++) th.emplace_back(Worker, &sh);
    for (auto& t : th) t.join();
    std::sort(sh.all.begin(), sh.all.end(), [](const Entry& a, const Entry& b) { return a.size > b.size; });
    if (sh.all.size() > TOP_N) sh.all.resize(TOP_N);
    auto* res = new std::vector<Entry>(std::move(sh.all));
    PostMessageW(g_wnd, WM_SCAN_DONE, 0, (LPARAM)res);
}

static void StartScan() {
    if (g_scanning.exchange(true)) return;
    g_files = 0;
    ListView_DeleteAllItems(g_list);
    g_entries.clear();
    EnableWindow(g_btn, FALSE);
    SetTimer(g_wnd, 1, 150, nullptr);
    SetWindowTextW(g_status, L"در حال اسکن…");
    std::thread(ScanMain).detach();
}

static void OnScanDone(std::vector<Entry>* res) {
    KillTimer(g_wnd, 1);
    g_entries = std::move(*res);
    delete res;
    SendMessageW(g_list, WM_SETREDRAW, FALSE, 0);
    for (size_t i = 0; i < g_entries.size(); i++) {
        wchar_t b[32];
        FmtSize(g_entries[i].size, b, 32);
        LVITEMW it = {};
        it.mask = LVIF_TEXT | LVIF_PARAM;
        it.iItem = (int)i;
        it.lParam = (LPARAM)i;
        it.pszText = b;
        ListView_InsertItem(g_list, &it);
        ListView_SetItemText(g_list, (int)i, 1, (LPWSTR)g_entries[i].path.c_str());
        ListView_SetItemText(g_list, (int)i, 2, (LPWSTR)L"حذف");
    }
    SendMessageW(g_list, WM_SETREDRAW, TRUE, 0);
    wchar_t st[128];
    _snwprintf(st, 128, L"%lld فایل بررسی شد  |  %u فایل حجیم", (long long)g_files.load(), (unsigned)g_entries.size());
    st[127] = 0;
    SetWindowTextW(g_status, st);
    g_scanning = false;
    EnableWindow(g_btn, TRUE);
}

static void DeleteRow(int idx) {
    LVITEMW it = {};
    it.mask = LVIF_PARAM;
    it.iItem = idx;
    if (!ListView_GetItem(g_list, &it)) return;
    const Entry& e = g_entries[(size_t)it.lParam];
    bool exists = GetFileAttributesW(e.path.c_str()) != INVALID_FILE_ATTRIBUTES;
    if (exists) {
        std::wstring msg = e.path + L"\n\nاین فایل به سطل بازیافت منتقل می‌شود.";
        if (MessageBoxW(g_wnd, msg.c_str(), L"حذف فایل",
                        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_RTLREADING | MB_RIGHT) != IDYES)
            return;
        std::wstring p = e.path;
        p.push_back(L'\0');  // رشته باید با دو null تمام شود
        SHFILEOPSTRUCTW op = {};
        op.hwnd = g_wnd;
        op.wFunc = FO_DELETE;
        op.pFrom = p.c_str();
        op.fFlags = FOF_ALLOWUNDO | FOF_SILENT;
        int r = SHFileOperationW(&op);
        if (r != 0 || op.fAnyOperationsAborted) return;
        g_freed += e.size;
    }
    ListView_DeleteItem(g_list, idx);
    wchar_t b[32], st[96];
    FmtSize(g_freed, b, 32);
    _snwprintf(st, 96, L"%s آزاد شد", b);
    st[95] = 0;
    SetWindowTextW(g_status, st);
}

static void Layout() {
    RECT rc;
    GetClientRect(g_wnd, &rc);
    int w = rc.right, h = rc.bottom, bar = S(44);
    MoveWindow(g_btn, S(10), S(8), S(110), S(28), TRUE);
    MoveWindow(g_status, S(132), S(14), std::max(0, w - S(142)), S(20), TRUE);
    MoveWindow(g_list, 0, bar, w, std::max(0, h - bar), TRUE);
    int c0 = S(100), c2 = S(70);
    int c1 = w - c0 - c2 - GetSystemMetrics(SM_CXVSCROLL) - S(4);
    if (c1 < S(150)) c1 = S(150);
    ListView_SetColumnWidth(g_list, 0, c0);
    ListView_SetColumnWidth(g_list, 1, c1);
    ListView_SetColumnWidth(g_list, 2, c2);
}

static void AddCol(int i, const wchar_t* t, int w, int fmt) {
    LVCOLUMNW c = {};
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
    c.pszText = (LPWSTR)t;
    c.cx = w;
    c.fmt = fmt;
    ListView_InsertColumn(g_list, i, &c);
}

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
    switch (m) {
    case WM_CREATE: {
        g_wnd = h;
        g_btn = CreateWindowExW(0, L"BUTTON", L"اسکن مجدد", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                0, 0, 0, 0, h, (HMENU)ID_BTN, nullptr, nullptr);
        g_status = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
                                   0, 0, 0, 0, h, (HMENU)ID_STATUS, nullptr, nullptr);
        g_list = CreateWindowExW(0, WC_LISTVIEWW, L"",
                                 WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                                 0, 0, 0, 0, h, (HMENU)ID_LIST, nullptr, nullptr);
        ListView_SetExtendedListViewStyle(g_list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
        SetWindowTheme(g_list, L"Explorer", nullptr);
        SendMessageW(g_btn, WM_SETFONT, (WPARAM)g_font, TRUE);
        SendMessageW(g_status, WM_SETFONT, (WPARAM)g_font, TRUE);
        SendMessageW(g_list, WM_SETFONT, (WPARAM)g_font, TRUE);
        AddCol(0, L"حجم", S(100), LVCFMT_RIGHT);
        AddCol(1, L"مسیر فایل", S(500), LVCFMT_LEFT);
        AddCol(2, L"عملیات", S(70), LVCFMT_CENTER);
        return 0;
    }
    case WM_SIZE:
        if (g_list) Layout();
        return 0;
    case WM_GETMINMAXINFO:
        ((MINMAXINFO*)lp)->ptMinTrackSize = {S(480), S(300)};
        return 0;
    case WM_COMMAND:
        if (LOWORD(wp) == ID_BTN) StartScan();
        return 0;
    case WM_TIMER: {
        wchar_t b[96];
        _snwprintf(b, 96, L"در حال اسکن…  %lld فایل", (long long)g_files.load());
        b[95] = 0;
        SetWindowTextW(g_status, b);
        return 0;
    }
    case WM_SCAN_DONE:
        OnScanDone((std::vector<Entry>*)lp);
        return 0;
    case WM_NOTIFY: {
        NMHDR* nh = (NMHDR*)lp;
        if (nh->idFrom != ID_LIST) break;
        if (nh->code == NM_CUSTOMDRAW) {
            LPNMLVCUSTOMDRAW cd = (LPNMLVCUSTOMDRAW)lp;
            switch (cd->nmcd.dwDrawStage) {
            case CDDS_PREPAINT: return CDRF_NOTIFYITEMDRAW;
            case CDDS_ITEMPREPAINT: return CDRF_NOTIFYSUBITEMDRAW;
            case (CDDS_ITEMPREPAINT | CDDS_SUBITEM):
                if (cd->iSubItem == 2) cd->clrText = RGB(200, 40, 40);
                return CDRF_DODEFAULT;
            }
            return CDRF_DODEFAULT;
        }
        if (nh->code == NM_CLICK) {
            LPNMITEMACTIVATE a = (LPNMITEMACTIVATE)lp;
            LVHITTESTINFO ht = {};
            ht.pt = a->ptAction;
            ListView_SubItemHitTest(g_list, &ht);
            if (ht.iItem >= 0 && ht.iSubItem == 2) DeleteRow(ht.iItem);
        }
        break;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, m, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hi, HINSTANCE, PWSTR, int show) {
    HDC dc = GetDC(nullptr);
    g_dpi = GetDeviceCaps(dc, LOGPIXELSY);
    ReleaseDC(nullptr, dc);

    INITCOMMONCONTROLSEX ic = {sizeof(ic), ICC_LISTVIEW_CLASSES};
    InitCommonControlsEx(&ic);

    NONCLIENTMETRICSW ncm = {};
    ncm.cbSize = sizeof(ncm);
    SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
    g_font = CreateFontIndirectW(&ncm.lfMessageFont);

    WNDCLASSW wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hi;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"BigFilesWnd";
    RegisterClassW(&wc);

    HWND w = CreateWindowExW(0, wc.lpszClassName, L"حجیم‌ترین فایل‌ها", WS_OVERLAPPEDWINDOW,
                             CW_USEDEFAULT, CW_USEDEFAULT, S(900), S(600), nullptr, nullptr, hi, nullptr);
    ShowWindow(w, show);
    Layout();
    StartScan();

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}
