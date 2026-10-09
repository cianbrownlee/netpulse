#include "util/platform.hpp"

#ifdef _WIN32
#include <winsock2.h>  // before windows.h, which would otherwise pull in the old winsock.h
#include <windows.h>
#include <io.h>

#include <cstdio>
#include <string>
#else
#include <pthread.h>
#include <unistd.h>
#endif

namespace netpulse {

#ifdef _WIN32

void set_thread_name(const char* name) {
    // SetThreadDescription takes UTF-16; thread names here are plain ASCII.
    const std::string narrow(name);
    const std::wstring wide(narrow.begin(), narrow.end());
    SetThreadDescription(GetCurrentThread(), wide.c_str());
}

bool stdout_is_terminal() { return _isatty(_fileno(stdout)) != 0; }

void use_utf8_console() { SetConsoleOutputCP(CP_UTF8); }

void ensure_sockets() {
    // Started once and never cleaned up: Windows does that when the process exits.
    static const bool started = [] {
        WSADATA data;
        return WSAStartup(MAKEWORD(2, 2), &data) == 0;
    }();
    (void)started;
}

#else

void set_thread_name(const char* name) {
    // Linux limits names to 15 characters; NetPulse's ("np-aggregate") fit.
    pthread_setname_np(pthread_self(), name);
}

bool stdout_is_terminal() { return isatty(STDOUT_FILENO) != 0; }

void use_utf8_console() {}

void ensure_sockets() {}

#endif

}  // namespace netpulse
