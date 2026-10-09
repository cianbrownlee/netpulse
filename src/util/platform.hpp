#pragma once

// The few operating-system calls NetPulse needs outside of packet capture, behind one interface
// for Linux and Windows. (Capture's own differences live in capture/packet_capture.cpp.)

namespace netpulse {

// Names the calling thread, as shown by debuggers, `top -H` on Linux and Process Explorer on
// Windows. Best effort: failures are ignored.
void set_thread_name(const char* name);

// Whether standard output is an interactive terminal rather than a file or pipe.
bool stdout_is_terminal();

// Makes the terminal show UTF-8 output (the dashboard's box drawing, arrows and gauges) as such.
// Needed on Windows, whose console otherwise uses a legacy code page; nothing to do elsewhere.
void use_utf8_console();

// Windows sockets (Winsock) must be started before any name lookups or address conversions;
// this does so once per process. Nothing to do on Linux.
void ensure_sockets();

}  // namespace netpulse
