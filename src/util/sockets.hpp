#pragma once

// The sockets headers for address conversion (inet_pton, inet_ntop) and name lookups
// (getnameinfo), which Windows and POSIX spell differently. On Windows, call ensure_sockets()
// (util/platform.hpp) before using them.

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif
