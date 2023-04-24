/* Refresh interval in seconds */
const unsigned int refresh = 5;

/* MPD options */
/* MPD connection, either path to a UNIX domain sockets, or an IP address for a TCP connection. */
const char *mpd_host = "/home/rot13/Music/.mpd/socket";
const unsigned int mpd_port = 0; /* Unnecessary when used with UNIX socket. */
const unsigned int mpd_timeout = 0;

/* Network options */
const char *wired_interfaces[] = {"eno0", NULL}; /* Make sure the last element is always NULL. */
const char *wireless_interfaces[] = {"wlp2s0", NULL}; /* Make sure the last element is always NULL. */

/* Battery options */
#define BATTERY_PATH "/sys/class/power_supply/BAT0"
#define AC_PATH "/sys/class/power_supply/AC"
