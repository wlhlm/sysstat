/* See LICENSE file for license details. */

#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/timerfd.h>

#include <mpd/client.h>
#include <yajl/yajl_gen.h>
#include <yajl/yajl_parse.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <pwd.h>
#include <string.h>
#include <time.h>
#include <poll.h>
#include <errno.h>
#include <signal.h>

#include "fuzzyclock.h"

/* Refresh interval in seconds */
const unsigned int refresh = 5;
const char *mpd_host = "/home/helm/Music/.mpd/socket";
const unsigned int mpd_port = 0; /* Unnecessary when used with UNIX socket. */
const unsigned int mpd_timeout = 0;

#define CUC(var) (const unsigned char *)var

typedef enum {
	EVENT_NAME,
	EVENT_INSTANCE,
	EVENT_X, EVENT_Y,
	EVENT_BUTTON
} ClickEventKey;

typedef struct {
	char *name;
	char *instance;

	uint32_t x;
	uint32_t y;

	uint32_t button;
} ClickEvent;

typedef struct {
	ClickEventKey last_key;
	ClickEvent event;
} ParserContext;

char *progname;
char *kernel = NULL;
char *user = NULL;
bool use_fuzzytime = true;
struct mpd_connection *connection;
yajl_handle yajl_parser;
ParserContext yajl_parser_context;
yajl_gen yajl_generator;

static int stdin_start_map(void *context);
static int stdin_map_key(void *context, const unsigned char *key, size_t len);
static int stdin_string(void *context, const unsigned char *string, size_t len);
static int stdin_integer(void *context, long long number);
static int stdin_end_map(void *context);
static inline int round_float_to_int(float f);
static char *size_to_human_readable(double n);
static char *get_kernel_string(void);
static struct passwd *get_passwd(void);
static char *get_user(void);
static char *get_user_home(void);
static char *get_ram_usage(void);
static char *get_datetime(bool fuzzy);
static char *get_disk_free(const char *mount);
static char *get_uptime(void);
static struct mpd_connection *mpd_connect(const char *host, unsigned int port, unsigned int timeout);
static float mpd_get_progress(struct mpd_connection *connection);
static char *mpd_get_song(struct mpd_connection *connection, bool shorttext);
static char *get_mpd(struct mpd_connection *connection, bool shorttext);
static char *get_free_storage(void);
static void print_record(yajl_gen yajl, const char *name, const char *record, const char *shortrecord, const char *color, bool markup, bool separator);
static void print_setup(void);
static void print_status(void);
static void parse_click_event(const char *buffer, size_t length);
static void handle_click_event(ClickEvent event);
static inline int err(const char *errmsg);

static int
stdin_start_map(void *context)
{
	ParserContext *ctx = context;

	/* Reset the ClickEvent memory */
	memset(&(ctx->event), '\0', sizeof(ctx->event));

	return 1;
}

static int
stdin_map_key(void *context, const unsigned char *key, size_t len)
{
	ParserContext *ctx = context;
	char *map_key = (char *)key;

	if (strncmp(map_key, "name", len) == 0) {
		ctx->last_key = EVENT_NAME;
	}
	else if (strncmp(map_key, "instance", len) == 0) {
		ctx->last_key = EVENT_INSTANCE;
	}
	else if (strncmp(map_key, "x", len) == 0) {
		ctx->last_key = EVENT_X;
	}
	else if (strncmp(map_key, "y", len) == 0) {
		ctx->last_key = EVENT_Y;
	}
	else if (strncmp(map_key, "button", len) == 0) {
		ctx->last_key = EVENT_BUTTON;
	}

	return 1;
}

static int
stdin_string(void *context, const unsigned char *string, size_t len)
{
	ParserContext *ctx = context;
	char *str;

	if (!(str = malloc(len+1))) {
		return 0;
	}
	snprintf(str, len+1, "%s", string);

	if (ctx->last_key == EVENT_NAME) {
		ctx->event.name = str;
	}
	else if (ctx->last_key == EVENT_INSTANCE) {
		ctx->event.instance = str;
	}
	else {
		free(str);
	}

	return 1;
}

static int
stdin_integer(void *context, long long number)
{
	ParserContext *ctx = context;

	if (ctx->last_key == EVENT_X) {
		ctx->event.x = (uint32_t) number;
	}
	else if (ctx->last_key == EVENT_Y) {
		ctx->event.y = (uint32_t) number;
	}
	else if (ctx->last_key == EVENT_BUTTON) {
		ctx->event.button = (uint32_t) number;
	}

	return 1;
}

static int
stdin_end_map(void *context)
{
	ParserContext *ctx = context;

	handle_click_event(ctx->event);

	free(ctx->event.name);
	free(ctx->event.instance);

	return 1;
}

static inline int
round_float_to_int(float f)
{
	if (f >= 0.0f) f += 0.5f;

	return (int) f;
}

/* from sbase: http://tools.suckless.org/sbase */
static char *
size_to_human_readable(double n)
{
	char buf[16];
	const char postfixes[] = "BKMGTPE";
	size_t i;

	for (i = 0; n >= 1024 && i < strlen(postfixes); i++) {
		n /= 1024;
	}

	if (i == 0) {
		snprintf(buf, sizeof(buf), "%lu", (unsigned long) n);
	}
	else {
		snprintf(buf, sizeof(buf), "%.2f%c", n, postfixes[i]);
	}
	return strndup(buf, sizeof(buf)-1);
}

static char *
get_kernel_string(void)
{
	struct utsname u;

	if (uname(&u) < 0) {
		return NULL;
	}

	return strdup(u.release);
}

static struct passwd *
get_passwd(void)
{
	uid_t uid;

	uid = geteuid();
	return getpwuid(uid);
}

static char *
get_user(void)
{
	struct passwd *pw;

	if (!(pw = get_passwd())) {
		return NULL;
	}

	return strdup(pw->pw_name);
}

static char *
get_user_home(void)
{
	struct passwd *pw;

	if (!(pw = get_passwd())) {
		return NULL;
	}

	return strdup(pw->pw_dir);
}

static char *
get_ram_usage(void)
{
	unsigned long long reclaimable, total, free, buffers, cached, shmem;
	unsigned long long usage = 0;
	FILE *meminfo;
	char buf[256];

	meminfo = fopen("/proc/meminfo", "r");
	if (meminfo == NULL) {
		return NULL;
	}

	while (!feof(meminfo)) {
		if (fgets(buf, sizeof(buf), meminfo) == NULL) {
			break;
		}

		if (strncmp(buf, "SReclaimable:", 13) == 0) {
			sscanf(buf, "%*s %llu", &reclaimable);
		}
		else if (strncmp(buf, "MemTotal:", 9) == 0) {
			sscanf(buf, "%*s %llu", &total);
		}
		else if (strncmp(buf, "MemFree:", 8) == 0) {
			sscanf(buf, "%*s %llu", &free);
		}
		else if (strncmp(buf, "Buffers:", 8) == 0) {
			sscanf(buf, "%*s %llu", &buffers);
		}
		else if (strncmp(buf, "Cached:", 7) == 0) {
			sscanf(buf, "%*s %llu", &cached);
		}
		else if (strncmp(buf, "Shmem:", 6) == 0) {
			sscanf(buf, "%*s %llu", &shmem);
		}
	}

	usage = total - free - cached + shmem - buffers - reclaimable;
	/* Values in /proc/meminfo are in Kibibyte */
	usage *= 1024;

	fclose(meminfo);
	return size_to_human_readable(usage);
}

static char *
get_datetime(bool fuzzy)
{
	time_t t;
	struct tm *now;
	char datestring[32];
	char *secondarytimestring, *timestring;

	t = time(NULL);
	now = localtime(&t);
	if (!strftime(datestring, sizeof(datestring), "%d-%b", now)) {
		return NULL;
	}

	if (fuzzy) {
		if (!(secondarytimestring = fuzzytime(now))) {
			return NULL;
		}
	}
	else {
		if (!(secondarytimestring = calloc(sizeof(datestring), sizeof(*secondarytimestring)))) {
			return NULL;
		}
		if (!strftime(secondarytimestring, sizeof(datestring), "%H:%M", now)) {
			free(secondarytimestring);
			return NULL;
		}
	}


	size_t len = strnlen(datestring, sizeof(datestring)-1) + strlen(secondarytimestring) + strlen(" ") + 1;
	timestring = malloc(len);
	if(!timestring) {
		free(secondarytimestring);
		return NULL;
	}
	snprintf(timestring, len, "%s %s", datestring, secondarytimestring);

	return timestring;
}

static char *
get_disk_free(const char *mount)
{
	struct statvfs s;
	unsigned long free;

	if (statvfs(mount, &s) == -1) {
		return NULL;
	}

	/* f_bavail vs f_bfree */
	free = s.f_bavail * s.f_bsize;

	return size_to_human_readable(free);
}

static char *
get_uptime(void)
{
	struct sysinfo s;
	long uptime;
	unsigned long days = 0, hours = 0, minutes = 0;
	char *timestring;

	timestring = malloc(64);
	if (timestring == NULL) {
		return NULL;
	}

	if (sysinfo(&s) == -1) {
		return NULL;
	}

	uptime = s.uptime / 60;
	minutes = uptime % 60;
	uptime /= 60;
	hours = uptime % 24;
	days = uptime / 24;

	if (days) {
		snprintf(timestring, 64, "%lud %luh", days, hours);
	}
	else if (hours) {
		snprintf(timestring, 64, "%luh %lum", hours, minutes);
	}
	else {
		snprintf(timestring, 64, "%lum", minutes);
	}

	return timestring;
}

static struct mpd_connection *
mpd_connect(const char *host, unsigned int port, unsigned int timeout)
{
	struct mpd_connection *connection = mpd_connection_new(host, port, timeout);
	if (connection == NULL) {
		return NULL;
	}

	if (mpd_connection_get_error(connection) != MPD_ERROR_SUCCESS) {
		mpd_connection_free(connection);
		return NULL;
	}

	return connection;
}

static float
mpd_get_progress(struct mpd_connection *connection)
{
	struct mpd_status *status;
	unsigned int total;
	float progress;

	status = mpd_run_status(connection);
	if (status == NULL) {
		return -1.0f;
	}

	total = mpd_status_get_total_time(status);
	progress = (total == 0) ? 0.0f : (float) mpd_status_get_elapsed_time(status) / total;

	mpd_status_free(status);
	return progress;
}

static char *
mpd_get_song(struct mpd_connection *connection, bool shorttext)
{
	struct mpd_song *song;
	const char *artist, *title, *uri;
	char *songstring;

	song = mpd_run_current_song(connection);
	if (song == NULL) {
		return NULL;
	}

	artist = mpd_song_get_tag(song, MPD_TAG_ARTIST, 0);
	title = mpd_song_get_tag(song, MPD_TAG_TITLE, 0);
	uri = mpd_song_get_uri(song);

	if ((artist != NULL) && (title != NULL) && !shorttext) {
		/* +4 = sizeof(" - ") + \0 */
		songstring = malloc(strlen(artist) + strlen(title) + 4);
		if (songstring != NULL) {
			sprintf(songstring, "%s - %s", artist, title);
		}
	}
	else if (title != NULL) {
		songstring = strdup(title);
	}
	else if (artist != NULL) {
		songstring = strdup(artist);
	}
	else {
		songstring = strdup(uri);
	}

	mpd_song_free(song);
	return songstring;
}

static char *
get_mpd(struct mpd_connection *connection, bool shorttext)
{
	int progress;
	char *song = NULL;
	char *mpd = NULL;
	size_t mpd_size;

	progress = round_float_to_int(mpd_get_progress(connection) * 100.0f);
	if (progress < 0) {
		goto cleanup;
	}

	song = mpd_get_song(connection, shorttext);
	if (song == NULL) {
		goto cleanup;
	}

	/* 5 = " 100%" */
	mpd_size = strnlen(song, 255) + 5 + 1;
	mpd = malloc(mpd_size);
	if (mpd == NULL) {
		goto cleanup;
	}

	if (shorttext) {
		snprintf(mpd, mpd_size, "%s", song);
	}
	else {
		snprintf(mpd, mpd_size, "%s %d%%", song, progress);
	}

cleanup:
	free(song);
	return mpd;
}

static char *
get_free_storage(void)
{
	char *freestring = NULL;
	char *home_directory = NULL;
	char *home = NULL, *root = NULL;

	home_directory = get_user_home();
	if (!home_directory) {
		goto cleanup;
	}

	home = get_disk_free(home_directory);
	if (!home) {
		goto cleanup;
	}
	root = get_disk_free("/");
	if (!root) {
		goto cleanup;
	}

	freestring = malloc(64);
	if (freestring) {
		snprintf(freestring, 64, "~/:%s /:%s", home, root);
	}

cleanup:
	free(home_directory);
	free(home);
	free(root);
	return freestring;
}

static void
print_record(yajl_gen yajl, const char *name, const char *record, const char *shortrecord, const char *color, bool markup, bool separator)
{
	if (!record) return;

	yajl_gen_map_open(yajl);
	yajl_gen_string(yajl, CUC("name"), strlen("name"));
	yajl_gen_string(yajl, CUC(name), strlen(name));
	yajl_gen_string(yajl, CUC("full_text"), strlen("full_text"));
	yajl_gen_string(yajl, CUC(record), strlen(record));
	if (shortrecord) {
		yajl_gen_string(yajl, CUC("short_text"), strlen("short_text"));
		yajl_gen_string(yajl, CUC(shortrecord), strlen(shortrecord));
	}
	if (color) {
		yajl_gen_string(yajl, CUC("color"), strlen("color"));
		yajl_gen_string(yajl, CUC(color), strlen(color));
	}
	if (markup) {
		yajl_gen_string(yajl, CUC("markup"), strlen("markup"));
		yajl_gen_string(yajl, CUC("pango"), strlen("pango"));
	}
	yajl_gen_string(yajl, CUC("separator"), strlen("separator"));
	yajl_gen_bool(yajl, separator);
	yajl_gen_map_close(yajl);
}

static void
print_setup(void)
{
	printf("{\"version\":1,\"click_events\":true}\n");
	printf("[\n");

	fflush(stdout);

	yajl_gen_array_open(yajl_generator);
	yajl_gen_clear(yajl_generator);
}

static void
print_status(void)
{
	char *datetime, *datetime_fuzzy, *uptime, *ram, *storage, *mpd = NULL, *mpd_short = NULL;
	const unsigned char *yajl_output;
	size_t yajl_output_len;

	datetime_fuzzy = get_datetime(use_fuzzytime);
	datetime = get_datetime(false);
	uptime = get_uptime();
	ram = get_ram_usage();
	storage = get_free_storage();
	if (connection) {
		mpd = get_mpd(connection, false);
		mpd_short = get_mpd(connection, true);
	}

	yajl_gen_array_open(yajl_generator);
	if (mpd) {
		print_record(yajl_generator, "music", "<b>MPD</b>", NULL, "#b72f62", true,  false);
		print_record(yajl_generator, "music", mpd, mpd_short, NULL, false, true);
	}
	if (storage) {
		print_record(yajl_generator, "hd", "<b>HD</b>", NULL, "#7996a9", true, false);
		print_record(yajl_generator, "hd", storage, NULL, NULL, false, true);
	}
	if (ram) {
		print_record(yajl_generator, "ram", "<b>Ram</b>", NULL, "#7996a9", true, false);
		print_record(yajl_generator, "ram", ram, NULL, NULL, false, true);
	}
	if (uptime) {
		print_record(yajl_generator, "uptime", "<b>Up</b>", NULL, "#b492b6", true, false);
		print_record(yajl_generator, "uptime", uptime, NULL, NULL, false, true);
	}
	print_record(yajl_generator, "os", "<b>Arch</b>", NULL, "#b72f62", true, false);
	print_record(yajl_generator, "os", kernel, NULL, NULL, false, true);
	print_record(yajl_generator, "user", user, NULL, "#b492b6", false, true);
	if (datetime_fuzzy && datetime) {
		print_record(yajl_generator, "datetime", datetime_fuzzy, datetime, "#ffebeb", true, false);
	}
	yajl_gen_array_close(yajl_generator);

	yajl_gen_get_buf(yajl_generator, &yajl_output, &yajl_output_len);
	fwrite(yajl_output, 1, yajl_output_len, stdout);
	yajl_gen_clear(yajl_generator);

	putchar('\n');
	fflush(stdout);

	free(datetime);
	free(uptime);
	free(ram);
	free(storage);
	free(mpd);
	free(mpd_short);
}

static void
parse_click_event(const char *buffer, size_t length)
{
	yajl_status status = yajl_parse(yajl_parser, CUC(buffer), length);
}

static void
handle_click_event(ClickEvent event)
{
	use_fuzzytime = !use_fuzzytime;

	print_status();
}

static inline int
err(const char *errmsg)
{
	return fprintf(stderr, errmsg, progname, strerror(errno));
}

int
main(int argc, char *argv[])
{
	int ret = 0;
	int timer = -1;
	struct sigaction sa;

	progname = argv[0];

	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGPIPE, &sa, NULL) == -1) {
		err("%s: failed to install signal handler: %s\n");
		goto cleanup_fail;
	}

	timer = timerfd_create(CLOCK_MONOTONIC, 0);
	if (timer == -1) {
		err("%s: failed to create timerfd: %s\n");
		goto cleanup_fail;
	}
	if (timerfd_settime(timer, 0,
		        &((struct itimerspec) {
			        .it_interval = ((struct timespec) {.tv_sec = refresh}),
			        /* Workaround to have the timer immediately trigger on start */
			        .it_value = ((struct timespec) {.tv_nsec = 1})
		        }), NULL) == -1) {
		err("%s: failed to start timerfd: %s\n");
		goto cleanup_fail;
	}

	struct pollfd fds[] = {
		{ .fd = STDIN_FILENO, .events = POLLIN },
		{ .fd = timer, .events = POLLIN }
	};

	yajl_callbacks callbacks = {
		.yajl_integer = stdin_integer,
		.yajl_string = stdin_string,
		.yajl_start_map = stdin_start_map,
		.yajl_map_key = stdin_map_key,
		.yajl_end_map = stdin_end_map
	};

	yajl_parser = yajl_alloc(&callbacks, NULL, &yajl_parser_context);
	yajl_generator = yajl_gen_alloc(NULL);
	if (!yajl_generator || !yajl_parser) {
		err("%s: failed to allocate JSON parser: %s\n");
		goto cleanup_fail;
	}

	user = get_user();
	if (user == NULL) {
		err("%s: failed to get user information: %s\n");
		goto cleanup_fail;
	}
	kernel = get_kernel_string();
	if (kernel == NULL) {
		err("%s: failed to get kernel information: %s\n");
		goto cleanup_fail;
	}

	connection = mpd_connect(mpd_host, mpd_port, mpd_timeout);
	if (connection == NULL) {
		err("%s: failed to connect to mpd\n");
		goto cleanup_fail;
	}

	print_setup();
	for (;;) {
		if (poll(fds, 2, -1) == -1) {
			err("%s: failed waiting in poll(): %s\n");
			goto cleanup_fail;
		}

		/* timerfd fired */
		if (fds[1].revents & POLLIN) {
			uint64_t timerret;

			/* Discard timer data, compiler still complains :( */
			(void) read(fds[1].fd, &timerret, sizeof(timerret));

			print_status();

		}
		/* We got something on stdin */
		if (fds[0].revents & POLLIN) {
			ssize_t input_length;
			char input_event_buf[256];

			input_length = read(fds[0].fd, input_event_buf, sizeof(input_event_buf));
			if (input_length == -1) {
				err("%s: failed to read input event: %s");
				goto cleanup_fail;
			}
			parse_click_event(input_event_buf, input_length);
		}
	}

	goto cleanup;

cleanup_fail:
	ret = 1;
cleanup:
	close(timer);
	free(user);
	free(kernel);
	mpd_connection_free(connection);
	yajl_free(yajl_parser);
	yajl_gen_free(yajl_generator);

	return ret;
}
