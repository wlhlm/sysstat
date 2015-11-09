/* See LICENSE file for license details. */

#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/timerfd.h>

#include <mpd/client.h>
#include <yajl/yajl_gen.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <pwd.h>
#include <string.h>
#include <time.h>
#include <poll.h>

#include "fuzzyclock.h"

/* Refresh interval in seconds */
const unsigned int refresh = 5;

#define CUC(var) (const unsigned char *)var

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
		snprintf(buf, sizeof(buf), "%lu", (unsigned long)n);
	}
	else {
		snprintf(buf, sizeof(buf), "%.2f%c", n, postfixes[i]);
	}
	return strndup(buf, 16);
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

static char *
get_user(void)
{
	uid_t uid;
	struct passwd *pw;

	uid = geteuid();
	pw = getpwuid(uid);
	if (pw == NULL) {
		return NULL;
	}

	return strdup(pw->pw_name);
}

static char *
get_ram_usage(void)
{
	unsigned long long reclaimable, total, free, buffers, cached, shmem;
	unsigned long long usage;
	FILE *meminfo;
	char buf[256];

	meminfo = fopen("/proc/meminfo", "r");
	if (meminfo == NULL) {
		return NULL;
	}

	while (!feof(meminfo)) {
		if (fgets(buf, 255, meminfo) == NULL) {
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
get_datetime(void)
{
	time_t t;
	struct tm *now;
	char datestring[32];
	char *fuzzytimestring, *timestring;

	t = time(NULL);
	now = localtime(&t);
	if (strftime(datestring, 32, "%d-%b", now) == 0) {
		return NULL;
	}
	if (!(fuzzytimestring = fuzzytime(now))) {
		return NULL;
	}

	size_t len = strlen(datestring) + strlen(fuzzytimestring) + strlen(" ") + 1;
	timestring = malloc(len);
	if(!timestring) {
		free(fuzzytimestring);
		return NULL;
	}
	snprintf(timestring, len, "%s %s", datestring, fuzzytimestring);

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
	unsigned long days, hours, minutes;
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
mpd_connect(void)
{
	struct mpd_connection *connection = mpd_connection_new("/home/helm/Music/.mpd/socket", 0, 0);
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
	char *song;
	char *mpd;
	size_t mpd_size;

	progress = round_float_to_int(mpd_get_progress(connection) * 100.0f);
	if (progress < 0) {
		return NULL;
	}

	song = mpd_get_song(connection, shorttext);
	if (song == NULL) {
		return NULL;
	}

	mpd_size = strlen(song) + 5 + 1;
	mpd = malloc(mpd_size);
	if (mpd == NULL) {
		return NULL;
	}

	if (shorttext) {
		snprintf(mpd, mpd_size, "%s", song);
	}
	else {
		snprintf(mpd, mpd_size, "%s %d%%", song, progress);
	}

	free(song);
	return mpd;
}

static char *get_free_storage(void)
{
	char *freestring;
	char *home, *root;

	home = get_disk_free("/home/helm");
	if (home == NULL) {
		return NULL;
	}
	root = get_disk_free("/");
	if (root == NULL) {
		return NULL;
	}

	freestring = malloc(64);
	if (freestring != NULL) {
		snprintf(freestring, 64, "~/:%s /:%s", home, root);
	}

	free(home);
	free(root);
	return freestring;
}

static void
print_record(yajl_gen yajl, const char *name, const char *record, const char *shortrecord, const char *color, bool separator)
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
	if (color != NULL) {
		yajl_gen_string(yajl, CUC("color"), strlen("color"));
		yajl_gen_string(yajl, CUC(color), strlen(color));
	}
	yajl_gen_string(yajl, CUC("separator"), strlen("separator"));
	yajl_gen_bool(yajl, separator);
	yajl_gen_map_close(yajl);
}

static yajl_gen
print_setup(void)
{
	yajl_gen yajl;

	yajl = yajl_gen_alloc(NULL);

	printf("{\"version\":1}\n");
	printf("[\n");

	fflush(stdout);

	yajl_gen_array_open(yajl);
	yajl_gen_clear(yajl);

	return yajl;
}

int
main(void)
{
	char *kernel = NULL, *user = NULL, *datetime, *uptime, *ram, *storage, *mpd = NULL, *mpd_short = NULL;
	struct mpd_connection *connection;
	yajl_gen yajl;
	const unsigned char *yajl_output;
	size_t yajl_output_len;

	int timer = timerfd_create(CLOCK_MONOTONIC, 0);
	uint64_t timerret;
	if (timer == -1) {
		goto cleanup;
	}
	if (timerfd_settime(timer, 0, &((struct itimerspec) {
	                    .it_interval = ((struct timespec) {.tv_sec = refresh}),
	                    /* Workaround to have the timer immediately trigger on start */
	                    .it_value = ((struct timespec) {.tv_nsec = 1})
	                    }), NULL) == -1) {
		goto cleanup;
	}

	struct pollfd fds[] = {
		{ .fd = timer, .events = POLLIN }
	};

	user = get_user();
	if (user == NULL) {
		goto cleanup;
	}
	kernel = get_kernel_string();
	if (kernel == NULL) {
		goto cleanup;
	}

	yajl = print_setup();
	if (yajl == NULL) {
		goto cleanup;
	}
	connection = mpd_connect();

	for (;;) {
		poll(fds, 1, -1);
		if (fds[0].revents & POLLIN) {
			/* Discard timer data */
			(void)read(fds[0].fd, &timerret, sizeof(timerret));

			datetime = get_datetime();
			uptime = get_uptime();
			ram = get_ram_usage();
			storage = get_free_storage();
			if (connection) {
				mpd = get_mpd(connection, false);
				mpd_short = get_mpd(connection, true);
			}

			yajl_gen_array_open(yajl);
			if (mpd) {
				print_record(yajl, "mpd", "MPD", NULL, "#b72f62", true);
				print_record(yajl, "mpd", mpd, mpd_short, NULL, true);
			}
			print_record(yajl, "hd", "HD", NULL, "#7996a9", false);
			print_record(yajl, "hd", storage, NULL, NULL, true);
			print_record(yajl, "ram", "Ram", NULL, "#7996a9", false);
			print_record(yajl, "ram", ram, NULL, NULL, true);
			print_record(yajl, "uptime", "Up", NULL, "#b492b6", false);
			print_record(yajl, "uptime", uptime, NULL, NULL, true);
			print_record(yajl, "os", "Arch", NULL, "#b72f62", false);
			print_record(yajl, "os", kernel, NULL, false, true);
			print_record(yajl, "user", user, NULL, "#b492b6", true);
			print_record(yajl, "datetime", datetime, NULL, "#ffebeb", false);
			yajl_gen_array_close(yajl);

			yajl_gen_get_buf(yajl, &yajl_output, &yajl_output_len);
			fwrite(yajl_output, 1, yajl_output_len, stdout);
			yajl_gen_clear(yajl);

			printf("\n");
			fflush(stdout);

			free(datetime);
			free(uptime);
			free(ram);
			free(storage);
			if (connection) {
				free(mpd);
				free(mpd_short);
			}
		}
	}

	mpd_connection_free(connection);

cleanup:
	free(user);
	free(kernel);

	return 0;
}
