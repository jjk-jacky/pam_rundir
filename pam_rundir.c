/*
 * pam_rundir - Copyright (C) 2015 Olivier Brunel
 *
 * pam_rundir.c
 * Copyright (C) 2015 Olivier Brunel <jjk@jjacky.com>
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see http://www.gnu.org/licenses/
 */

#include "config.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/prctl.h>
#include <linux/securebits.h>
#include <string.h>
#include <pwd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>

#define PAM_SM_SESSION
#include <security/pam_modules.h>
#include <security/pam_appl.h>

#define FLAG_NAME           "pam_rundir_has_counted"

static int
ensure_parent_dir (void)
{
    int r = 1;
    mode_t um = umask (S_IWOTH);

    if (mkdir (PARENT_DIR, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) != 0
            && errno != EEXIST)
        r = 0;
    umask (um);
    return r;
}

static int
intlen (int n)
{
    int l;

    for (l = 1; ; ++l)
    {
        if (n < 10)
            break;
        n /= 10;
    }

    return l;
}

static void
print_int (char *s, int n, int l)
{
    s += l;
    for (;;)
    {
        const char digits[] = "0123456789";

        *--s = digits[n % 10];
        if (n < 10)
            break;
        n /= 10;
    }
}

static int
open_and_lock (const char *file)
{
    int fd;

    do { fd = open (file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR); }
    while (fd < 0 && errno == EINTR);
    if (fd < 0)
        return fd;

    if (flock (fd, LOCK_EX) < 0)
    {
        close (fd);
        return -1;
    }

    return fd;
}

static inline void
print_filename (char *s, int uid, int l)
{
    /* construct file name, e.g: "/run/user/.1000" */
    memcpy (s, PARENT_DIR, sizeof (PARENT_DIR) - 1);
    s[sizeof (PARENT_DIR) - 1] = '/';
    s[sizeof (PARENT_DIR)] = '.';
    print_int (s + sizeof (PARENT_DIR) + 1, uid, l);
    s[sizeof (PARENT_DIR) + 1 + l] = '\0';

}

static int
read_counter (int fd)
{
    int count = 0;

    /* read counter in file, as ascii string */
    for (;;)
    {
        char buf[4];
        int p;
        int r;

        r = read (fd, buf, sizeof (buf));
        if (r == 0)
            break;
        else if (r < 0)
        {
            if (errno == EINTR)
                continue;
            else
                return -1;
        }
        else if (count == 0 && r == 1 && buf[0] == '-')
            /* special case: dir not usable, but not a failure */
            return -2;

        for (p = 0; r > 0; --r, ++p)
        {
            if (buf[p] < '0' || buf[p] > '9')
                return -1;
            count *= 10;
            count += buf[p] - '0';
        }
    }
    return count;
}

/* basically, this is called when we tried to update the counter but failed,
 * leaving the file in an invalid state (i.e. only partial write, or no
 * truncate).
 * So here, we try to make the file "properly invalid" so any further attempt to
 * read it will lead to a no-op (because of invalid data). Obviously though, if
 * we fail to e.g. seek or write, we can't do anything else...
 * (Anyhow, this will likely never be called.)
 */
static void
emergency_invalidate_counter (int fd)
{
    int r;

    if (lseek (fd, 0, SEEK_SET) < 0)
        return;

    do { r = write (fd, "-", 1); }
    while (r < 0 && errno == EINTR);

    if (r == 1)
        do { r = ftruncate (fd, 1); }
        while (r < 0 && errno == EINTR);
}

static int
write_counter (int fd, int count)
{
    int r;
    int l;

    r = lseek (fd, 0, SEEK_SET);
    if (r < 0)
        return r;

    l = (count >= 0) ? intlen (count) : 1;
    {
        char buf[l];

        if (count >= 0)
            print_int (buf, count, l);
        else
            buf[0] = '-';

        for (;;)
        {
            int w = 0;

            r = write (fd, buf + w, l - w);
            if (r < 0)
            {
                if (errno = EINTR)
                    continue;
                if (w > 0)
                    emergency_invalidate_counter (fd);
                return -1;
            }

            w += r;
            if (w == l)
                break;
        }

        do { r = ftruncate (fd, l); }
        while (r < 0 && errno == EINTR);
        if (r < 0)
            emergency_invalidate_counter (fd);
    }
    return r;
}

static int
rmrf (const char *path)
{
    int r = 0;
    DIR *dir;
    struct dirent *dp;
    int lp;

    if (unlink (path) == 0)
        return 0;
    else if (errno != EISDIR)
        return -1;

    dir = opendir (path);
    if (!dir)
        return -1;
    lp = strlen (path);
    for (dp = readdir (dir); dp != NULL; dp = readdir (dir))
    {
        if (strcmp (dp->d_name, ".") != 0 && strcmp (dp->d_name, "..") != 0)
        {
            int l = lp + strlen (dp->d_name) + 2;
            char name[l];

            memcpy (name, path, lp);
            name[lp] = '/';
            memcpy (name + lp + 1, dp->d_name, l - lp - 1);

            r += rmrf (name);
        }
    }
    closedir (dir);
    if (rmdir (path) < 0)
        --r;

    return r;
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int r;
    const char *user;
    struct passwd *pw;
    int l;

    /* did we add to the counter on open_session (i.e. anything to do) ? */
    r = pam_get_data (pamh, FLAG_NAME, (const void **) &pw);
    if (r != PAM_SUCCESS)
        return (r == PAM_NO_MODULE_DATA) ? PAM_SUCCESS : r;

    if (geteuid() != 0)
        return PAM_SESSION_ERR;

    if (!ensure_parent_dir ())
        return PAM_SESSION_ERR;

    r = pam_get_user (pamh, &user, NULL);
    if (r != PAM_SUCCESS)
        return PAM_USER_UNKNOWN;

    pw = getpwnam (user);
    if (!pw)
        return PAM_USER_UNKNOWN;

    /* get length for uid as ascii string, i.e. in file/folder name */
    l = intlen ((int) pw->pw_uid);

    {
        char file[sizeof (PARENT_DIR) + l + 2];
        int fd;
        int count = 0;

        print_filename (file, (int) pw->pw_uid, l);
        fd = open_and_lock (file);
        if (fd < 0)
            return PAM_SESSION_ERR;

        count = read_counter (fd);
        if (count < 0)
        {
            /* -2: dir not usable, but not a failure */
            r = (count == -2) ? 0 : -1;
            goto done;
        }

        /* make sure we don't go below zero, just in case */
        if (count > 0)
            --count;

        if (count == 0)
        {
            /* construct runtime dir name, i.e. remove the dot before uid */
            memmove (file + sizeof (PARENT_DIR), file + sizeof (PARENT_DIR) + 1, l + 1);

            r = rmrf (file);
            if (r < 0)
                count = -1;
        }

        r = write_counter (fd, count);
        if (r < 0)
            goto done;

        if (count == -1)
            r = -1;

done:
        close (fd); /* also unlocks */
    }

    return (r == 0) ? PAM_SUCCESS : PAM_SESSION_ERR;
}

PAM_EXTERN int
pam_sm_open_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int r;
    const char *user;
    struct passwd *pw;
    int l;

    if (geteuid() != 0)
        return PAM_SESSION_ERR;

    if (!ensure_parent_dir ())
        return PAM_SESSION_ERR;

    r = pam_get_user (pamh, &user, NULL);
    if (r != PAM_SUCCESS)
        return PAM_USER_UNKNOWN;

    pw = getpwnam (user);
    if (!pw)
        return PAM_USER_UNKNOWN;

    /* get length for uid as ascii string, i.e. in file/folder name */
    l = intlen ((int) pw->pw_uid);

    {
        char file[sizeof (PARENT_DIR) + l + 2];
        int fd;
        int count = 0;
        int secbits = -1;

        print_filename (file, (int) pw->pw_uid, l);
        fd = open_and_lock (file);
        if (fd < 0)
            return PAM_SESSION_ERR;

        count = read_counter (fd);
        if (count < 0)
        {
            /* -2: dir not usable, but not a failure */
            r = (count == -2) ? 0 : -1;
            goto done;
        }

        /* construct runtime dir name, i.e. remove the dot before uid */
        memmove (file + sizeof (PARENT_DIR), file + sizeof (PARENT_DIR) + 1, l + 1);

        /* update counter now, so we don't have to undo folder creation if
         * updating the counter fails, etc. Having a count with a failure to
         * create the folder isn't that big a deal (plus rare enough) to be
         * worthy of complicating things. */
        r = write_counter (fd, ++count);
        if (r < 0)
            goto done;

        /* flag for processing on close_session */
        if (pam_set_data (pamh, FLAG_NAME, (void *) 1, NULL) != PAM_SUCCESS)
        {
            /* well shit... try to revert, though we can't do nothing if it
             * fails. A PAM_BUF_ERR (only possible error) should be pretty rare
             * though (especially combined with a failure to re-write). */
            write_counter (fd, --count);
            r = -1;
            goto done;
        }

        /* to bypass permission checks for mkdir, in case it isn't group
         * writable */
        secbits = prctl (PR_GET_SECUREBITS);
        if (secbits != -1)
            prctl (PR_SET_SECUREBITS, (unsigned long) secbits | SECBIT_NO_SETUID_FIXUP);
        /* set euid and egid so if we do create the dir, it is owned by the user */
        if (seteuid (pw->pw_uid) < 0 || setegid (pw->pw_gid) < 0)
        {
            r = -1;
            goto done;
        }
        if (mkdir (file, S_IRWXU) == 0 || errno == EEXIST)
        {
            l = strlen (file);
            char buf[sizeof (VAR_NAME) + 1 + l];

            memcpy (buf, VAR_NAME, sizeof (VAR_NAME) - 1);
            buf[sizeof (VAR_NAME) - 1] = '=';
            memcpy (buf + sizeof (VAR_NAME), file, l + 1);

            pam_putenv (pamh, buf);
        }
        /* restore */
        if (seteuid (0) < 0 || setegid (0) < 0)
        {
            r = -1;
            goto done;
        }

done:
        if (secbits != -1)
            prctl (PR_SET_SECUREBITS, (unsigned long) secbits);
        close (fd); /* also unlocks */
    }

    return (r == 0) ? PAM_SUCCESS : PAM_SESSION_ERR;
}

#ifdef PAM_STATIC
struct pam_module _pam_rundir_modstruct = {
     "pam_rundir",
     NULL,
     NULL,
     NULL,
     pam_sm_open_session,
     pam_sm_close_session,
     NULL
};
#endif
