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
#include <sys/stat.h>
#include <sys/prctl.h>
#include <linux/securebits.h>
#include <string.h>
#include <pwd.h>
#include <errno.h>
#include <dirent.h>
#include <utmp.h>
#include <stdlib.h>

#define PAM_SM_SESSION
#include <security/pam_modules.h>

#define FLAG_NAME           "pam_rundir_has_counted"

static int
array_pos (char *id, char *ttys_ids[], int len)
{
    for (int i = 0; i < len; ++i)
    {
        if (strcmp (ttys_ids[i], "") == 0)
        {
            ttys_ids[i] = strdup(id);
            return i;
        }
        if (strcmp (ttys_ids[i], id) == 0)
            return i;
    }
    return -1;
}

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
get_number_of_ttys (void)
{
    DIR *dir;
    struct dirent *ent;
    int count = 0;
    if ((dir = opendir ("/dev")) != NULL)
    {
        while ((ent = readdir (dir)) != NULL)
        {
            if (strncmp ("tty", ent->d_name, 3) == 0)
                ++count;
        }
    }
    return count;
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

static inline void
print_filename (char *s, int uid, int l)
{
    /* construct file name, e.g: "/run/users/.1000" */
    memcpy (s, PARENT_DIR, sizeof (PARENT_DIR) - 1);
    s[sizeof (PARENT_DIR) - 1] = '/';
    s[sizeof (PARENT_DIR)] = '.';
    print_int (s + sizeof (PARENT_DIR) + 1, uid, l);
    s[sizeof (PARENT_DIR) + 1 + l] = '\0';

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

static int
user_has_session (const char *user)
{
    int ttys = get_number_of_ttys ();
    char *ttys_ids[ttys];
    int ttys_login[ttys];

    for (int i = 0; i < ttys; ++i) {
        ttys_ids[i] = "";
        ttys_login[i] = 0;
    }

    /* Loop through all the utmp entries.
     * Store the id in the char array.
     * Update the login state at every iteration. */

    setutent();
    struct utmp *utmp_entry = getutent();
    while (utmp_entry)
    {
        if (utmp_entry->ut_type == LOGIN_PROCESS)
        {
            // This is a logout. The user is unknown.
            int pos = array_pos (utmp_entry->ut_id, ttys_ids, ttys);
            ttys_login[pos] = 0;
        } else if (utmp_entry->ut_type == USER_PROCESS)
        {
            // This is a login.
            if (strcmp (utmp_entry->ut_user, user) == 0)
            {
                int pos = array_pos (utmp_entry->ut_id, ttys_ids, ttys);
                ttys_login[pos] = 1;
            }
        }
        utmp_entry = getutent();
    }

    for (int i = 0; i < ttys; ++i)
    {
        if (strcmp (ttys_ids[i], ""))
            free(ttys_ids[i]);
    }

    int logins = 0;
    for (int i = 0; i < ttys; ++i)
    {
        if (ttys_login[i] == 1)
            ++logins;
    }

    /* If there is only one login, then we know the user has
     * logged out. If somehow it is under 1, just assume the
     * user has no sessions. */
    if (logins <= 1)
    {
        return 0;
    } else {
        return 1;
    }
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

    char file[sizeof (PARENT_DIR) + l + 2];
    print_filename (file, (int) pw->pw_uid, l);

    if (!user_has_session (user))
    {
        /* construct runtime dir name, i.e. remove the dot before uid */
        memmove (file + sizeof (PARENT_DIR), file + sizeof (PARENT_DIR) + 1, l + 1);

        r = rmrf (file);
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
        int secbits = -1;

        print_filename (file, (int) pw->pw_uid, l);

        /* construct runtime dir name, i.e. remove the dot before uid */
        memmove (file + sizeof (PARENT_DIR), file + sizeof (PARENT_DIR) + 1, l + 1);

        /* flag for processing on close_session */
        if (pam_set_data (pamh, FLAG_NAME, (void *) 1, NULL) != PAM_SUCCESS)
        {
            /* well shit... try to revert, though we can't do nothing if it
             * fails. A PAM_BUF_ERR (only possible error) should be pretty rare
             * though (especially combined with a failure to re-write). */
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
            goto done;
        }

done:
        if (secbits != -1)
            prctl (PR_SET_SECUREBITS, (unsigned long) secbits);
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
