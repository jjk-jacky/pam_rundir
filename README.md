
# pam_rundir: Provide user runtime directory

pam_rundir is a PAM module that can be used to provide user runtime
directory, as described in the XDG Base Directory Specification.

The directory will be created on login (open session) and removed on logout
(close session), and its full path made available in an environment variable,
usually `$XDG_RUNTIME_DIR`.

## Free Software

pam_rundir - Copyright (C) 2015 Olivier Brunel <jjk@jjacky.com>

pam_rundir is free software: you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation, either version 2 of the License, or (at your option) any later
version.

pam_rundir is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
pam_rundir (COPYING). If not, see http://www.gnu.org/licenses/

## Want to know more?

Some useful links if you're looking for more info:

- [official site](http://jjacky.com/pam_rundir "pam_rundir @ jjacky.com")

- [source code & issue tracker](https://github.com/jjk-jacky/pam_rundir "pam_rundir @ GitHub.com")

Plus, pam_rundir comes with man pages.
