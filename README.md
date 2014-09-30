deshellshock
============

deshellshock is a cross-distro script to determine the vulnerability of a bash binary to the shellshock exploits (CVE-2014-6271, CVE-2014-7169, CVE-2014-6277, CVE-2014-6278, CVE-2014-7186, CVE-2014-7187) and then patch that where possible.

deshellshock works on a number of different distros.  Including some that no longer have official support.  It uses apt, yum, rpm downloads, repository corrections and source builds as appropriate.

  Attempts to improve the situation if it is.  
  - Debian 7 => apt-get install
  - Debian 6 => fix up apt repositories for squeeze-lts and then apt-get install
  - Supported Ubuntus (12.04 LTS, 14.04 LTS, 14.10) => apt-get install
  - Certain unsupported Ubuntu (11.10, 13.04) => install from an ubuntu package and apt-mark hold bash
  - Unsupported Ubuntus (others per EOL_UBUNTU_DISTROS variable) => convert to old-releases.ubuntu.com and build from source
  - Debian 5 (and older Debians) => build from source and apt-mark hold bash
  - RHEL4 => try and get yum + centos vault working, install a downloaded RPM, else compile a patched RPM.
  - WBEL3, RH9 => install a downloaded RPM, else compile a patched RPM.

  Use with --source if you just wish to have the functions available to you for testing
  
  Run with --check if you just wish to check, but not change your server
  
  Run with --usage to get this message
  
  Run without an argument to try and fix your server

todo
====

This is an initial release.  Needs testing on different distros.  Use at your own risk.  Please contribute back patches for errors and additional distros.

CVE-2014-7186, CVE-2014-7187 are currently undisclosed.  So there are no fixes at the time of writing.  Keeping an eye on http://ftp.gnu.org/gnu/bash/bash-3.2-patches/ for something later than 54 and on https://security-tracker.debian.org/tracker/source-package/bash to not list CVE-2014 open issues.
