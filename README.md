deshellshock
============

deshellshock is a cross-distro script to determine the vulnerability of a bash binary to the shellshock exploits (CVE-2014-6271 or CVE-2014-7169) and then patch that where possible.

deshellshock works on a number of different distros.  Including some that no longer have official support.  It uses apt, yum, rpm downloads, repository corrections and source builds as appropriate.

  Attempts to improve the situation if it is.  
  - Debian 7 => apt-get install
  - Debian 6 => fix up apt repositories for squeeze-lts and then apt-get install
  - Supported Ubuntus (12.04 LTS, 14.04 LTS, 14.10) => apt-get install
  - Unsupported Ubuntu (11.10, 13.04) => install from an ubuntu package and apt-mark hold bash
  - Unsupported Ubuntus (others per EOL_UBUNTU_DISTROS variable) => convert to old-releases.ubuntu.com and build from source
  - Debian 5 (and potentially other Debians) => build from source
  - RHEL4 => try and get yum + centos vault working, compile a patched RPM, else download and install a pre-compiled one.
  - RHEL3, RH9 => unsupported for now

  Use with --source if you just wish to have the functions available to you for testing
  
  Run with --check if you just wish to check, but not change your server
  
  Run with --usage to get this message
  
  Run without an argument to try and fix your server

todo
====

This is an initial release.  Needs testing on different distros.  Use at your own risk.  Please contribute back patches for errors and additional distros.
