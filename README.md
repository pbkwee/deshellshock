deshellshock
============

Bash script to detect if a server is hosting a vulnerable bash, and to patch it if it is.

Checks to see if a server has a 'shellshocked' bash (vulnerable to CVE_2014_6271 or CVE_2014_7169)

The goal is for the script to be run across as many different environments as possible.  So that one solution can be used for detecting and handling multiple different distros.

  Attempts to improve the situation if it is.  
    - Debian 7 => apt-get install
  - Debian 6 => fix up apt repositories for squeeze-lts and then apt-get install
  - Supported Ubuntus (12.04 LTS, 14.04 LTS, 14.10) => apt-get install
  - Unsupported Ubuntu (11.10, 13.04) => install from an ubuntu package and apt-mark hold bash
  - Unsupported Ubuntus (others: breezy dapper edgy feisty gutsy hardy hoary intrepid jaunty karmic maverick natty oneiric quantal raring warty) => convert to old-releases.ubuntu.com and build from source
  - Debian 5 (and potentially other Debians) => build from source
  - RHEL4, RHEL3 => unsupported for now

  Use with --source if you just wish to have the functions available to you for testing
  
  Run with --check if you just wish to check, but not change your server
  
  Run with --usage to get this message
  
  Run without an argument to try and fix your server

todo
====

This is an initial release.  Needs testing on different distros.  Use at your own risk.  Please contribute back patches for errors and additional distros.
