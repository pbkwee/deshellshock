#!/bin/bash
grep root /etc/passwd | grep tcsh &&  echo "dss:error: deshellshock.sh needs to be run as a script, rather than a set of commands on a tsch shell." && exit 1
export DEBIAN_FRONTEND=noninteractive
# https://wiki.ubuntu.com/Releases
# lucid server still current?
EOL_UBUNTU_DISTROS="breezy dapper edgy feisty gutsy hardy hoary intrepid jaunty karmic maverick natty oneiric quantal raring warty" 
SUPPORTED_UBUNTU_DISTROS="lynx pangolin tahr unicorn"
function print_usage() {
  echo "deshellshock is a cross-distro script to determine the vulnerability of a bash binary to the shellshock exploits (CVE-2014-6271, CVE-2014-7169, CVE-2014-6277, CVE-2014-6278, CVE-2014-7186, CVE-2014-7187) and then patch that where possible.

deshellshock works on a number of different distros. Including some that no longer have official support. It uses apt, yum, rpm downloads, repository corrections and source builds as appropriate.

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
  
  Written by Peter Bryant at http://lauchtimevps.com
  
  Latest version (or thereabouts) available at https://github.com/pbkwee/deshellshock
  "
}

function print_CVE_2014_7169_vulnerable() {
# http://en.wikipedia.org/wiki/Shellshock_%28software_bug%29#Testing_2
if [ -f echo ] ; then echo "dss:warn: Remove the echo file first"; return 2; fi
X='() { (a)=>\' bash -c "echo date" >/dev/null 2>&1
if [ -f echo ]; then rm -f echo; echo "Y"; return 0; fi
echo "N"
return 1
}

function print_CVE_2014_6271_vulnerable() {
if env x='() { :;}; echo vulnerable' bash -c "echo foo" 2>&1 | grep -qai vulnerable; then echo "Y"; return 0; fi
echo "N"
return 1
}

function print_CVE_2014_6277_6278_vulnerable() {
if env ls='() { echo vulnerable; }' bash -c ls 2>&1 | grep -qai vulnerable; then echo "Y"; return 0; fi
echo "N"
return 1
}

function is_CVE_2014_6277_6278_vulnerable() {
  print_CVE_2014_6277_6278_vulnerable >/dev/null
  return $? 
}


function is_CVE_2014_6271_vulnerable() {
  print_CVE_2014_6271_vulnerable > /dev/null
  return $?
}

function is_CVE_2014_7169_vulnerable() {
  print_CVE_2014_7169_vulnerable > /dev/null
  return $?
}

function is_vulnerable() {
	is_CVE_2014_6271_vulnerable && return 0
	is_CVE_2014_7169_vulnerable && return 0
	is_CVE_2014_7186_vulnerable && return 0
	is_CVE_2014_7187_vulnerable && return 0
	is_CVE_2014_6277_6278_vulnerable && return 0
	return 1 
}

function is_CVE_2014_7186_vulnerable() {
  print_CVE_2014_7186_vulnerable > /dev/null
  return $?
}

function print_CVE_2014_7186_vulnerable() {
  # http://en.wikipedia.org/wiki/Shellshock_%28software_bug%29#CVE-2014-7186
  if bash -c 'true <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF' > /dev/null 2>&1 ; then echo "N"; return 1; fi
  echo "Y" && return 0
} 
function is_CVE_2014_7187_vulnerable() {
  print_CVE_2014_7187_vulnerable > /dev/null
  return $?
}

function print_CVE_2014_7187_vulnerable() {
  # http://en.wikipedia.org/wiki/Shellshock_%28software_bug%29#CVE-2014-7187
  if (for ((x=1;x<201;x++)) ; do echo "for x$x in ; do :"; done; for ((x=1;x<201;x++)) ; do echo done ; done) | bash > /dev/null 2>&1 ; then echo "N"; return 1; fi
  echo "Y"
  return 0
} 

# use print_vulnerability_status beforefix and print_vulnerability_status afterfix
function print_vulnerability_status() {
local prefix=${1:-prefix}
echo "dss:isvulnerable:$prefix: CVE_2014_6271$(print_CVE_2014_6271_vulnerable)"
echo "dss:isvulnerable:$prefix: CVE_2014_7169$(print_CVE_2014_7169_vulnerable)"
echo "dss:isvulnerable:$prefix: CVE_2014_7186$(print_CVE_2014_7186_vulnerable)"
echo "dss:isvulnerable:$prefix: CVE_2014_7187$(print_CVE_2014_7187_vulnerable)"
echo "dss:isvulnerable:$prefix: CVE_2014_6277_6278$(print_CVE_2014_6277_6278_vulnerable)"
}

function prep_shellshock_output_dir() {
if [ ! -d /root/deshellshockinfo ] ; then echo "dss:info: Creating /root/deshellshockinfo and cd-ing there."; mkdir /root/deshellshockinfo; fi
[ -d /root/deshellshockinfo ] && cd /root/deshellshockinfo
if [ ! -e /root/deshellshockinfo/bash.orig ]; then 
  echo "dss:info: Running cp /bin/bash /root/deshellshockinfo/bash.orig"
  if ! cp /bin/bash /root/deshellshockinfo/bash.orig; then 
    echo "dss:error: Failed making a copy of the original bash binary.  Is there a disk error, out of disk space?"
    return 1
  fi
fi
return 0
}

function print_info() {
echo "dss:hostname: $(hostname)"
echo "dss:date: $(date -u)"
echo "Testing for CVE_2014_6271 (error messages occurring here can be expected):"
env x='() { :;}; echo vulnerable' bash -c "echo" 2>&1
local val1=$(print_CVE_2014_6271_vulnerable)
local ret1=$?
echo "dss:CVE_2014_6271 result isvulnerable $val1 $ret1"
echo "Testing for CVE-2014_7169 (error messages occurring here can be expected):"
if [ -f echo ] ; then 
  echo "dss:warn: Cannot test.  There is an echo file already."; 
  val2="NA"
  ret2=-1
else 
  X='() { (a)=>\' bash -c "echo date" 2>&1
  rm -f echo
  local val2=$(print_CVE_2014_7169_vulnerable)
  local ret2=$?
fi

echo "dss:CVE-2014_7169 result isvulnerable $val2 $ret2"
echo "Testing for CVE_2014_6277_6278 (error messages occurring here can be expected):"
env ls='() { echo vulnerable; }' bash -c ls
local val3=$(print_CVE_2014_6277_6278_vulnerable)
local ret3=$?
echo "dss:CVE-2014_6277_6278 result isvulnerable $val3 $ret3"

echo "Testing for CVE_2014_7186:"
bash -c 'true <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF' ||
echo "CVE-2014-7186 vulnerable, redir_stack"
local val4=$(print_CVE_2014_7186_vulnerable)
local ret4=$?
echo "dss:CVE_2014_7186 result isvulnerable $val4 $ret4"

echo "Testing for CVE_2014_7187:"
(for ((x=1;x<201;x++)) ; do echo "for x$x in ; do :"; done; for ((x=1;x<201;x++)) ; do echo done ; done) | bash ||
echo "CVE-2014-7187 vulnerable, word_lineno"
local val5=$(print_CVE_2014_7187_vulnerable)
local ret5=$?
echo "dss:CVE_2014_7187 result isvulnerable $val5 $ret5"

echo "dss:info: Bash version: $(bash --version 2>&1| grep version | grep -v gpl)"
echo "dss:info: Bash ls: $(ls -l $(which bash))"
echo "dss:Redhat-release: $([ ! -f /etc/redhat-release ] && echo 'NA'; [ -f /etc/redhat-release ] && cat /etc/redhat-release)"
echo "dss:Debian-version: $([ ! -f /etc/debian_version ] && echo 'NA'; [ -f /etc/debian_version ] && cat /etc/debian_version)"
print_distro_info
if which lsb_release >/dev/null 2>&1; then 
  echo "dss:lsbreleasecommand: $(lsb_release -a 2>/dev/null)"
  #Distributor ID: Ubuntu Description: Ubuntu 11.10 Release: 11.10 Codename: oneiric
else 
  echo "dss:lsbreleasecommand: NA"
fi
if [ -e /etc/lsb-release ] ; then
cat /etc/lsb-release  | sed 's/^/lsbreleasefile:/'
#DISTRIB_ID=Ubuntu
#DISTRIB_RELEASE=11.10
#DISTRIB_CODENAME=oneiric
#DISTRIB_DESCRIPTION="Ubuntu 11.10"
fi
echo "Checking DNS works:"
if ! host google.com | grep -qai 'has address' ; then
  echo "dss:info: DNS not working trying to fix..."
  wget -q -O fixdns http://72.249.185.185/fixdns 
  bash fixdns --check --removebad
  if ! host google.com | grep -qai 'has address' ; then
    echo "dss:info: DNS not working after fix attempt, check your /etc/resolv.conf and set, say, nameserver 8.8.8.8"
  fi
fi
return 0
}


function convert_deb_6_stable_repo_to_squeeze() {
if [ ! -f /etc/debian_version ] ; then return 0; fi

if [ ! -f /etc/apt/sources.list  ]; then echo "dss:warn: Odd.  Debian distro but no apt sources.list"; return 1; fi

# cat /etc/debian_version 
# 6.0.4
if ! grep -qai "^6." /etc/debian_version; then return 0; fi

if ! grep -qai "^deb.*stable" /etc/apt/sources.list ; then echo "dss:info: Not using 'stable' repo.  Not converting deb6 stable to squeeze"; return 0; fi

if [ ! -e /root/deshellshockinfo/sources.list ]; then echo "dss:info: Running cp /etc/apt/sources.list /root/deshellshockinfo/sources.list"; cp /etc/apt/sources.list /root/deshellshockinfo/sources.list; fi

sed -i 's@^deb http://http.us.debian.org/debian stable@deb http://http.us.debian.org/debian squeeze@' /etc/apt/sources.list
sed -i 's@^deb http://security.debian.org stable@deb http://security.debian.org squeeze@' /etc/apt/sources.list
return 0
}

function convert_old_ubuntu_repo() {
[ ! -f /etc/apt/sources.list ] && return 0
CODENAME=$1
if [ -z "$CODENAME" ]; then echo "dss:error: We require a codename here.  e.g. convert_old_ubuntu_repo hardy"; return 1; fi

! egrep -qai "^deb.*ubuntu/ $CODENAME|^deb.*ubuntu $CODENAME" /etc/apt/sources.list && return 0
if grep -qai '^deb .*old-releases.ubuntu.com' /etc/apt/sources.list; then echo "dss:info: Already running an 'old-releases' $CODENAME repository."; return 0; fi

if [ ! -e /root/deshellshockinfo/sources.list ]; then echo "dss:info: Running cp /etc/apt/sources.list /root/deshellshockinfo/sources.list"; cp /etc/apt/sources.list /root/deshellshockinfo/sources.list; fi

echo "dss:info: Commenting out expired $CODENAME repository and adding in the 'old-releases' repository"
sed -i "s@^deb http://us.archive.ubuntu.com/ubuntu/ $CODENAME@#deb http://us.archive.ubuntu.com/ubuntu/ $CODENAME@" /etc/apt/sources.list
sed -i "s@^deb http://security.ubuntu.com/ubuntu $CODENAME@#deb http://security.ubuntu.com/ubuntu $CODENAME@" /etc/apt/sources.list
echo "
deb http://old-releases.ubuntu.com/ubuntu/ $CODENAME main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu/ $CODENAME-updates main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu/ $CODENAME-security main restricted universe multiverse" >> /etc/apt/sources.list

return 0

}


function add_missing_squeeze_lts() {
if [ -e /etc/apt/sources.list ] && grep -qai '^deb.*squeeze' /etc/apt/sources.list && ! grep -qai squeeze-lts /etc/apt/sources.list; then echo "
deb http://http.debian.net/debian/ squeeze-lts main contrib non-free
deb-src http://http.debian.net/debian/ squeeze-lts main contrib non-free
" >> /etc/apt/sources.list
echo "info: added missing squeeze-lts repos"
fi 
return 0
}


function convert_old_lenny_repo() {
# no apt sources nothing to do
[ ! -f /etc/apt/sources.list ] && return 0

# no lenny stuff, nothing to do
! grep -qai '^deb.*lenny' /etc/apt/sources.list && return 0

# already using archives, all good
if grep -qai '^deb http://archive.debian.org/debian/ lenny' /etc/apt/sources.list; then
  echo "dss:info: This is a lenny distro, and already has archive.debian in the repository."
  return 0
fi

if [ ! -e /root/deshellshockinfo/sources.list ]; then echo "dss:info: Running cp /etc/apt/sources.list /root/deshellshockinfo/sources.list"; cp /etc/apt/sources.list /root/deshellshockinfo/sources.list; fi

sed -i 's@^deb http://ftp.us.debian.org/debian lenny@#deb http://ftp.us.debian.org/debian lenny@' /etc/apt/sources.list
sed -i 's@^deb http://security.debian.org/ lenny@#deb http://security.debian.org/ lenny@' /etc/apt/sources.list
sed -i 's@^deb-src http://ftp.us.debian.org/debian lenny main contrib@#deb-src http://ftp.us.debian.org/debian lenny main contrib@' /etc/apt/sources.list
echo "deb http://archive.debian.org/debian/ lenny main non-free contrib" >> /etc/apt/sources.list
echo "dss:info: Lenny apt sources now has $(cat /etc/apt/sources.list | egrep -v '^$|^#')"
return 0
}

function print_distro_info() {
 if [ -x /usr/bin/lsb_release ] || [ -x /bin/lsb_release ] ; then    
  local foo="dss:distroinfo: $(lsb_release -a 2>/dev/null)" 
  echo $foo
elif [ -f /etc/redhat-release ]; then
  local foo="dss:distroinfo: REDHAT $(cat /etc/redhat-release)" 
  echo $foo
elif [ -f /etc/debian_version ]; then
  local foo="dss:distroinfo: DEBIAN $(cat /etc/debian_version)" 
  echo $foo
else echo "dss:distroinfo: NA"; fi
return 0
}


function fix_missing_lsb_release() {
which lsb_release >/dev/null 2>&1 && return 0
! [ -f /etc/debian_version ] && return 0
echo "dss:info: Missing lsb release command.  trying to install it."
apt-get update
apt-get -y --force-yes install lsb-release
}

function fix_via_apt_install_bash() {
  ! is_vulnerable && return 0 
if ! which dpkg >/dev/null 2>&1; then echo "dss:info: dpkg not installed.  Skipping apt-get install"; return 0; fi
if print_distro_info | grep Ubuntu | egrep -qai "$(echo $EOL_UBUNTU_DISTROS | sed 's/ /|/')"; then 
  echo "dss:info: Running an EOL Ubuntu.  Not doing an apt-get install -y bash.  $(print_distro_info)"
  return 0
fi

if dpkg -s bash 2>/dev/null | grep -q "Status.*installed" ; then 
  echo "dss:info: Attempting to apt-get install bash"
  apt-get update
  apt-get -y --force-yes install bash
  ret=$?
  if [ $ret -eq 0 ]; then
  	echo "dss:fixmethod: apt-get install" 
  	return 0
  fi
  echo "dss:error: Failed doing apt-get -y force-yes install bash"
  cd /root/deshellshockinfo
  # download isnt an option on some older apts
  apt-get download bash 2>/dev/null
  ret=$?
  file=$(find . -name '*.deb' | grep bash | head -n 1)
  if [ $ret -ne 0 ] || [ -z "$file" ]; then
  	echo "dss:error: Failed downloading the bash package with apt-get download bash"
  	return 1
  fi
  dpkg -i $file
  ret=$?
  if [ $ret -eq 0 ]; then
  	echo "dss:fixmethod: apt-get download bash and dpkg -i"
  	return 0
  fi
  return $ret
fi
echo "dss:info: bash not installed.  Not running apt-get install bash"
return 0
}

function yum_enable_rhel4() {
[ ! -f /etc/redhat-release ] && return 0
! grep -qai 'release.* 4' /etc/redhat-release && return 0
if which yum >/dev/null 2>&1; then echo "dss:info: yum enabled on a rhel4 distro already."; return 0; fi
echo "dss:info:yum not enabled on $(print_distro_info).  Trying to enable it."
{
rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/libxml2-2.6.16-12.6.i386.rpm
rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/libxml2-python-2.6.16-12.6.i386.rpm

rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/readline-4.3-13.i386.rpm
rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/python-2.3.4-14.7.el4.i386.rpm

# install all together else dependency issues
rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/sqlite-3.3.6-2.i386.rpm http://vault.centos.org/4.9/os/i386/CentOS/RPMS/sqlite-devel-3.3.6-2.i386.rpm http://vault.centos.org/4.9/os/i386/CentOS/RPMS/python-sqlite-1.1.7-1.2.1.i386.rpm

rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/python-elementtree-1.2.6-5.el4.centos.i386.rpm
rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/sqlite-3.3.6-2.i386.rpm
rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/python-sqlite-1.1.7-1.2.1.i386.rpm

rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/elfutils-libelf-0.97.1-5.i386.rpm
rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/elfutils-0.97.1-5.i386.rpm
rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/popt-1.9.1-32_nonptl.i386.rpm

rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/python-urlgrabber-2.9.8-2.noarch.rpm
rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/yum-metadata-parser-1.0-8.el4.centos.i386.rpm
rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/centos-release-4-8.i386.rpm
rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/yum-2.4.3-4.el4.centos.noarch.rpm
if [ ! -e /root/deshellshockinfo/CentOS-Base.repo ]; then 
  echo "dss:info: Running cp /etc/yum.repos.d/CentOS-Base.repo /root/deshellshockinfo/CentOS-Base.repo" 
  cp /etc/yum.repos.d/CentOS-Base.repo /root/deshellshockinfo/CentOS-Base.repo
fi

wget -nc -O /etc/yum.repos.d/CentOS-Base.repo http://vault.centos.org/4.9/CentOS-Base.repo
}
if which yum >/dev/null 2>&1; then echo "dss:info: yum enabled on a rhel4 distro."; return 0
else echo "dss:info: yum install failed on a rhel4 distro."; return 1 ; fi
return 0
}

function report_unsupported() {
  ! is_vulnerable && return 0 
if [ ! -f /etc/redhat-release ]; then return 0; fi
if grep -qai 'Shrike' /etc/redhat-release; then 
  # RH9
  return 0
elif grep -qai 'release.* 7' /etc/redhat-release; then 
  # yum install
  return 0
elif  grep -qai 'release.* 6' /etc/redhat-release; then
  # yum install 
  return 0
elif  grep -qai 'release.* 5' /etc/redhat-release; then
  # yum install 
  return 0
elif  grep -qai 'release.* 4' /etc/redhat-release; then
  # install prebuilt rpm 
  return 0
elif  grep -qai 'release.* 3' /etc/redhat-release; then
  # install prebuilt rpm 
  return 0
elif  grep -qai 'release.* 2' /etc/redhat-release; then 
  true
elif  grep -qai 'release.* 1' /etc/redhat-release; then 
  true
else 
  return 0
fi

# cat /etc/redhat-release 
#Red Hat Enterprise Linux WS release 4 (Nahant)
echo "dss:warn: There is currently no autopatch option for $(print_distro_info)"
return 1
}

# build an rpm package
function fix_rh9_wbel3_rhel4_via_rpmbuild() {
  [ ! -f /etc/redhat-release ] && return 0
  ! is_vulnerable && return 0 
  ! egrep -qai 'release.* 4|Shrike|release.* 3' /etc/redhat-release && return 0
  echo "dss:info: Attempting to build a patched bash RPM from a SRPM."
    mkdir -p /root/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS} 
    echo "%_topdir /root/rpmbuild/" > /root/.rpmmacros
    rpm -Uvh http://vault.centos.org/4.9/apt/i386/SRPMS.updates/bash-3.0-27.el4.src.rpm
    cd /root/rpmbuild/SOURCES/
    # http://ftp.gnu.org/pub/gnu/bash/bash-3.0-patches/
    for((i=17;i<21;i++)); do 
    wget -O bash30-0$i http://ftp.gnu.org/pub/gnu/bash/bash-3.0-patches/bash30-0$i || return 1
    # bash30-017:*** ../bash-3.0.16/builtins/common.h	2004-04-23 16:51:00.000000000 -0400
    # bash30-017:--- builtins/common.h	2014-09-16 21:57:03.000000000 -0400
    # should be like: bash30-015:*** ../bash-3.0-patched/general.c	Wed Apr 14 23:20:13 2004
    sed -i 's/bash-3.0.[0-9][0-9]/bash-3.0/' bash30-0$i
    # Patch16: bash30-016
    # # Other patches
    # insert our new patches
    ! grep -qai "Patch$i bash30-0$i" /root/rpmbuild/SPECS/bash.spec && sed -i "s/Patch$((i-1)): bash30-0$((i-1))/Patch$((i-1)): bash30-0$((i-1))\nPatch$i: bash30-0$i/" /root/rpmbuild/SPECS/bash.spec
    # %patch16 -p0 -b .016
    ! grep -qai "%patch$i -p0 -b .0$i" /root/rpmbuild/SPECS/bash.spec && sed -i "s/%patch$((i-1)) -p0 -b .0$((i-1))/%patch$((i-1)) -p0 -b .0$((i-1))\n%patch$((i)) -p0 -b .0$((i))/" /root/rpmbuild/SPECS/bash.spec    
    done
    # patch 16 is commented out for some reason, and that breaks the build
    sed -i 's@#%patch16@%patch16@' /root/rpmbuild/SPECS/bash.spec
    
    cd /root/rpmbuild/SPECS
    yum install -y texinfo bison libtermcap-devel
    yum install -y rpm-build
    # install build dependencies based on the spec
    yum install -y $(rpmbuild -ba bash.spec 2>&1 | grep needed | awk {' print $1 '})
    if ! rpmbuild -ba bash.spec; then echo "dss:error: rpmbuild of bash for rhel4 failed."; return 1; fi
    if [ ! -f /root/rpmbuild/RPMS/i386/bash-3.0-27.i386.rpm ]; then echo "dss:error: rpmbuild of bash for rhel4 failed, rpm not created."; return 1; fi
    # --replacepkgs fixes "package bash-3.0-27 is already installed"
    # --replacefiles fixes "/bin/bash from install of bash-3.0-27 conflicts with file from package bash-3.0-27"
    if ! rpm -Uvh --oldpackage --replacepkgs --replacefiles /root/rpmbuild/RPMS/i386/bash-3.0-27.i386.rpm; then echo "dss:error: Install of built bash rpm failed."; return 1; fi
	echo "dss:fixmethod: bash RPM patch and build" 
	return 0
}

function fix_rhel4_via_rpm_download() {
  [ ! -f /etc/redhat-release ] && return 0
  ! is_vulnerable && return 0 
  ! egrep -qai 'release.* 4|ora Core release 5|Fedora Core release 6' /etc/redhat-release && return 0
  # --oldpackage since I found a few places where there was a 'newer' but exploitable rpm
  if ! rpm --oldpackage --replacepkgs --replacefiles  -Uvh http://downloads.rimuhosting.com/bash-3.0-27.i386.rpm ; then echo "dss:error: Failing installing downloaded rhel3/4 rpm"; fi
  echo "dss:fixmethod: bash RPM download for rhel3/4"  
  # todo fedora 10 doesn't like this or the rh9 binary
  #Fedora release 10 (Cambridge)
  # error: Failed dependencies:
  #  libtermcap.so.2 is needed by bash-3.0-27.i386
  return 0
}

function fix_rh9_wbel3_via_rpm_download() {
  [ ! -f /etc/redhat-release ] && return 0
  ! is_vulnerable && return 0 
  ! egrep -qai 'Shrike|release.* 3' /etc/redhat-release && return 0
  if ! rpm --oldpackage --replacepkgs --replacefiles  -Uvh http://downloads.rimuhosting.com/rh9/bash-3.0-27.i386.rpm ; then echo "dss:error: Failing installing downloaded rh9 rpm"; fi
  echo "dss:fixmethod: bash RPM download for rh9"  
  return 0
}

function fix_centos5_plus_via_yum_install() {
  ! is_vulnerable && return 0 
if ! print_distro_info | egrep -i 'redhat|centos' | egrep -qai 'release.* 5|release.* 6|release.* 7' ; then echo "dss:info: Not centos5 to centos7, not doing a centos5-7 fix for $(print_distro_info)"; return 0; fi
echo "dss:info: Doing a centos5-7 fix for $(print_distro_info)"
if [ ! -x /usr/bin/yum ] ; then 
  #rpm http://centos5.rimuhosting.com/centos /5 os updates rimuhosting addons extras centosplus
  if [ ! -f /etc/apt/sources.list ]; then
    echo "dss:warn: Cannot do a yum install on this host, yum not installed, no /etc/apt/sources.list either."
    return 1
  fi
  if ! which apt-get >/dev/null 2>&1 ; then 
    echo "dss:warn: Cannot do a yum install on this host, yum not installed, no apt-get either."
  fi
  echo "dss:info: Trying to install yum via apt-get"
  apt-get --force-yes -y install yum
fi
if [ ! -x /usr/bin/yum ] ; then 
  echo "dss:warn: Cannot do a yum install on this host, yum not installed"
  return 1
fi
if [ ! -x /usr/bin/which ]; then
  echo "dss:warn: Which not installed.  Installing that with yum install which."
  yum install -y which
fi

yum install -y bash
ret=$?
# this file was added by us, but with wrong name (ending in s).
[ -f /etc/yum.repos.d/CentOS-Base.repos ] && [ -f /etc/yum.repos.d/CentOS-Base.repo ] && rm /etc/yum.repos.d/CentOS-Base.repos 
if is_vulnerable && print_distro_info | egrep -i 'redhat|centos' | egrep -qai 'release.* 5' && [ ! -f /etc/yum.repos.d/CentOS-Base.repo ] && [ -d /etc/yum.repos.d ] ; then
 echo "dss:warn: Still vulnerable after a yum install bash.  Installing a different CentOS-Base.repo"
 wget -nc -O /etc/yum.repos.d/CentOS-Base.repo http://downloads.rimuhosting.com/CentOS-Base.repos.v5
 yum install -y bash
 ret=$?
fi
echo "dss:fixmethod: yum install bash" 
return $ret
}

function fix_ubuntu_11_10_via_deb_pkg_install() {
  ! is_vulnerable && return 0 
if ! print_distro_info | grep Ubuntu | egrep -qai 'Release: 11.10|13.04'; then return 0 ; fi

if uname -a | grep -qai i686; then 
# Linux 2.6.32.28-xenU SMP Thu Jan 20 00:41:40 UTC 2011 i686 i686 i386 GNU/Linux
  echo "dss:info: Attempting to patch this distro, which is no longer supported, with the 32 bit lts deb package"
  wget http://security.ubuntu.com/ubuntu/pool/main/b/bash/bash_4.1-2ubuntu3.4_i386.deb
  dpkg -i bash_4.1-2ubuntu3.4_i386.deb
  ret=$?
  echo "dss:fixmethod: dpkg ubuntu"
  # prevent upgrades overwriting this one
  [ $ret -eq 0 ] && [ -x /usr/bin/apt-mark ] && sudo apt-mark hold bash
  return $ret
else 
  echo "dss:info: Attempting to patch this distro, which is no longer supported, with the 64 bit lts deb package"
  wget http://security.ubuntu.com/ubuntu/pool/main/b/bash/bash_4.1-2ubuntu3.4_amd64.deb
  dpkg -i bash_4.1-2ubuntu3.4_amd64.deb
  ret=$?
  echo "dss:fixmethod: dpkg ubuntu"
  # prevent upgrades overwriting this one
  [ $ret -eq 0 ] && [ -x /usr/bin/apt-mark ] && sudo apt-mark hold bash
  return $ret
fi
return 0
}

function fix_via_build_for_unsupported_debians_and_ubuntus() {
  ! is_vulnerable && return 0 
if [ $(print_distro_info | egrep -i 'Debian|Ubuntu' | wc -l) -eq 0 ]; then echo "dss:info: Not a debian or ubuntu distro.  Not attempting to install from source."; return 0; fi
if print_distro_info | grep -i Ubuntu | egrep -qai "$(echo $SUPPORTED_UBUNTU_DISTROS | sed 's/ /|/')"; then echo "dss:info: This is a currently supported Ubuntu distro.  Not attempting to install from source."; return 0; fi
if [ $(print_distro_info | egrep 'Debian GNU/Linux 7|Debian GNU/Linux 6|Ubuntu .*10.04|Ubuntu .*14.04|Ubuntu .*13' | wc -l) -gt 0 ]; then echo "dss:info: Not attempting to install from source.  There are better options available for this distro."; return 0; fi

# just try.  we are likely otherwise out of options for them
#if [ $(print_distro_info | egrep 'Debian GNU/Linux 5|Ubuntu 8|Ubuntu 9|Ubuntu 8|Ubuntu .*12.04' | wc -l) -eq 0 ]; then echo "dss:info: Not one of the 'known to work' options for install from source: Debian GNU/Linux 5.  Not attempting to install from source."; return 0; fi

# worked on at least as far back ubuntu 9.04, debian 3.1
echo "dss:info: This is an ubuntu/debian distro.  Likely out of long term support.  Attempting to make/install bash from source."

apt-get update
apt-get -y -f autoremove
apt-get -f install
if ! apt-get -y --force-yes install build-essential gettext bison; then
  echo "dss:error: Failed installing build dependencies: apt-get -y --force-yes install build-essential gettext bison.  continuing on, but the build will likely fail."
  for i in build-essential gettext bison  ; do
  	apt-get -y --force-yes install $i
  done    
fi

# get bash 3.2 source
wget http://ftp.gnu.org/gnu/bash/bash-3.2.tar.gz || return 1
tar zxvf bash-3.2.tar.gz || return 1
cd bash-3.2 || return 1

# download and apply all patches, including the latest one that patches CVE-2014-6271
# Note: CVE-2014-6271 is patched by release 52.
# Release 53 is not out on the GNU mirror yet - it should address CVE-2014-7169.
for i in $(seq -f "%03g" 1 55); do
    wget -nc http://ftp.gnu.org/gnu/bash/bash-3.2-patches/bash32-$i
    patch -p0 < bash32-$i
done

# compile and install to /usr/local/bin/bash
./configure && make || return 1
make install || return 1

# point /bin/bash to the new binary
[ ! -f /bin/bash.old ] && [ -e /bin/bash ] && mv /bin/bash /bin/bash.old
if [ ! -f /usr/local/bin/bash ] ; then echo "dss:error: /usr/local/bin/bash was not built."; return 1; fi
if ! /usr/local/bin/bash -c true ; then echo "dss:error: /usr/local/bin/bash was working."; return 1; fi
echo "dss:info: doing an apt-mark hold bash since we have installed a compiled version."
 [ -x /usr/bin/apt-mark ] && apt-mark hold bash 
cp -f /usr/local/bin/bash /bin/bash
echo "dss:info: Succeeded building bash."
echo "dss:info: New bash version: $(bash --version 2>&1| grep version | grep -v gpl)"
echo "dss:info: New bash ls: $(ls -l $(which bash))"
echo "dss:fixmethod: src build"
return 0
}

function build_from_source_unused() {
mkdir src || return 1
cd src || return 1
wget http://ftp.gnu.org/gnu/bash/bash-4.3.tar.gz || return 1
#download all patches
for i in $(seq -f "%03g" 0 28); do wget -nc http://ftp.gnu.org/gnu/bash/bash-4.3-patches/bash43-$i; done
tar zxvf bash-4.3.tar.gz || return 1
cd bash-4.3 || return 1
#apply all patches
for i in $(seq -f "%03g" 0 28);do patch -p0 < ../bash43-$i; done
#build and install
./configure && make && make install  || return 1
cd ..
cd ..
rm -r src 
return 0
}


function run() {
if ! prep_shellshock_output_dir ; then
    ret=$?
    print_vulnerability_status beforefix
    print_info
    return  $ret
fi

print_vulnerability_status beforefix || return $?
print_info

if ! is_vulnerable ; then 
  echo "dss:info: The server appears to not be vulnerable.  Not doing anything."
  return 0
fi

# improve apt sources
convert_deb_6_stable_repo_to_squeeze  || return $?
convert_old_lenny_repo || return $?

# https://wiki.ubuntu.com/Releases
# lucid server still current?
for distro in $EOL_UBUNTU_DISTROS; do 
  convert_old_ubuntu_repo $distro || return $?
done
add_missing_squeeze_lts || return $?

fix_missing_lsb_release

fix_via_apt_install_bash #|| return $?

yum_enable_rhel4 || return $?

fix_rhel4_via_rpm_download || return $?
fix_rh9_wbel3_via_rpm_download || return $?
# does faila bit...
fix_rh9_wbel3_rhel4_via_rpmbuild #|| return $?
fix_centos5_plus_via_yum_install || return $?
fix_ubuntu_11_10_via_deb_pkg_install || return $?
fix_via_build_for_unsupported_debians_and_ubuntus || return $?

report_unsupported || return $?
return 0
}

if [ "--usage" = "${ACTION:-$1}" ] ; then
  print_usage
elif [ "--check" = "${ACTION:-$1}" ] ; then
  print_info
elif [ "--source" = "${ACTION:-$1}" ] ; then 
  echo "dss: Loading deshellshock functions"
else 
  run
  ret=$?
  print_vulnerability_status afterfix
  if [ $ret -eq 0 ] ; then true ; else false; fi
fi