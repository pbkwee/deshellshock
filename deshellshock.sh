#!/bin/bash


DEBIAN_FRONTEND=noninteractive
# https://wiki.ubuntu.com/Releases
# lucid server still current?
EOL_UBUNTU_DISTROS="breezy dapper edgy feisty gutsy hardy hoary intrepid jaunty karmic maverick natty oneiric quantal raring warty" 

function print_usage() {
  echo "Checks to see if a server has a 'shellshocked' bash (vulnerable to CVE_2014_6271 or CVE_2014_7169)
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
  
  Written by Peter Bryant at http://lauchtimevps.com
  
  Latest version (or thereabouts) available at https://github.com/pbkwee/deshellshock
  "
}

function print_CVE_2014_7169_vulnerable() {
# http://en.wikipedia.org/wiki/Shellshock_%28software_bug%29#Testing_2
if [ -f echo ] ; then echo "dss:Remove the echo file first"; return 2; fi
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
	is_CVE_2014_7169_vulnerable && return 1 
}
# use print_vulnerability_status beforefix and print_vulnerability_status afterfix
function print_vulnerability_status() {
local prefix=${1:-prefix}
echo "dss:isvulnerable:$prefix: CVE_2014_6271$(print_CVE_2014_6271_vulnerable)"
echo "dss:isvulnerable:$prefix: CVE_2014_7169$(print_CVE_2014_7169_vulnerable)"
}

function prep_shellshock_output_dir() {
if [ ! -d /root/deshellshockinfo ] ; then echo "dss:info: creating /root/deshellshockinfo and cd-ing there."; mkdir /root/deshellshockinfo; fi
[ -d /root/deshellshockinfo ] && cd /root/deshellshockinfo
if [ ! -e /root/deshellshockinfo/bash.orig ]; then 
  echo "dss:info: Running cp /bin/bash /root/deshellshockinfo/bash.orig"
  if ! cp /bin/bash /root/deshellshockinfo/bash.orig; then 
    echo "dss:error: failed making a copy of the original bash binary.  Is there a disk error, out of disk space?"
    return 1
  fi
fi
return 0
}

function print_info() {
echo "dss:hostname: $(hostname)"
echo "dss:date: $(date -u)"
echo "dss:Testing for CVE_2014_6271 (error messages occurring here can be expected):"
env x='() { :;}; echo vulnerable' bash -c "echo" 2>&1
local val1=$(print_CVE_2014_6271_vulnerable)
local ret1=$?
echo "dss:CVE_2014_6271 result isvulnerable $val1 $ret1"
echo "dss:Testing for CVE-2014_7169 (error messages occurring here can be expected):"
if [ -f echo ] ; then 
  echo "dss:warn: cannot test.  There is an echo file already."; 
  val2="NA"
  ret2=-1
else 
  X='() { (a)=>\' bash -c "echo date" 2>&1
  rm -f echo
  local val2=$(print_CVE_2014_7169_vulnerable)
  local ret2=$?
fi
echo "dss:CVE-2014_7169 result isvulnerable $val2 $ret2"
echo "dss:Bash version: $(bash --version 2>&1| grep version | grep -v gpl)"
echo "dss:Bash ls: $(ls -l $(which bash))"
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
return 0
}


function convert_deb_6_stable_repo_to_squeeze() {
if [ ! -f /etc/debian_version ] ; then echo "dss:info: Not debian.  Not converting deb6 stable to squeeze"; return 0; fi

if [ ! -f /etc/apt/sources.list  ]; then echo "dss:warn: Odd.  Debian distro but no apt sources.list"; return 1; fi

# cat /etc/debian_version 
# 6.0.4
if ! grep -qai "^6." /etc/debian_version; then echo "dss:info: Not debian 6.  Not converting deb6 stable to squeeze"; return 0; fi

if ! grep -qai "^deb.*stable" /etc/apt/sources.list ; then echo "dss:info: Not using 'stable' repo.  Not converting deb6 stable to squeeze"; return 0; fi

if [ ! -e /root/deshellshockinfo/sources.list ]; then echo "dss:info: Running cp /etc/apt/sources.list /root/deshellshockinfo/sources.list"; cp /etc/apt/sources.list /root/deshellshockinfo/sources.list; fi

sed -i 's@^deb http://http.us.debian.org/debian stable@deb http://http.us.debian.org/debian squeeze@' /etc/apt/sources.list
sed -i 's@^deb http://security.debian.org stable@deb http://security.debian.org squeeze@' /etc/apt/sources.list
return 0
}

function convert_old_ubuntu_repo() {
[ ! -f /etc/apt/sources.list ] && return 0
CODENAME=$1
if [ -z "$CODENAME" ]; then echo "dss:error: we require a codename here.  e.g. convert_old_ubuntu_repo hardy"; return 1; fi

! egrep -qai "^deb.*ubuntu/ $CODENAME|^deb.*ubuntu $CODENAME" /etc/apt/sources.list && return 0
if grep -qai '^deb .*old-releases.ubuntu.com' /etc/apt/sources.list; then echo "dss:info: already running an 'old-releases' $CODENAME repository."; return 0; fi

if [ ! -e /root/deshellshockinfo/sources.list ]; then echo "dss:info: Running cp /etc/apt/sources.list /root/deshellshockinfo/sources.list"; cp /etc/apt/sources.list /root/deshellshockinfo/sources.list; fi

echo "dss:info: commenting out expired $CODENAME repository and adding in the 'old-releases' repository"
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
  echo "dss:info: this is a lenny distro, and already has archive.debian in the repository."
  return 0
fi

if [ ! -e /root/deshellshockinfo/sources.list ]; then echo "dss:info: Running cp /etc/apt/sources.list /root/deshellshockinfo/sources.list"; cp /etc/apt/sources.list /root/deshellshockinfo/sources.list; fi

sed -i 's@^deb http://ftp.us.debian.org/debian lenny@#deb http://ftp.us.debian.org/debian lenny@' /etc/apt/sources.list
sed -i 's@^deb http://security.debian.org/ lenny@#deb http://security.debian.org/ lenny@' /etc/apt/sources.list
sed -i 's@^deb-src http://ftp.us.debian.org/debian lenny main contrib@#deb-src http://ftp.us.debian.org/debian lenny main contrib@' /etc/apt/sources.list
echo "deb http://archive.debian.org/debian/ lenny main non-free contrib" >> /etc/apt/sources.list
echo "dss:info: lenny apt sources now has $(cat /etc/apt/sources.list | egrep -v '^$|^#')"
return 0
}

function print_distro_info() {
if which lsb_release >/dev/null 2>&1; then 
  local foo="dss:distroinfo: $(lsb_release -a 2>/dev/null)"
  echo $foo
elif [ -f /etc/redhat-release ]; then
  local foo="dss:distroinfo: REDHAT $(cat /etc/redhat-release)" 
  echo $foo
else echo "dss:distroinfo: NA"; fi
return 0
}


function fix_missing_lsb_release() {
which lsb_release >/dev/null 2>&1 && return 0
! [ -f /etc/debian_version ] && return 0
echo "dss:info: missing lsb release command.  trying to install it."
apt-get update
apt-get -y --force-yes install lsb-release
}

function fix_via_apt_install_bash() {
if ! which dpkg >/dev/null 2>&1; then echo "dss:info: dpkg not installed.  Skipping apt-get install"; return 0; fi
if print_distro_info | grep Ubuntu | egrep -qai "$(echo $EOL_UBUNTU_DISTROS | sed 's/ /|')"; then 
  echo "dss:info: running an EOL Ubuntu.  Not doing an apt-get install -y bash.  $(print_distro_info)"
  return 0
fi

if dpkg -s bash 2>/dev/null | grep -q "Status.*installed" ; then 
  echo "dss:info: attempting to apt-get install bash"
  apt-get update
  apt-get -y --force-yes install bash
  ret=$?
  echo "dss:fixmethod: apt-get install" 
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

rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/python-elementtree-1.2.6-5.el4.centos.i386.rpm
rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/sqlite-3.3.6-2.i386.rpm
rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/python-sqlite-1.1.7-1.2.1.i386.rpm

rpm -Uvh http://vault.centos.org/4.9/os/i386/CentOS/RPMS/http://vault.centos.org/4.9/os/i386/CentOS/RPMS/elfutils-libelf-0.97.1-5.i386.rpm
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

wget -O /etc/yum.repos.d/CentOS-Base.repo http://vault.centos.org/4.9/CentOS-Base.repo
}
if which yum >/dev/null 2>&1; then echo "dss:info: yum enabled on a rhel4 distro."; return 0
else echo "dss:info: yum install failed on a rhel4 distro."; return 1 ; fi
return 0
}

function fix_rh4_wbel3() {
if [ ! -f /etc/redhat-release ]; then echo "dss:info: Not redhat.  Not doing RH4 fix."; return 0; fi
if grep -qai 'Shrike' /etc/redhat-release; then 
  # RH9
  true
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
  # rpm build 
  return 0
elif  grep -qai 'release.* 3' /etc/redhat-release; then 
  true
elif  grep -qai 'release.* 2' /etc/redhat-release; then 
  true
elif  grep -qai 'release.* 1' /etc/redhat-release; then 
  true
else 
  return 0
fi

# cat /etc/redhat-release 
#Red Hat Enterprise Linux WS release 4 (Nahant)
echo "dss:warn: There is currently no autopatch option for $(cat /etc/redhat-release)"
return 1
}

# build an rpm package
function fix_rhel4() {
  [ ! -f /etc/redhat-release ] && return 0
  ! is_vulnerable && return 0 
  ! grep -qai 'release.* 4' /etc/redhat-release && return 0
  echo "dss:info:Attempting to build a patched bash RPM from a SRPM."
    mkdir -p /root/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS} 
    echo "%_topdir /root/rpmbuild/" > /root/.rpmmacros
    rpm -Uvh http://vault.centos.org/4.9/apt/i386/SRPMS.updates/bash-3.0-27.el4.src.rpm
    cd /root/rpmbuild/SOURCES/
    # http://ftp.gnu.org/pub/gnu/bash/bash-3.0-patches/
    for((i=17;i<19;i++)); do 
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
    # install build dependencies based on the spec
    yum install -y $(rpmbuild -ba bash.spec 2>&1 | grep needed | awk {' print $1 '})
    if ! rpmbuild -ba bash.spec; then echo "dss:error:rpmbuild of bash for rhel4 failed."; return 1; fi
    if [ ! -f /root/rpmbuild/RPMS/i386/bash-3.0-27.i386.rpm ]; then echo "dss:error:rpmbuild of bash for rhel4 failed, rpm not created."; return 1; fi
    if ! rpm -Uvh -oldpackage /root/rpmbuild/RPMS/i386/bash-3.0-27.i386.rpm; then echo "dss:error:install of built bash rpm failed."; return 1; fi
	echo "dss:fixmethod: bash RPM patch and build" 
	return 0
}

function fix_rhel4_via_download() {
  [ ! -f /etc/redhat-release ] && return 0
  ! is_vulnerable && return 0 
  ! grep -qai 'release.* 4' /etc/redhat-release && return 0
  # -oldpackage since I found a few places where there was a 'newer' but exploitable rpm
  if ! rpm --oldpackage -Uvh http://downloads.rimuhosting.com/bash-3.0-27.i386.rpm ; then echo "dss:error: failing installing downloaded rhel4 rpm"; fi
  echo "dss:fixmethod: bash RPM download"  
  return 0
}

function fix_centos5_plus() {
if ! print_distro_info | grep REDHAT | egrep -qai 'release.* 5|release.* 6|release.* 7' ; then echo "dss:info: not centos5 to centos7, not doing a centos5-7 fix for $(print_distro_info)"; return 0; fi
echo "dss:info: doing a centos5-7 fix for $(print_distro_info)"
if ! which yum >/dev/null 2>&1 ; then 
  #rpm http://centos5.rimuhosting.com/centos /5 os updates rimuhosting addons extras centosplus
  if [ ! -f /etc/apt/sources.list ]; then
    echo "dss:warn: cannot do a yum install on this host, yum not installed, no /etc/apt/sources.list either."
    return 1
  fi
  if ! which apt-get >/dev/null 2>&1 ; then 
    echo "dss:warn: cannot do a yum install on this host, yum not installed, no apt-get either."
  fi
  echo "dss:info: trying to install yum via apt-get"
  apt-get -y install yum
fi
if ! which yum >/dev/null 2>&1 ; then 
  echo "dss:warn: cannot do a yum install on this host, yum not installed"
  return 1
fi
yum install -y bash
ret=$?
echo "dss:fixmethod: yum install bash" 
return $ret
}

function fix_ubuntu_11_10() {
if ! print_distro_info | grep Ubuntu | egrep -qai 'Release: 11.10|13.04'; then return 0 ; fi
if ! is_CVE_2014_7169_vulnerable  && ! is_CVE_2014_6271_vulnerable ; then 
  # nothing to do
  return 0;
fi

if uname -a | grep -qai i686; then 
# Linux 2.6.32.28-xenU SMP Thu Jan 20 00:41:40 UTC 2011 i686 i686 i386 GNU/Linux
  echo "dss:info: attempting to patch this distro, which is no longer supported, with the 32 bit lts deb package"
  wget http://security.ubuntu.com/ubuntu/pool/main/b/bash/bash_4.1-2ubuntu3.2_i386.deb
  dpkg -i bash_4.1-2ubuntu3.2_i386.deb
  ret=$?
  echo "dss:fixmethod: dpkg ubuntu"
  # prevent upgrades overwriting this one
  [ $ret -eq 0 ] && sudo apt-mark hold bash
  return $ret
else 
  echo "dss:info: attempting to patch this distro, which is no longer supported, with the 64 bit lts deb package"
  wget http://security.ubuntu.com/ubuntu/pool/main/b/bash/bash_4.1-2ubuntu3.2_amd64.deb
  dpkg -i bash_4.1-2ubuntu3.2_amd64.deb
  ret=$?
  echo "dss:fixmethod: dpkg ubuntu"
  # prevent upgrades overwriting this one
  [ $ret -eq 0 ] && sudo apt-mark hold bash
  return $ret
fi
return 0
}

function fix_via_build_for_certain_distros() {
if [ $(print_distro_info | egrep 'Debian|Ubuntu' | wc -l) -eq 0 ]; then echo "dss:info: not a debian or ubuntu distro.  Not attempting to install from source."; return 0; fi
if ! is_CVE_2014_7169_vulnerable  && ! is_CVE_2014_6271_vulnerable ; then 
  # nothing to do
  return 0;
fi
if [ $(print_distro_info | egrep 'Debian GNU/Linux 7|Debian GNU/Linux 6|Ubuntu.*10.04|Ubuntu.*12.04|Ubuntu.*14.04|Ubuntu.*13' | wc -l) -gt 0 ]; then echo "dss:info: Not attempting to install from source.  There are better options available for this distro."; return 0; fi

if [ $(print_distro_info | egrep 'Debian GNU/Linux 5|Ubuntu 8' | wc -l) -eq 0 ]; then echo "dss:info: Not one of the 'known to work' options for install from source: Debian GNU/Linux 5.  Not attempting to install from source."; return 0; fi

echo "dss:info: This is an ubuntu/debian distro.  Likely out of long term support.  Attempting to make/install bash from source."

apt-get update
apt-get -y -f autoremove
apt-get -f install
if ! apt-get -y --force-yes install build-essential gettext bison; then
  echo "dss:error: failed installing build dependencies: apt-get -y --force-yes install build-essential gettext bison.  continuing on, but the build will likely fail."
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
for i in $(seq -f "%03g" 1 53); do
    wget -nv http://ftp.gnu.org/gnu/bash/bash-3.2-patches/bash32-$i
    patch -p0 < bash32-$i
done

# compile and install to /usr/local/bin/bash
./configure && make || return 1
make install || return 1

# point /bin/bash to the new binary
[ ! -f /bin/bash.old ] && [ -e /bin/bash ] && mv /bin/bash /bin/bash.old
if [ ! -f /usr/local/bin/bash ] ; then echo "dss:error: /usr/local/bin/bash was not built."; return 1; fi
if ! /usr/local/bin/bash -c true ; then echo "dss:error: /usr/local/bin/bash was working."; return 1; fi 
cp -f /usr/local/bin/bash /bin/bash
echo "dss:info: succeeded building bash."
echo "dss:info: new bash version: $(bash --version 2>&1| grep version | grep -v gpl)"
echo "dss:info: new bash ls: $(ls -l $(which bash))"
echo "dss:fixmethod: src build"
return 0
}

function build_from_source_unused() {
mkdir src || return 1
cd src || return 1
wget http://ftp.gnu.org/gnu/bash/bash-4.3.tar.gz || return 1
#download all patches
for i in $(seq -f "%03g" 0 26); do wget     http://ftp.gnu.org/gnu/bash/bash-4.3-patches/bash43-$i; done
tar zxvf bash-4.3.tar.gz || return 1
cd bash-4.3 || return 1
#apply all patches
for i in $(seq -f "%03g" 0 25);do patch -p0 < ../bash43-$i; done
#build and install
./configure && make && make install  || return 1
cd ..
cd ..
rm -r src 
return 0
}


function run() {
prep_shellshock_output_dir || return $?
print_vulnerability_status beforefix || return $?
print_info

if ! is_CVE_2014_7169_vulnerable && ! is_CVE_2014_6271_vulnerable ; then 
  echo "dss:info: the server appears to not be vulnerable.  Not doing anything."
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

fix_via_apt_install_bash || return $?

# explain how you are SOL for now
yum_enable_rhel4 || return $?
fix_rh4_wbel3 || return $?
# if it fails we will try the rpm download
fix_rhel4 #|| return $?
fix_rhel4_via_download || return $?
fix_centos5_plus || return $?
fix_ubuntu_11_10 || return $?
fix_via_build_for_certain_distros || return $?

return 0
}

if [ "--usage" = "$1" ] ; then
  print_usage
elif [ "--check" = "$1" ] ; then
  print_info
elif [ "--source" = "$1" ] ; then 
  echo "dss:Loading deshellshock functions"
else 
  run
  ret=$?
  print_vulnerability_status afterfix
  if [ $ret -eq 0 ] ; then true ; else false; fi
fi