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
  - Unsupported Ubuntu (11.10, 13.04, and potentially others) => install from an ubuntu package and apt-mark hold bash 
  - Debian 5 (and potentially other Debians and Ubuntus) => build from source
  - RHEL4, RHEL3 => unsupported for now
  
  Use with --source if you just wish to have the functions available to you for testing
  
  Run with --check if you just wish to check, but not change your server
  
  Run with --usage to get this message
  
  Run without an argument to try and fix your server"
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

# use print_vulnerability_status beforefix and print_vulnerability_status afterfix
function print_vulnerability_status() {
local prefix=${1:-prefix}
echo "dss:isvulnerable:$prefix: CVE_2014_6271$(print_CVE_2014_6271_vulnerable)"
echo "dss:isvulnerable:$prefix: CVE_2014_7169$(print_CVE_2014_7169_vulnerable)"
}

function prep_shellshock_output_dir() {
if [ ! -d /root/deshellshockinfo ] ; then echo "dss:info: creating /root/deshellshockinfo and cd-ing there."; mkdir /root/deshellshockinfo; fi
[ -d /root/deshellshockinfo ] && cd /root/deshellshockinfo
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

function fix_rh4_wbel3() {
if [ ! -f /etc/redhat-release ]; then echo "dss:info: Not redhat.  Not doing RH4 fix."; return 0; fi
if grep -qai 'release.* 4' /etc/redhat-release; then 
  true
elif  grep -qai 'release.* 3' /etc/redhat-release; then 
  true
elif  grep -qai 'release.* 2' /etc/redhat-release; then 
  true
elif  grep -qai 'release.* 1' /etc/redhat-release; then 
  true
else 
  echo "dss:info: Redhat, but not RH3 or RH4.  Not doing RH3/RH4 fix."; return 0
fi

# cat /etc/redhat-release 
#Red Hat Enterprise Linux WS release 4 (Nahant)
echo "dss:warn: There is currently no autopatch option for $(cat /etc/redhat-release)"
return 1
}

function fix_centos5_plus() {
if ! print_distro_info | grep REDHAT | egrep -qai 'release.* 5|release.* 6|release.*7' ; then echo "dss:info: not centos5 to centos7, not doing a centos5-7 fix for $(print_distro_info)"; return 0; fi
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

apt-get update; apt-get -y --force-yes install build-essential gettext bison || return 1

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
fix_rh4_wbel3 || return $?

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