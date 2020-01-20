#!/usr/bin/python3

from prettytable import PrettyTable
import os
import subprocess
from colorama import Fore,Style
x = PrettyTable()

x.field_names = ["CIS Benchmarks","Yes/No"]
x.align["CIS Benchmarks"] = "l"
x.align["Yes/No"] = "l"

y = PrettyTable()
y.field_names = ["CIS Benchmarks","Yes/No"]
y.align["CIS Benchmarks"] = "l"
y.align["Yes/No"] = "l"

FNULL = open(os.devnull, 'w')

#determining debian or centos
cmd = "cat /proc/version | grep -o 'Debian\|Centos' -m 1"
version = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
version1 = version.communicate()[0]
if version1==b'Debian\nDebian\n':
        inst = 'apt-get'
        inst2 = 'libselinux1'
        inst3 = 'purge'
        permission = b'-rw-r--r--\n'
        check1 = "dpkg -s aide | grep 'Package' | cut -d ' ' -f 1"
        check1o = check2o = check3o = check4o = b'Package:\n'
        check2 = "dpkg -s libselinux1 | grep 'Package' | cut -d ' ' -f 1"
        check3 = "dpkg -s mcstrans | grep 'Package' | cut -d ' ' -f 1"
        check4 = "dpkg -s ntp | grep 'Package' | cut -d ' ' -f 1"
else:
        inst = 'yum'
        inst2 = 'libselinux'
        inst3 = 'remove'
        permission = b'-rw-r--r--.\n'
        check1 = 'rpm -q aide | grep -o aide-'
        check1o = b'aide-\n'
        check2 = "rpm -q libselinux | grep -o libselinux-"
        check2o = b'libselinux-\n'
        check3 = "rpm -q mcstrans | grep -o mcstrans-"
        check3o = b'mcstrans-\n'
        check4 = "rpm -q ntp | grep -o ntp-"
        check4o = b'ntp-\n'

def status():
        cmd = "mount | grep -E '\s/tmp\s'"
        mount = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        output = mount.communicate()[0]

        exit=mount.returncode

        if exit==0:
                x.add_row(["/tmp is configured",Fore.GREEN +"yes" + Style.RESET_ALL])
        elif exit==1:
                x.add_row(["/tmp is configured",Fore.RED +"no" + Style.RESET_ALL])

        cmd1="ls -l /etc/passwd | cut -d ' ' -f 1"
       	perm1= subprocess.Popen(cmd1,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        output1 = perm1.communicate()[0]
        if output1==permission:
                 x.add_row(["/etc/passwd  permissions",Fore.GREEN +"yes" + Style.RESET_ALL])
        else:
                x.add_row(["/etc/passwd permissions",Fore.RED +"no" + Style.RESET_ALL])
        cmd2="ls -l /etc/group | cut -d ' ' -f 1"
        perm2= subprocess.Popen(cmd2,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        output2 = perm2.communicate()[0]
        if output2==permission:
                x.add_row(["/etc/group  permissions",Fore.GREEN +"yes" + Style.RESET_ALL])
        else:
                x.add_row(["/etc/group permissions",Fore.RED +"no" + Style.RESET_ALL])

        cmd3="ls -l /etc/passwd | cut -d ' ' -f 3,4"
        perm3= subprocess.Popen(cmd3,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        output3 = perm3.communicate()[0]

        if output3==b'root root\n':
                x.add_row(["/etc/passwd  ownership",Fore.GREEN +"yes" + Style.RESET_ALL])
        else:
                x.add_row(["/etc/passwd ownership",Fore.RED +"no" + Style.RESET_ALL])
        cmd4="ls -l /etc/group | cut -d ' ' -f 3,4"
        perm4= subprocess.Popen(cmd4,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        output4 = perm4.communicate()[0]
        if output4==b'root root\n':
                x.add_row(["/etc/group  ownership",Fore.GREEN +"yes" + Style.RESET_ALL])
        else:
                x.add_row(["/etc/group ownership",Fore.RED +"no" + Style.RESET_ALL])

        cmd5="systemctl is-enabled autofs"
        perm5= subprocess.Popen(cmd5,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        output5 = perm5.communicate()[0]
        if output5==b'disabled\n':
                x.add_row(["Automounting disabled",Fore.GREEN +"yes" + Style.RESET_ALL])
        elif output5==b'enabled\n':
                x.add_row(["Automounting disabled",Fore.RED +"no" + Style.RESET_ALL])


        cmd6 = check1
        perm6 = subprocess.Popen(cmd6,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        output6 = perm6.communicate()[0]
        if output6==check1o:
                x.add_row(["AIDE installed",Fore.GREEN +"yes" + Style.RESET_ALL])
        else:
                x.add_row(["AIDE installed",Fore.RED +"no" + Style.RESET_ALL])

        cmd7 = check2
        perm7 = subprocess.Popen(cmd7,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        output7 = perm7.communicate()[0]
        if output7==check2o:
                x.add_row(["SELinux installed",Fore.GREEN +"yes" + Style.RESET_ALL])
        else:
                x.add_row(["SELinux installed",Fore.RED +"no" + Style.RESET_ALL])
        cmd8 = check3
        perm8 = subprocess.Popen(cmd8,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        output8 = perm8.communicate()[0]
        if output8==check3o:
                x.add_row(["MCS Translation Service is not installed",Fore.RED +"no" + Style.RESET_ALL])
        else:
                x.add_row(["MCS Translation Service is not installed",Fore.GREEN +"yes" + Style.RESET_ALL])

        cmd9 = check4
        perm9 = subprocess.Popen(cmd9,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        output9 = perm9.communicate()[0]
        if output9==check4o:
                x.add_row(["Ensure time synchronization",Fore.GREEN +"yes" + Style.RESET_ALL])
        else:
                x.add_row(["Ensure time synchronization",Fore.RED +"no" + Style.RESET_ALL])


        cmd10="systemctl is-enabled vsftpd"
        perm10= subprocess.Popen(cmd10,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        output10 = perm10.communicate()[0]
        if output10==b'disabled\n':
                x.add_row(["FTP server disabled",Fore.GREEN +"yes" + Style.RESET_ALL])
        elif output10==b'enabled\n':
                x.add_row(["FTP server disabled",Fore.RED +"no" + Style.RESET_ALL])

        cmd11="sysctl net.ipv4.ip_forward | cut -d ' ' -f 3"
        perm11= subprocess.Popen(cmd11,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        output11 = perm11.communicate()[0]
        if output11==b'0\n':
                x.add_row(["IP forwarding is disabled",Fore.GREEN +"yes" + Style.RESET_ALL])
        else:
                x.add_row(["IP forwarding is disabled",Fore.RED +"no" + Style.RESET_ALL])

        cmd12="sysctl net.ipv4.conf.all.log_martians | cut -d ' ' -f 3"
        perm12= subprocess.Popen(cmd12,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        output12 = perm12.communicate()[0]
        if output12==b'1\n':
                x.add_row(["Suspicious packets are logged",Fore.GREEN +"yes" + Style.RESET_ALL])
        else:
                x.add_row(["Suspicious packets are logged",Fore.RED +"no" + Style.RESET_ALL])

        cmd13="sysctl net.ipv4.icmp_echo_ignore_broadcasts | cut -d ' ' -f 3"
        perm13= subprocess.Popen(cmd13,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        output13 = perm13.communicate()[0]
        if output13==b'1\n':
                x.add_row(["Broadcast ICMP requests are ignored",Fore.GREEN +"yes" + Style.RESET_ALL])
        else:
                x.add_row(["Broadcast ICMP requests are ignored",Fore.RED +"no" + Style.RESET_ALL])

#        cmd14="umask"
#        perm14= subprocess.Popen(cmd14,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
#        output14 = perm14.communicate()[0]
#        if output14==b'0027\n':
#                x.add_row(["umask is 0027",Fore.GREEN +"yes" + Style.RESET_ALL])
#        else:
#                x.add_row(["umask is 0027",Fore.RED +"no" + Style.RESET_ALL])
def enabled():
        lst=[]
       	for row in x:
                row.border = False
                row.header = False
                lst.append(str(row.get_string(fields=["Yes/No"])))
        if lst[0]==' \x1b[31mno\x1b[0m ':
                cmd = "mount | grep -E '\s/tmp\s'"
                mount = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                output = mount.communicate()[0]
                exit=mount.returncode
                if exit==0:
                        print(output)
                elif exit==1:
                        f=open('/etc/fstab','a+')
                        f.write("tmp /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0")
                        f.close()
                        subprocess.call(["mount", "/tmp"], stdout=FNULL)
                        y.add_row(["/tmp is configured",Fore.GREEN +"yes" + Style.RESET_ALL])
        elif lst[0]==' \x1b[32myes\x1b[0m ':
                y.add_row(["/tmp is configured",Fore.GREEN +"yes" + Style.RESET_ALL])

        if lst[1]==' \x1b[31mno\x1b[0m ':
                subprocess.call(["chmod", "644", "/etc/passwd"])
                y.add_row(["/etc/passwd permissions",Fore.GREEN +"yes" + Style.RESET_ALL])
        elif lst[1]==' \x1b[32myes\x1b[0m ':
                y.add_row(["/etc/passwd permissions",Fore.GREEN +"yes" + Style.RESET_ALL])
        if lst[2]==' \x1b[31mno\x1b[0m ':
                subprocess.call(["chmod", "644", "/etc/group"])
                y.add_row(["/etc/group permissions",Fore.GREEN +"yes" + Style.RESET_ALL])
        elif lst[2]==' \x1b[32myes\x1b[0m ':
                y.add_row(["/etc/group permissions",Fore.GREEN +"yes" + Style.RESET_ALL])
        if lst[3]==' \x1b[31mno\x1b[0m ':
                subprocess.call(["chown", "root:root", "/etc/passwd"])
                y.add_row(["/etc/passwd ownership",Fore.GREEN +"yes" + Style.RESET_ALL])
        elif lst[3]==' \x1b[32myes\x1b[0m ':
                y.add_row(["/etc/passwd ownership",Fore.GREEN +"yes" + Style.RESET_ALL])
        if lst[4]==' \x1b[31mno\x1b[0m ':
                subprocess.call(["chown", "root:root", "/etc/group"])
                y.add_row(["/etc/group ownership",Fore.GREEN +"yes" + Style.RESET_ALL])

        elif lst[4]==' \x1b[32myes\x1b[0m ':
                y.add_row(["/etc/group ownership",Fore.GREEN +"yes" + Style.RESET_ALL])
        if lst[5]==' \x1b[31mno\x1b[0m ':
                subprocess.call(["systemctl", "disable", "autofs", "-q"], stdout=FNULL)
                y.add_row(["Automounting disabled",Fore.GREEN +"yes" + Style.RESET_ALL])
        elif lst[5]==' \x1b[32myes\x1b[0m ':
                y.add_row(["Automounting disable",Fore.GREEN +"yes" + Style.RESET_ALL])
        if lst[6]==' \x1b[31mno\x1b[0m ':
                subprocess.call([inst, "install", "aide", "-y"], stdout=FNULL)
                y.add_row(["AIDE installed",Fore.GREEN +"yes" + Style.RESET_ALL])
        elif lst[6]==' \x1b[32myes\x1b[0m ':
                y.add_row(["AIDE installed",Fore.GREEN +"yes" + Style.RESET_ALL])
        if lst[7]==' \x1b[31mno\x1b[0m ':
                subprocess.call([inst, "install", inst2, "-y"], stdout=FNULL)
                y.add_row(["SELinux installed",Fore.GREEN +"yes" + Style.RESET_ALL])
        elif lst[7]==' \x1b[32myes\x1b[0m ':
                y.add_row(["SELinux installed",Fore.GREEN +"yes" + Style.RESET_ALL])
        if lst[8]==' \x1b[31mno\x1b[0m ':
                subprocess.call([inst, inst3, "mcstrans"])
                y.add_row(["MCS Translaion Service is not installed",Fore.GREEN +"yes" + Style.RESET_ALL])
        elif lst[8]==' \x1b[32myes\x1b[0m ':
                y.add_row(["MCS Translaion Service is not installed",Fore.GREEN +"yes" + Style.RESET_ALL])
        if lst[9]==' \x1b[31mno\x1b[0m ':
                subprocess.call([inst, "install", "ntp", "-y"], stdout=FNULL)
                y.add_row(["Ensure time synchronisation",Fore.GREEN +"yes" + Style.RESET_ALL])

        elif lst[9]==' \x1b[32myes\x1b[0m ':
                y.add_row(["Ensure time synchronisation",Fore.GREEN +"yes" + Style.RESET_ALL])
        if lst[10]==' \x1b[31mno\x1b[0m ':
                subprocess.call(["systemctl", "disable", "vsftpd", "-q"], stdout=FNULL)
                y.add_row(["FTP server is disabled",Fore.GREEN +"yes" + Style.RESET_ALL])
        elif lst[10]==' \x1b[32myes\x1b[0m ':
                y.add_row(["FTP server is disabled",Fore.GREEN +"yes" + Style.RESET_ALL])

        if lst[11]==' \x1b[31mno\x1b[0m ':
                f=open('/proc/sys/net/ipv4/ip_forward','a+')
                f.write("0")
                f.close()
                y.add_row(["IP forwarding is disabled",Fore.GREEN +"yes" + Style.RESET_ALL])
        elif lst[11]==' \x1b[32myes\x1b[0m ':
                y.add_row(["IP forwarding is disabled",Fore.GREEN +"yes" + Style.RESET_ALL])

        if lst[12]==' \x1b[31mno\x1b[0m ':
                subprocess.call(["sysctl", "-w", "net.ipv4.conf.all.log_martians=1"], stdout=FNULL)
                y.add_row(["suspicous packets are logged",Fore.GREEN +"yes" + Style.RESET_ALL])
        elif lst[12]==' \x1b[32myes\x1b[0m ':
                y.add_row(["suspicous packets are logged",Fore.GREEN +"yes" + Style.RESET_ALL])
        if lst[13]==' \x1b[31mno\x1b[0m ':
                subprocess.call(["sysctl", "-w", "net.ipv4.icmp_echo_ignore_broadcasts=1", "-q"])
                y.add_row(["Broadcast ICMP requests are ignored",Fore.GREEN +"yes" + Style.RESET_ALL])
        elif lst[13]==' \x1b[32myes\x1b[0m ':
                y.add_row(["Broadcast ICMP requests are ignored",Fore.GREEN +"yes" + Style.RESET_ALL])
 #       if lst[14]==' \x1b[31mno\x1b[0m ':
 #               subprocess.call(["umask", "0027"])
 #               y.add_row(["umask is 0027",Fore.GREEN +"yes" + Style.RESET_ALL])
 #       elif lst[14]==' \x1b[32myes\x1b[0m ':
 #               y.add_row(["umask is 0027",Fore.GREEN +"yes" + Style.RESET_ALL])


        print('Done, your machine is now fully secured')
def main():
        print('Wait, checking your system configuration...')
        subprocess.call([inst, "install", "autofs", "-y"], stdout=FNULL)
        subprocess.call([inst, "install", "vsftpd", "-y"], stdout=FNULL)
        status()
        print(x)
        print('Do you want CIS Benchmarks enabled?')
        n=input('Type "1" for yes and "0" for no: ')
        if n.isdigit() and  n==str(1):
                print('Please Wait, configuring your system...')
                enabled()
                print('Current CIS Benchmarks status:')
                print(y)
        elif n.isdigit() and n==str(0):
                print('Ok Thankyou')
                print('Current CIS Benchmarks status:')
                print(x)
        else:
                print('Exiting...')

if __name__=='__main__':
        main()
