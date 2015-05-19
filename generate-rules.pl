#!/usr/bin/perl
##############################
# Oscar Garcia Jr.
# Ver 1.0 12/01/11
#############################


$cur_dir="/usr/local/firewall/intrusion";
#$lock_file="/var/run/firewall";
chomp($cur_dir);

if (!(-e "/var/run/firewall")) {
 `touch /var/run/firewall`;
}
else {
  print "Firewall generator already running!!\n";
  exit;
}

if (!(-e "$cur_dir/ports.open")) {
 print "Can't continue missing ports.open\n";
 exit;
}

if (!(-e "$cur_dir/firewall.temp")) {
 print "Can't continue missing firewall.temp\n";
 exit;
}

if (!(-e "$cur_dir/ports.blocked")) {
 `touch $cur_dir/ports.blocked`;
}

if (!(-e "$cur_dir/ports.unauthorized")) {
 `touch $cur_dir/ports.unauthorized`;
}

if (!(-e "$cur_dir/ports.filtered")) {
 `touch $cur_dir/ports.filtered`;
}

if (!(-e "$cur_dir/icmp.allow")) {
 `touch $cur_dir/icmp.allow`;
}

if (!(-e "$cur_dir/admin.allow")) {
 `touch $cur_dir/admin.allow`;
}

@array_firewall_temp=`cat $cur_dir/firewall.temp`;
@array_ports_open=`cat $cur_dir/ports.open |grep -v '#'`;
@array_ports_unauthorized =`cat $cur_dir/ports.unauthorized|grep -v '#'`;
@array_ports_blocked =`cat $cur_dir/ports.blocked|grep -v '#'`;
@array_ports_filtered=`cat $cur_dir/ports.filtered|grep -v '#'`;
@array_admin_allow=`cat $cur_dir/admin.allow|grep -v '#'`;
@array_icmp_allow=`cat $cur_dir/icmp.allow|grep -v '#'`;

################################
#Get list of admin ip
print "Loading admin rules...\n";
$list_admin_allow="#Set admin inbound\n";
foreach $ip(@array_admin_allow) {
 chomp($ip);
 $ip=&parse_ip($ip);
 if (($ip ne "") && !($ip =~/\#/) && ($ip =~/\d+\.\d+\.\d+\.\d+/)) {
     $list_admin_allow .= "\$IPT -A admin_inbound -p ALL -s $ip -j ACCEPT\n";
 }
}

################################
#Get list of allowed ip for icmp
print "Loading icmp rules...\n";
$list_icmp_allow="#Set icmp packets\n";
foreach $ip(@array_icmp_allow) {
 chomp($ip);
 $ip=&parse_ip($ip);
 if (($ip ne "") && !($ip =~/\#/)) {
     $list_icmp_allow .= "\$IPT -A icmp_packets -p ICMP -s $ip -j ACCEPT\n";
 }
}

###############################
#Get list tcp/udp ports accessible for public net 
print "Loading open ports...\n";
$list_open_ports_tcp="#Set Default Open TCP Ports\n";
$list_open_ports_udp="#Set Default Open UDP Ports\n";
foreach $line(@array_ports_open) {
 chomp($line);
 $line=~s/\s+//g;
 if (($line ne "") && !($line =~/\#/) && ($line=~/\//)) {
   ($proto,$port)=split("/",$line);
   if (($proto eq "tcp") && ($port ne "")) {
     $list_open_ports_tcp .= "\$IPT -A tcp_inbound -p TCP -s 0/0 --destination-port $port -j ACCEPT\n";
   }
   if (($proto eq "udp") && ($port ne "")){
     $list_open_ports_udp .= "\$IPT -A udp_inbound -p UDP -s 0/0 --destination-port $port -j ACCEPT\n";
   } 
 }
}

################################
#Get list tcp/udp ports blocked for public net
print "Loading blocked ports...\n";
$list_blocked_ports_tcp="#Set blocked TCP Ports\n";
$list_blocked_ports_udp="#Set blocked UDP Ports\n";
foreach $line(@array_ports_blocked) {
 chomp($line);
 $line=~s/\s+//g;
 if (($line ne "") && !($line =~/\#/) && ($line=~/\//)) {
   ($proto,$port)=split("/",$line);
   if ($proto eq "tcp") {
     $list_blocked_ports_tcp .= "\$IPT -A tcp_inbound -p TCP -s 0/0 --destination-port $port -j REJECT\n";
   }
   if ($proto eq "udp") {
     $list_blocked_ports_udp .= "\$IPT -A udp_inbound -p UDP -s 0/0 --destination-port $port -j REJECT\n";
   }
 }
}

#################################
#Get list of unauthorized/banned host;
print "Loading banned list...\n";
$list_unauthorized_ports_tcp="#Block TCP Port to unauthorized host\n";
$list_unauthorized_ports_udp="#Block UDP Port to unauthorized host\n";
foreach $line(@array_ports_unauthorized) {
 chomp($line);
 $line=~s/\s+//g;
 if (($line ne "") && !($line =~/\#/) && ($line=~/\//)) {
   ($proto,$port,$hosts_file)=split("/",$line);
   if (!(-e "$cur_dir/$hosts_file")) {
     print "Missing include file for unauthorized host\n";
     exit;
   }
   else {
     @array_list=`cat $cur_dir/$hosts_file|grep -v '#'`;
     foreach $ip(@array_list) { 
       chomp($ip);
       $ip=&parse_ip($ip);
       if (($ip ne "") && !($ip =~/\#/) && ($ip =~/\d+\.\d+\.\d+\.\d+/)) {
         if ($proto eq "tcp") {
          $list_unauthorized_ports_tcp .= "\$IPT -A tcp_inbound -p TCP -s $ip --destination-port $port -j DROP\n";
         }
         if ($proto eq "udp") {
          $list_unauthorized_ports_udp .= "\$IPT -A udp_inbound -p UDP -s $ip --destination-port $port -j DROP\n";
         }
       }
     }
   }
 }
}

#############################
#Get list of filtered tcp/udp ports
print "Loading filtered rules...\n";
$list_filtered_ports_tcp="#Filtered TCP Port to unauthorized host\n";
$list_filtered_ports_udp="#Filtered UDP Port to unauthorized host\n";
foreach $line(@array_ports_filtered) {
 chomp($line);
 $line=~s/\s+//g;
 if (($line ne "") && !($line =~/\#/) && ($line=~/\//)) {
   ($proto,$port,$hosts_file)=split("/",$line);
   if (!(-e "$cur_dir/$hosts_file")) {
     print "Missing include file for filtered host\n";
     exit;
   }
   else {
     @array_list=`cat $cur_dir/$hosts_file|grep -v '#'`;
     foreach $ip(@array_list) {
       chomp($ip);
        $ip=&parse_ip($ip);
       if (($ip ne "") && !($ip =~/\#/) && ($ip =~/\d+\.\d+\.\d+\.\d+/)) {
         if ($proto eq "tcp") {
          $list_filtered_ports_tcp .= "\$IPT -A tcp_inbound -p TCP -s $ip --destination-port $port -j ACCEPT\n";
         }
         if ($proto eq "udp") {
          $list_filtered_ports_udp .= "\$IPT -A udp_inbound -p UDP -s $ip --destination-port $port -j ACCEPT\n";
         }
       }
     }
   }
 }
}

######################################
#Assemble the rules
print "Constructing new rules..\n";
open data,">$cur_dir/iptables-rules";
foreach $ipt_rule(@array_firewall_temp) {
 print data $ipt_rule;

 if ($ipt_rule =~/\#custom_admin_inbound/){
  print data $list_admin_allow;  
 }

 if ($ipt_rule =~/\#icmp_packets chain/){
  print data $list_icmp_allow;
 }

 if ($ipt_rule =~/\#custom_tcp_inbound/) {
  print data $list_unauthorized_ports_tcp;
  print data $list_filtered_ports_tcp;
  print data $list_open_ports_tcp;
  print data $list_blocked_ports_tcp;
 }
 if ($ipt_rule =~/\#custom_udp_inbound/) {
  print data $list_unauthorized_ports_udp;
  print data $list_filtered_ports_udp;
  print data $list_open_ports_udp;
  print data $list_blocked_ports_udp;
 } 
}
close data;
#########################################
#Update running rules
`chmod u+x $cur_dir/iptables-rules`;
print "Activating new firewall settings\n";
`$cur_dir/iptables-rules`;
print "Removing lock file\n";
`rm -rf $lock_file`;

sub parse_ip() {
  if ($_[0] =~/\/\d+/) {
    $_[0]=~s/^(.*?)((\d+\.){3}\d+\/\d+).*?$/$2/;
  }
  else {
    $_[0]=~s/^(.*?)((\d+\.){3}\d+).*?$/$2/;
  }
  return $_[0];
}
