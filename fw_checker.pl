#!/usr/bin/perl
# Firewall Checker v1.0
# Created by: Oscar Garcia Jr.
# 12/01/11

$lock_file="/var/run/firewall";
$fw="/usr/local/firewall/intrusion/iptables-rules";
$test=`/sbin/iptables -L -n |grep "ACCEPT.* tcp dpt\:22"|wc -l`;
$rules=`cat $fw |grep "destination-port 22" |grep ACCEPT |wc -l`;
$hostname=`hostname`;
$date=`date`;
$admin="cyber_etomac\@yahoo.com";

chomp($test);
chomp($rules);
chomp($date);
chomp($hostname);

if ($test ne $rules) {
print "Firewall is down!!!\n";
}  
  elsif (!(-e "/var/run/firewall")) {
      print "Starting the Firewall !!!\n";
     `$fw`;
  
  `echo "$hostname fw rules changed at $date" |mail -s "$hostname fw altered $date" $admin`;
}
else {
  print "Firewall is up\n";
}

