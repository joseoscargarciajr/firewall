#!/usr/bin/perl
# Check Intruders
# Created by Oscar Garcia Jr.
# 12/01/11

%list_ip=();
%list_denied=();
%list_allowed=();
$limit_score=6;

$today =`date +"%b %e"`;
$cur_dir="/usr/local/firewall/intrusion";
chomp($cur_dir);
chomp($today);

if (!(-e "$cur_dir/host.deny")) {
 `touch $cur_dir/host.deny`;
}

if (!(-e "$cur_dir/host.allow")) {
 `touch $cur_dir/host.allow`;
}

`cat $cur_dir/host.deny > $cur_dir/tmp.deny`;

@array_denied_ip=`cat $cur_dir/host.deny`;
@array_allowed_ip =`cat $cur_dir/host.allow`;

foreach $line(@array_allowed_ip) {
 chomp($line);
 if ($line ne "") {
   $list_allowed{$line}=1;
 }
}

foreach $line(@array_denied_ip) {
 chomp($line);
 if (($line ne "") && !(exists($list_allowed{$line}))){
   $list_denied{$line}=1;
 }
}

@array_list=`cat /var/log/messages |grep "$today" | grep sshd | grep "Failed password"`;
foreach $line(@array_list) {
 chomp($line);
 $ip=$line;
 $ip=~s/^(.*?)((\d+\.){3}\d+).*?$/$2/;
 if ($list_ip{$ip} == "") {
   $list_ip{$ip}= 1;
 }
 else {
   ++$list_ip{$ip};
 }
}

foreach $ip(keys (%list_ip)) {
  $hit_score = $list_ip{$ip};
  print "$ip = $hit_score\n";
  if (($hit_score >= $limit_score) && !(exists($list_allowed{$ip}))) {
   $list_denied{$ip}=1;
  }
}

print "Denied IP's\n";
$denied_ips=join("\n",sort(keys (%list_denied)));
`echo "$denied_ips" > $cur_dir/host.deny`;
print "$denied_ips\n";

$stat=`/usr/bin/diff $cur_dir/host.deny $cur_dir/tmp.deny`;
if ($stat != "") {
  print "Block the list\n";
  `$cur_dir/generate-rules.pl`;
}
else {
  print "No new host to block\n";
}



