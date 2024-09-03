#!/usr/bin/perl
use strict;
use warnings;

my $dir ="."; 

my @doms = qw/www.ccb.com 
cmbchina.com
www.icbc.com.cn
www.boc.cn
www.abchina.com
www.hxb.com.cn
www.psbc.com
www.citicbank.com
www.cebbank.com
www.spdb.com.cn
www.bankcomm.com
www.cib.com.cn
www.cgbchina.com.cn
bank.pingan.com
www.cmbc.com.cn
/;


system(qq[crip print -f pem -u=https://$_ >$dir/$_.pem]) for @doms;
system(qq[crip print -u=https://$_ >$dir/$_.txt]) for @doms;
