#!/usr/bin/perl
use POSIX qw/strftime/;

my $t = strftime("%Y%m%d%H%m%s", localtime);

system(qq[java -jar ctca/target/jmh-benchmarks.jar benchmarkDefault | tee result/default-$t.log]);
system(qq[java -jar ctca/target/jmh-benchmarks.jar benchmarkCTCA | tee result/ctca-$t.log]);
