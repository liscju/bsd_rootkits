#!/usr/local/bin/perl

if (@ARGV < 1) {
	print "\nUsage: invoke_syscall.pl <str>";
	exit;
}

$str = $ARGV[0];
$syscall_id = 210;
syscall($syscall_id, $str);
