#!/usr/bin/perl
use strict;

use Digest::MD5 'md5_base64';

$| = 1;

sub write_header {
    my($out_fname) = @_;
    open(OUT, ">$out_fname") or die "Can't open $out_fname for writing: $!";

    # TEMU state magic number
    print OUT "\xfe\xff\xfe\xff";

    # TEMU state version number 20
    print OUT pack("L", 20);

    my($ebx, $ecx, $edx, $esi, $edi, $ebp, $eax, $xds, $xes, $xfs, $xgs,
       $orig_eax, $eip, $xcs, $eflags, $esp, $xss) = (0) x 17;
   # Hardcode FS to 0xd8
   # TODO: Add options to set registers
    my($xfs) = 0xd8;
    my($eflags) = 0x287;
    printf "EAX: 0x%08x    EBX: 0x%08x\n", $eax, $ebx;
    printf "ECX: 0x%08x    EDX: 0x%08x\n", $ecx, $edx;
    printf "ESI: 0x%08x    EDI: 0x%08x\n", $esi, $edi;
    printf "ESP: 0x%08x    EBP: 0x%08x\n", $esp, $ebp;

    printf "EIP: 0x%08x\n", $eip;
    printf "EFLAGS: 0x%x (%b)\n", $eflags, $eflags;

    printf "SS: 0x%04x   CS: 0x%04x   DS: 0x%04x\n", $xcs, $xds, $xss;
    printf "ES: 0x%04x   FS: 0x%04x   GS: 0x%04x\n", $xes, $xfs, $xgs;
    print OUT pack("L17", $ebx, $ecx, $edx, $esi, $edi, $ebp, $eax,
		   $xds, $xes, $xfs, $xgs,
		   $orig_eax, $eip, $xcs, $eflags, $esp, $xss);
}

my $zero_page = "\0" x 4096;

my %common =
  (
   # First try:
   # "XsMbesJY9ZXPSi+5bbIk5A" => 1,

   "TUHAMtZPiPtzLKjXwkWHXQ" => 1,
   "/Q1+lPuwHkqjcnjCx/TJaA" => 1,
  );

sub process_raw {
    my($raw_fname, $start_addr) = @_;

    open(RAW, "<$raw_fname") or die "Can't open $raw_fname: $!";

    my $start_addr = hex($start_addr);

    my $data;
    my $addr = $start_addr;
    while (read(RAW, $data, 4096)) {
	my $md5 = md5_base64($data);
	if ($data eq $zero_page or $common{$md5}) {
	    print "." unless $addr & 0x000fffff;
	} else {
	    my($first, $last) = ($addr, $addr + 4095);
	    my $header = pack("LL", $first, $last);
	    printf "0x%08x-0x%08x $md5:\n", $first, $last;
	    print OUT $header, $data;
	}
	$addr += 4096;
    }
}

if (@ARGV == 3) {
    write_header($ARGV[2]);
    process_raw($ARGV[0], $ARGV[1]);
} elsif (@ARGV == 5) {
    write_header($ARGV[4]);
    process_raw($ARGV[0], $ARGV[1]);
    process_raw($ARGV[2], $ARGV[3]);
} else {
    die "Usage: raw-to-state.pl (in.raw 0xSTARTADDR){1,2} out.state";
}

