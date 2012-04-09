#!/usr/bin/perl
package snmproute;

use strict;
use warnings;

use Net::SNMP;
use Net::SNMP::Mixin;
use Getopt::Long qw(GetOptionsFromArray);

my %actions = (
    view => {
        opts => [ qw(target=s port=i version=s cidr) ],
        handler =>\&action_view,
    },
);

run(@ARGV) unless caller();

sub run
{
    my $action = shift;
    my %opts = ();

    return usage() if (!defined $action || !defined $actions{$action});

    GetOptionsFromArray(\@_, \%opts,  @{ $actions{ $action }->{opts} });

    # Some common option checks
    die "You must specify target\n" if !defined $opts{target};
    die "Sorry SNMPv3 not supported yet\n" 
        if defined $opts{version} && $opts{version} == 3;

    # Call action handler
    $actions{ $action }->{handler}->(%opts);
}

sub action_view
{
    my (%opts) = @_;

    my ($manager, $error) = Net::SNMP->session(
        hostname    => $opts{target},
        port        => delete $opts{port} || 161,
        version     => delete $opts{version} || 1,
    );
    die $error if !defined $manager ;
    $manager->mixer('Net::SNMP::Mixin::IfInfo');

    # Easy enough, get table -> dump table
    if (defined $opts{cidr}) {
        $manager->mixer('Net::SNMP::Mixin::IpCidrRouteTable');
        $manager->init_mixins();
        die $manager->errors(1) if $manager->errors;

        _dump_ipCidrRouteTable(
            $manager->get_ip_cidr_route_table(), 
            $manager->get_if_entries()
        );
    } 
    else {
        $manager->mixer('Net::SNMP::Mixin::IpRouteTable');
        $manager->init_mixins();
        die $manager->errors(1) if $manager->errors;

        _dump_ipRouteTable(
            $manager->get_ip_route_table(), 
            $manager->get_if_entries()
        );
    }
    $manager->close();
}

sub _dump_ipCidrRouteTable
{
    my $ifdb = pop;
    my @rt = @_; 

    printf "%-15s %-15s %-15s %-8s %-8s %-8s %-8s %-8s %-8s %-8s\n", 
        qw(Dest GW Mask Type Metric Status Proto HopAS ToS Iface);
    for my $entry (@rt) {
        printf "%-15s %-15s %-15s %-8s %-8s %-8s %-8s %-8s %-8s %-8s\n", 
            @{ $entry }{qw(ipCidrRouteDest ipCidrRouteNextHop ipCidrRouteMask 
                        ipCidrRouteTypeString ipCidrRouteMetric1 
                        ipCidrRouteStatusString ipCidrRouteProtoString 
                        ipCidrRouteNextHopAS ipCidrRouteTos)}, 
            $ifdb->{ $entry->{ipCidrRouteIfIndex} }->{ifName};
    }

}

sub _dump_ipRouteTable
{
    my $ifdb = pop;
    my @rt = @_; 

    printf "%-15s %-15s %-15s %-8s %-8s %-8s %-8s\n", 
        qw(Dest GW Mask Type Metric Proto Iface);
    for my $entry (@rt) {
        printf "%-15s %-15s %-15s %-8s %-8s %-8s %-8s\n", 
            @{ $entry }{qw(ipRouteDest ipRouteNextHop ipRouteMask 
                        ipRouteTypeString ipRouteMetric1 ipRouteProtoString)}, 
            $ifdb->{ $entry->{ipRouteIfIndex} }->{ifName};
    }
}

sub usage
{
    print <<USAGE
snmproute.pl view [-t|--target] TARGET [-p|--port PORT] [-v|--version VERSION] [-c|--cidr]
snmproute.pl add [-t|--target] TARGET [-p|--port PORT] [-v|--version VERSION]
snmproute.pl del [-t|--target] TARGET [-p|--port PORT] [-v|--version VERSION] 
USAGE
}

1;
