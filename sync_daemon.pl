#!/usr/bin/perl

# This software was written by Philipp Wuensche <cryx-otsync@h3q.com>
# It is considered beerware.

use strict;

#use Convert::Bencode_XS qw(:all);
use Convert::Bencode qw(:all);
use Data::Dumper;
use LWP::UserAgent;
use URI::Escape;

# enable verbose output
my $debug = 0;

# tracker from where we get our sync data
my @trackers = ('127.0.0.1:8989');
# tracker to upload merged data
my @client_tracker = ('127.0.0.1:8989');

# time to wait between syncs
my $sleeptime = '300';

# SSL cert and key
my $ssl_cert = 'cert.pem';
my $ssl_key = 'key.pem';

foreach(@trackers) {
        print "Syncing from: $_\n";
}
foreach(@client_tracker) {
        print "Syncing to: $_\n";
}

my $file = shift;


# global hash for storing the merged syncs
my %merged_syncs;

while(1) {
        %merged_syncs;
        my @bencoded_sync_data;

        # fetch the sync from every tracker and put it into an array in bencoded form
        foreach my $tracker (@trackers) {
                my $bencoded_sync = fetch_sync($tracker);
#               my $bencoded_sync = fetch_sync_from_file($file);
                if($bencoded_sync ne 0 && $bencoded_sync =~ /^d4\:sync/) {
                        push(@bencoded_sync_data,$bencoded_sync);
                }
        }

        # bdecode every sync and throw it into the merged-sync
        foreach my $bencoded_sync (@bencoded_sync_data) {
                print "Doing merge...\n";
                merge_sync(bdecode($bencoded_sync));
                my $num_torrents = keys(%merged_syncs);

                print "number of torrents: $num_torrents\n";
        }

        # number of max. peers in one changeset
        my $peer_limit = 500;
        # max number of changesets per commit
        my $max_changesets = 10;
        my $hash_count = 0;
        my $peer_count = 0;
        my $changeset;
        my @escaped_changesets;

        # run until all hashes are put into changesets and commited to the trackers
        while(keys(%merged_syncs) != 0) {

                foreach my $hash (keys(%merged_syncs)) {
                        print "Starting new changeset\n" if($peer_count == 0 && $debug);
                        my $num_peers = keys(%{$merged_syncs{$hash}});

                        print "\t$peer_count peers for $hash_count hashes in changeset\n" if($debug);

                        my $pack_hash = pack('H*',$hash);

                        # as long as the peer_limit is not reached, add new hashes with peers to the changeset hash-table
                        if($peer_count < $peer_limit) {
                                print "\t\tAdd $num_peers peers for $hash changeset\n" if($debug);
                                $peer_count = $peer_count + $num_peers;
                                foreach my $peer_socket (keys(%{$merged_syncs{$hash}})) {

                                        my $flags = $merged_syncs{$hash}{$peer_socket};

                                        print "\t\t\tAdd $peer_socket $flags\n" if($debug);

                                        my $pack_peer = packme($peer_socket,$flags);

                                        $changeset->{'sync'}->{$pack_hash} = $changeset->{'sync'}->{$pack_hash}.$pack_peer;
                                }
                                $hash_count++;
                                # hash is stored in the changeset, delete it from the hash-table
                                delete $merged_syncs{$hash};
                        }

                        # the peer_limit is reached or we are out of torrents, so start preparing a changeset
                        if($peer_count >= $peer_limit || keys(%merged_syncs) == 0) {

                                print "Commit changeset for $hash_count hashes with $peer_count peers total\n" if($debug);

                                # bencode the changeset
                                my $enc_changeset = bencode($changeset);

                                # URL-escape the changeset and put into an array of changesets
                                my $foobar = uri_escape($enc_changeset);
                                push(@escaped_changesets,$foobar);

                                # the changeset is ready and stored, so delete it from the changeset hash-table
                                delete $changeset->{'sync'};

                                $hash_count = 0;
                                $peer_count = 0;
                                print "\n\n\n" if($debug);
                        }

                        # if enought changesets are prepared or we are out of torrents for more changesets,
                        # sync the changesets to the trackers
                        if($#escaped_changesets == $max_changesets || keys(%merged_syncs) == 0) {
                                print "\tSync...\n";
                                sync_to_tracker(\@escaped_changesets);
                                undef @escaped_changesets;
                        }

                }
        }

        print "Sleeping for $sleeptime seconds\n";
        sleep $sleeptime;
}

sub connect_tracker {
        # connect a tracker via HTTPS, returns the body of the response
        my $url = shift;

        $ENV{HTTPS_DEBUG} = 0;
        $ENV{HTTPS_CERT_FILE} = $ssl_cert;
        $ENV{HTTPS_KEY_FILE}  = $ssl_key;

        my $ua = new LWP::UserAgent;
        my $req = new HTTP::Request('GET', $url);
        my $res = $ua->request($req);

        my $content = $res->content;

        if($res->is_success()) {
                return $content;
        } else {
                print $res->code."|".$res->status_line."\n";
                return 0;
        }
}

sub sync_to_tracker {
        # commit changesets to a tracker
        my @changesets = @{(shift)};

        # prepare the URI with URL-encoded changesets concatenated by a &
        my $uri = 'sync?';
        foreach my $set (@changesets) {
                $uri .= 'changeset='.$set.'&';
        }
        my $uri_length = length($uri);

        # commit the collection of changesets to the tracker via HTTPS
        foreach my $tracker (@client_tracker) {
                print "\t\tTracker: $tracker (URI: $uri_length)\n";
                my $url = "https://$tracker/".$uri;
                connect_tracker($url);
        }
}

sub packme {
        # pack data
        # returns ipaddr, port and flags in packed format
        my $peer_socket = shift;
        my $flags = shift;

        my($a,$b,$c,$d,$port) = split(/[\.,\:]/,$peer_socket);
        my $pack_peer = pack('C4 n1 b16',$a,$b,$c,$d,$port,$flags);

        return $pack_peer;
}

sub unpackme {
        # unpack packed data
        # returns ipaddr. in quad-form with port (a.b.c.d:port) and flags as bitfield
        # data is packed as:
        # - 4 byte ipaddr. (unsigned char value)
        # - 2 byte port (unsigned short in "network" (big-endian) order)
        # - 2 byte flags (bit string (ascending bit order inside each byte))
        my $data = shift;

        my($a, $b, $c, $d, $port, $flags) = unpack('C4 n1 b16',$data);
        my $peer_socket = "$a\.$b\.$c\.$d\:$port";

        return($peer_socket,$flags);
}

sub fetch_sync {
        # fetch sync from a tracker
        my $tracker = shift;
        my $url = "https://$tracker/sync";

        print "Fetching from $url\n";

        my $body = connect_tracker($url);

        if($body && $body =~ /^d4\:sync/) {
                return $body;
        } else {
                return 0;
        }
}

sub fetch_sync_from_file {
        # fetch sync from a file
        my $file = shift;
        my $body;
        print "Fetching from file $file\n";
        open(FILE,"<$file");
        while(<FILE>) {
                $body .= $_;
        }
        close(FILE);
        return $body;
}

sub merge_sync {
        # This builds a hash table with the torrenthash as keys. The value is a hash table again with the peer-socket as keys
        # and flags in the value
        # Example:
        # 60dd2beb4197f71677c0f5ba92b956f7d04651e5 =>
        #       192.168.23.23:2323 => 0000000000000000
        #       23.23.23.23:2342 => 0000000100000000
        # b220b4d7136e84a88abc090db88bec8604a808f3 =>
        #       42.23.42.23:55555 => 0000000000000000

        my $hashref = shift;
 
        my $nonuniq_hash_counter = 0;
        my $nonuniq_peer_counter = 0;
        my $hash_counter = 0;
        my $peer_counter = 0;

        foreach my $key (keys(%{$hashref->{'sync'}})) {
                # start merge for every sha1-hash in the sync
                my $hash = unpack('H*',$key);

                $hash_counter++;
                $nonuniq_hash_counter++ if exists $merged_syncs{$hash};

                while(${$hashref->{'sync'}}{$key} ne "")
                {
                        # split the value into 8-byte and unpack it for getting peer-socket and flags
                        my($peer_socket,$flags) = unpackme(substr(${$hashref->{'sync'}}{$key},0,8,''));

                        $peer_counter++;
                        $nonuniq_peer_counter++ if exists $merged_syncs{$hash}{$peer_socket};

                        # Create a hash table with sha1-hash as key and a hash table as value.
                        # The hash table in the value has the peer-socket as key and flags as value
                        # If the entry already exists, the flags are ORed together, if not it is ORed with 0
                        $merged_syncs{$hash}{$peer_socket} = $flags | $merged_syncs{$hash}{$peer_socket};
                }
        }
        print "$hash_counter hashes $nonuniq_hash_counter non-uniq, $peer_counter peers $nonuniq_peer_counter non-uniq.\n";

}

sub test_decode {
        my $hashref = shift;

        print "CHANGESET DEBUG OUTPUT\n";

        print Dumper $hashref;
        foreach my $key (keys(%{$hashref->{'sync'}})) {
                my $hash = unpack('H*',$key);

                print "Changeset for $hash\n";
                while(${$hashref->{'sync'}}{$key} ne "")
                {

                        my($peer_socket,$flags) = unpackme(substr(${$hashref->{'sync'}}{$key},0,8,''));
                        print "\tSocket: $peer_socket Flags: $flags\n";
                }
        }
}
