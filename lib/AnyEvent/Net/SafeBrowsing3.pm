package AnyEvent::Net::SafeBrowsing3;

use strict;
use warnings;

use Carp;
use URI;
use Digest::SHA qw(sha256);
use List::Util qw(first);
use MIME::Base64;
use IO::Socket::SSL;
use AnyEvent;
use AnyEvent::Net::SafeBrowsing3::Data;
use AnyEvent::Net::SafeBrowsing3::Storage;
use AnyEvent::Net::SafeBrowsing3::Utils;
use Mouse;
use AnyEvent::HTTP;
use Google::ProtocolBuffers;

our $VERSION = '3.61';

=head1 NAME

AnyEvent::Net::SafeBrowsing3 - AnyEvent Perl extension for the Safe Browsing v3 API.

=head1 SYNOPSIS

  use AnyEvent;
  use AnyEvent::Net::SafeBrowsing3;
  use AnyEvent::Net::SafeBrowsing3::Tarantool;

  my $cv = AnyEvent->condvar;
  
  my $storage = AnyEvent::Net::SafeBrowsing3::Tarantool->new({
    host              => 'tarantool.host', 
    port              => '33013', 
    a_chunks_space    => 0, 
    s_chunks_space    => 1, 
    full_hashes_space => 2
  });
  $storage->dbh->connect();

  my $sb = AnyEvent::Net::SafeBrowsing3->new({
    server => "http://safebrowsing.google.com/safebrowsing/", 
    key => "key";
    storage => $storage,
  });

  $sb->update(['goog-malware-shavar'], sub {warn "Next hop after ".$_[0], $cv->send()});
  $cv->recv;

  $storage->close();

=head1 DESCRIPTION

AnyEvent::Net::SafeBrowsing3 implements the Google Safe Browsing v3 API.

The library passes most of the unit tests listed in the API documentation. See the documentation (L<https://developers.google.com/safe-browsing/developers_guide_v3>) for more details about the failed tests.

The Google Safe Browsing database must be stored and managed locally. L<AnyEvent::Net::SafeBrowsing3::Tarantool> uses Tarantool as the storage back-end. Other storage mechanisms (databases, memory, etc.) can be added and used transparently with this module.

If you do not need to inspect more than 10,000 URLs a day, you can use L<AnyEvent::Net::SafeBrowsing3::Lookup> with the Google Safe Browsing v3 Lookup API which does not require to store and maintain a local database. Use AnyEvent::Net::SafeBrowsing3::Empty for this one.

IMPORTANT: If you start with an empty database, you will need to perform several updates to retrieve all the Google Safe Browsing information. This may require up to 24 hours. This is a limitation of the Google API, not of this module.

=cut

=head1 CONSTRUCTOR

=over 4

=back

=head2 new()

Create an AnyEvent::Net::SafeBrowsing3 object

  my $sb = AnyEvent::Net::SafeBrowsing3->new({
      server => "https://safebrowsing.google.com/safebrowsing/",
      key => "afaf1234......",
      storage => AnyEvent::Net::SafeBrowsing3::Tarantool->new(...),
      log_class => 'MyProject::MyLog',
      data_filepath => '/tmp/safebrowsing_data',
      cache_time => 45*60,
})

Arguments

=over 4

=item server

Required. Safe Browsing Server.

=item key

Required. Your Safe browsing API key

=item storage

Required. Object which handles the storage for the Safe Browsing database (instance of AnyEvent::Net::SafeBrowsing3::Empty by default). See L<AnyEvent::Net::SafeBrowsing3::Storage> for more details.

=item version

Optional. Safe Browsing version. 3.0 by default

=item log_class

Optional. Name of class for writing a log. Default is 'AnyEvent::Net::SafeBrowsing3::Log'

=item data_filepath

Optional. Path to a scratch file where safebrowsing will store its ancillary data. Default is '/tmp/safebrowsing_data3' 

=item http_timeout 

Optional. Timeout for request to Safe Browsing service. Measured in seconds. Default 60 sec

=item user_agent

Optional. User agent which will be received  SafeBrowsing service. Default "AnyEvent::Net::SafeBrowsing3 client $VERSION"

=item cache_time

Optional. For how many seconds full hashes data is cached. If cache_time isn't set then values recieved from SafeBrowsing service will be used  

=item default_retry

Optional. Retry timeout after unknown fail. Measured in seconds. Default 30 sec

=back

=cut

has server       => (is => 'rw', isa => 'Str', required => 1 );
has key          => (is => 'rw', isa => 'Str', required => 1 );
has storage      => (is => 'rw', isa => 'Object', default => sub {AnyEvent::Net::SafeBrowsing3::Empty->new()});
has version      => (is => 'rw', isa => 'Str', default => '3.0' );
has log_class    => (is => 'rw', isa => 'Str', default => 'AnyEvent::Net::SafeBrowsing3::Log' );
has data         => (is => 'rw', isa => 'Object');
has data_filepath=> (is => 'rw', isa => 'Str', default => '/tmp/safebrowsing_data3' );
has in_update    => (is => 'rw', isa => 'Int');
has force        => (is => 'rw', isa => 'Bool', default => '0');
has http_timeout => (is => 'ro', isa => 'Int', default => 60);
has user_agent   => (is => 'rw', isa => 'Str', default => 'AnyEvent::Net::SafeBrowsing3 client '.$VERSION );
has cache_time   => (is => 'ro', isa => 'Int');
has default_retry=> (is => 'ro', isa => 'Int', default => 30);

=head1 PUBLIC FUNCTIONS

=over 4

=back

=head2 update()

Performs a database update.

  $sb->update($list, $callback);
  $sb->update(['goog-malware-shavar', 'googpub-phish-shavar'], sub {});

Returns the time of next hop to update database.

This function can handle two lists at the same time. If one of the list should not be updated, it will automatically skip it and update the other one. It is faster to update two lists at once rather than doing them one by one.

NOTE: If you start with an empty database, you will need to perform several updates to retrieve all Safe Browsing information. This may require up to 24 hours. This is a limitation of API, not of this module.

Arguments

=over 4

=item list

Required. Reference to array that contains list names.

=item callback

Required. Callback function that will be called after database is updated.

=back

=cut

sub update {
    my ($self, $list, $cb_ret) = @_;
    die "Required callback" unless $cb_ret;
    return unless $list;
    if( $self->in_update() ){
        # Already in update status, next try after 30 sec 
        $cb_ret->( $self->default_retry() );
        return;
    }
    $self->in_update( scalar @$list );
    my $mwait;
    my $cb = sub {
        my ($wait) = @_;
        $mwait = $wait if !$mwait || $wait < $mwait;
        $self->in_update( $self->in_update()-1 );
        log_debug2( "In update: ".$self->in_update() );
        $cb_ret->($mwait) unless $self->in_update();
    };
    foreach my $item ( @$list ){
        my $info = $self->data->get('updated/'.$item);
        log_info( "Update info: ", $info );
        if(!$info || $info->{'time'} + $info->{'wait'} < AE::now() || $self->force ) {
            # OK to update list info
            log_info("OK to update $item: " . AE::now() . "/" . 
                    ($info ? $info->{'time'} +  $info->{'wait'} : 'first update'));
            my $do_request = sub {
                $self->storage->get_regions(list => $item, cb => sub {
                    my($a_range, $s_range) = @_;
                    unless( defined $a_range ){
                        log_error( 'Get range error' );
                        $cb->($self->default_retry());
                        return;
                    }

                    # request body
                    # examples:
                    #     googpub-phish-shavar;a:1-3,5,8:s:4-5
                    #     googpub-phish-shavar;a:1-5
                    #     googpub-phish-shavar;

                    my $max_request_length = 4096;
                    my $rest_request_length = $max_request_length;
                    $rest_request_length -= 1;             # symbol \n in end of body
                    
                    my $body = "$item;";
                    $rest_request_length -= length($body);
                    my $prefix = "a:";
                    my $prefix_s = ($a_range ne '' ? ":" : "")."s:";
                    my $min_size;
                    my $last_id;
                    if ($s_range ne '' ){
                        if($s_range =~ /[,\-]/){
                            # more than one id
                            die "Bad a_range format" unless $s_range =~ /^(\d+).*?(\d+)$/;
                            my $first_id = $1;
                            $last_id = "-".$2;
                            $min_size = length($prefix_s) + length($first_id) + length($last_id);
                        }
                        else{
                            $min_size = length($prefix_s) + length($s_range);
                        }
                    }
                    if ($a_range ne '') {
                        my $more_than_rest = $rest_request_length - length($a_range) - length($prefix) - ($s_range ? length($prefix_s)+$min_size : 0);
                        if( $more_than_rest < 0 ){
                            die "Bad a_range format" unless $a_range =~ /(\d+)$/;
                            my $last_id = "-".$1;
                            substr($a_range, $more_than_rest-length($last_id), -$more_than_rest+length($last_id), '');
                            $a_range =~ s/(?:((?:^|,)\d+)(\-\d+)?,\d*|\-\d*)$/($1||"").$last_id/e;
                        }
                        my $chunks_list = $prefix.$a_range;
                        $rest_request_length -= length($chunks_list);
                        $body .= $chunks_list;
                    }
                    if ($s_range ne '' ){
                        if( $min_size < $rest_request_length ){
                            # min_size less than rest_length
                            my $more_than_rest = $rest_request_length - length($s_range) - length($prefix_s);
                            if( $more_than_rest < 0 ){
                                substr($s_range, $more_than_rest-length($last_id), -$more_than_rest+length($last_id), '');
                                $s_range =~ s/(?:((?:^|,)\d+)(\-\d+)?,\d*|\-\d*)$/($1||"").$last_id/e;
                            }
                            my $chunks_list = $prefix_s.$s_range;
                            $rest_request_length -= length($chunks_list);
                            $body .= $chunks_list;
                        }
                    }
                    $body .= "\n";
                    die "Request length more than $max_request_length: ".length( $body ) if length( $body ) > $max_request_length;

                    # request URL
                    my $url = $self->server . "downloads?client=api&key=" . $self->key
                                            . "&appver=$VERSION&pver=" . $self->version;
                    log_debug1( "Url: ".$url );
                    log_debug1( "Body: ".$body );
                    http_post( $url, $body, %{$self->param_for_http_req}, sub {
                        my ($data, $headers) = @_; 
                        if( $headers->{Status} == 200 ){
                            if( $data ){
                                log_debug3("Response body: ".$data);
                                $self->process_update_data( $data, $cb );
                                }
                            else {
                                $cb->($self->default_retry());
                            }
                        }
                        else {
                            log_error("Bad response from server ".$headers->{Status} );
                            $self->update_error($item, $cb);
                        }
                        return;
                    });
                    return;
                });
                return;
            };

            $do_request->();
            
        }
        else {
            log_info("Too early to update $item");
            $cb->(int($info->{'time'} + $info->{'wait'}-AE::now()));
        }
    }
    return;
}

=head2 force_update()

Performs a force database update.

  $sb->force_update($list, $callback);
  $sb->force_update(['goog-malware-shavar', 'googpub-phish-shavar'], sub {});

Returns the time of next hop to update db

Be careful if you call this method  because too frequent updates might result in the blacklisting of your API key.

Arguments

=over 4

=item list

Required. Reference to array that contains list names.

=item callback

Required. Callback function that will be called after database is updated.

=back

=cut

sub force_update {
    my $self = shift;
    $self->force(1);
    $self->update(@_);
    $self->force(0);
    return;
}

=head2 lookup()

Lookups a URL against the Safe Browsing database.

  my $match = $sb->lookup(list => ['goog-malware-shavar,googpub-phish-shavar'], url => 'http://www.gumblar.cn', cb => sub {});

Returns the name of the list if there is any match, returns an empty string otherwise.

Arguments

=over 4

=item list

Required. Lookup against specific list names. Should be a reference to array.

=item url

Required. URL to lookup.

=item callback

Required. Callback function that will be called after lookup is performed.

=back

=cut

sub lookup {
    my ($self, %args)   = @_;
    my $lists           = $args{list}       or die "List arg is required";
    my $url             = $args{url}        or die "URL is required";
    my $cb              = $args{cb}         or die "Callback is required";

    # TODO: create our own URI management for canonicalization
    # fix for http:///foo.com (3 ///)
    $url =~ s/^(https?:\/\/)\/+/$1/;

    my $uri = URI->new($url)->canonical;
    die "Bad url ".$url if $uri->scheme !~ /^https?$/;
    
    # compute full hashes (32b) and prefixes (4b) for all canonical combinations of URLs (domain + path). result is  in binary
    my @full_hashes = $self->full_hashes($uri);
    my @full_hashes_prefix = map (substr($_, 0, 4), @full_hashes);
    
    # check if any prefix (4 bytes long) match with local database.
    # prefix in match is a hex string (because prefixes are stored in databse like hex strings)
    # returns a reference to array of add chunks to callback
    
    foreach my $prefix (@full_hashes_prefix) {
        $self->local_lookup_prefix(lists => $lists, prefix => sprintf("%x", unpack('N', $prefix)), cb => sub {
            my $add_chunks = shift;
            unless( scalar @$add_chunks ){
                $cb->([]);
                return;
            }
            
            # if any prefix matches with local database, check for full hashes stored locally
            # preliminary declarations
            my $found = [];
            my $processed = 0;
            my $watcher = sub {
                my $list = shift;
                push @$found, $list if $list;  
                $processed++;
                if($processed == @$add_chunks){
                    if( $found ){
                        $cb->($found);
                    }
                    else {
                        log_debug2("No match");
                        $cb->([]);
                    }
                }
            };
    
            # get stored full hashes
            # returns a reference to array of full hashes found to callback
            foreach my $add_chunk (@$add_chunks) {
               $self->storage->get_full_hashes( prefix => $add_chunk->{prefix}, timestamp => time(), list => $add_chunk->{list}, cb => sub {
                   my $hashes = shift;
                   if( @$hashes ){
                       log_debug2("Full hashes already stored for prefix " . $add_chunk->{prefix} . ": " . scalar @$hashes);
                       my $fnd = '';
                       log_debug1( "Searched hashes: ", \@full_hashes );
                   
                       # find match between our computed full hashes and full hashes retrieved from local database
                       foreach my $full_hash (@full_hashes) {
                           foreach my $hash (@$hashes) {
                               if ($hash->{hash} eq $full_hash && defined first { $hash->{list} eq $_ } @$lists) {
                                   log_debug2("Full hash was found in storage: ", $hash);
                                   $fnd = $hash->{list};
                               }
                           }
                       }
                       $watcher->($fnd);
                   }
                   else {
                       # ask Google for new hashes
                       # TODO: make sure we don't keep asking for the same over and over
                       $self->request_full_hash(prefixes => [ map(pack( 'H*', $_->{prefix}), @$add_chunks) ], cb => sub {
                           my $hashes = shift;
                           my $debug_string = '';
                           for my $line (@$hashes) { $debug_string .= "prefix:" . unpack('H*', $line->{prefix}) . 
                                                                      " hash:" . unpack('H*', $line->{hash}) . 
                                                                      " list:" . $line->{list} . " timestamp:". $line->{timestamp} . " " }
                           log_debug1( "Full hashes: ". $debug_string);
                           $self->storage->add_full_hashes(full_hashes => $hashes, cb => sub {});
                       
                           # check for new full hashes
                           # preliminary declaration
                           $processed = 0;
                           $found = [];
                           my $watcher = sub {
                               my $list = shift;
                               push @$found, $list if $list;  
                               $processed++;
                               if($processed == @full_hashes){
                                   if( $found ){
                                       $cb->($found);
                                   }
                                   else {
                                       $cb->([]);
                                   }
                               }
                           };
                       
                           foreach my $full_hash (@full_hashes) {
                               my $hash = first { $_->{hash} eq  $full_hash} @$hashes;
                               if (! defined $hash){
                                   $watcher->();
                                   next;
                               }
    
                               my $list = first { $hash->{list} eq $_ } @$lists;
                               if (defined $hash && defined $list) {
                                   log_debug2("Match: " . unpack('H*', $full_hash));
                                   $watcher->($hash->{list});
                               }
                           }
                        });
                    }
                });
            }
        });
    }    
    return;
}

=head1 PRIVATE FUNCTIONS

These functions are not intended to be used externally.

=over 4

=back

=head2 BUILD()

Constructor

=cut

sub BUILD {
    my $self = shift;
    eval "use ".$self->log_class.";";
    die $@ if $@;
    if( $self->data ){
        die "Parameter 'data' is unavailable from constructor";
    }
    $self->data( AnyEvent::Net::SafeBrowsing3::Data->new( path => $self->data_filepath ));
    return $self;
}

=head2 param_for_http_req()

Generates parameters for http request

  $self->param_for_http_req(timeout => $timeout, 
                       tls_ctx => { verify => 1 },
                       headers => { "user-agent" => $user_agent })

=cut

sub param_for_http_req {
    my $self = shift;
    return {timeout => $self->http_timeout, tls_ctx => {verify => 1}, headers => { "user-agent" => $self->user_agent }}
}

=head2 process_update_data()

Process the data received from server.

Data is a response body and has format:

  n:1200
  i:googpub-phish-shavar
  u:cache.google.com/first_redirect_example
  sd:1,2
  i:acme-white-shavar
  u:cache.google.com/second_redirect_example
  ad:1-2,4-5,7
  sd:2-6

This subroutine makes a list of redirection links (from "u:" part).
Then calls parse_data() function foreach item in redirection list.

Example:

  $self->process_update_data($data, $callback);

Arguments

=over 4

=item data

Required. Contains response body recieved from Safe Browsing Server.

=item callback

Required. Callback function that will be called after process_update_data() is performed.

=back

=cut

sub process_update_data {
    my ($self, $data, $cb) = @_;
    my @lines = split /\s/, $data;

    my $wait = $self->default_retry();

    my @redirections = ();
    my $del_add_duration = 0;
    my $del_sub_duration = 0;
    my $add_range_info = '';
    my $list = '';

    foreach my $line (@lines) {
        if ($line =~ /n:\s*(\d+)\s*$/) {
            log_info("Next poll: $1 seconds");
            $wait = $1;
            $self->data->set( 'updated/'.$list, {'time' => AE::now(), 'wait' => $wait} ) if $list;
        }
        elsif ($line =~ /i:\s*(\S+)\s*$/) {
            log_debug1("List: $1");
            $list = $1;
            $self->data->set( 'updated/'.$list, {'time' => AE::now(), 'wait' => $wait} ) if $wait;
        }
        elsif ($line =~ /u:\s*(\S+)\s*$/) {
            unless( $list ){
                log_error("Unknown list. Skip.");
                next;
            }
            log_debug1("Redirection: $1");
            push(@redirections, [$1, $list]);
        }
        elsif ($line =~ /ad:(\S+)$/) {
            unless( $list ){
                log_error("Unknown list. Skip.");
                next;
            }
            log_debug1("Delete Add Chunks: $1");

            $add_range_info = $1 . " $list";
            my $nums = AnyEvent::Net::SafeBrowsing3::Utils->expand_range($1);
            if( @$nums ){
                my $chunk_size = 500;
                my $iters = int(scalar(@$nums)/$chunk_size)+1;
                for( my $i = 0; $i < $iters; $i++){
                    my $from = $i*$chunk_size;
                    my $to = $chunk_size*($i+1)-1;
                    $to = scalar(@$nums)-1 if $to >= scalar(@$nums);
                    $self->storage->delete_add_chunks(chunknums => [@$nums[$from..$to]], list => $list, cb => sub {$_[0] ? log_error("delete tarantool error") : log_debug2("Delete tarantool ok")});
                    # TODO change function delete_full_hashes() so as it could take prefix parameter instead of chunknum parameter.
                    # chunknums are not storing in FULL_HASHES space any more
                    # Delete full hash as well
                    #$self->storage->delete_full_hashes(chunknums => $nums, list => $list, cb => sub {log_debug2(@_)}) ;
                }
            }
        }
        elsif ($line =~ /sd:(\S+)$/) {
            unless( $list ){
                log_error("Unknown list. Skip.");
                next;
            }
            log_debug1("Delete Sub Chunks: $1");

            my $nums = AnyEvent::Net::SafeBrowsing3::Utils->expand_range($1);
            if( @$nums ){
                my $chunk_size = 500;
                my $iters = int(scalar(@$nums)/$chunk_size)+1;
                for( my $i = 0; $i < $iters; $i++){
                    my $from = $i*$chunk_size;
                    my $to = $chunk_size*($i+1)-1;
                    $to = scalar(@$nums)-1 if $to >= scalar(@$nums);
                    $self->storage->delete_sub_chunks(chunknums => [@$nums[$from..$to]], list => $list, cb => sub {$_[0] ? log_error("delete tarantool error") : log_debug2("Delete tarantool ok")}) if @$nums;
                }
            }
        }
        elsif ($line =~ /r:pleasereset/) {
            unless( $list ){
                log_error("Unknown list. Skip.");
                next;
            }
            log_info("Database must be reset");

            $self->storage->reset($list);
            @redirections = ();
            $wait = 10;
            last;
        }
    }
    my $have_error = 0;
    my $get_redir;
    $get_redir = sub {
        my $redirections = shift;
        my $data = shift( @$redirections );
        my $redirection = $data->[0];
        $list = $data->[1];
        log_debug1("Url: https://$redirection");
        http_get( "https://$redirection", %{$self->param_for_http_req}, sub {
            my ($data, $headers) = @_; 
            log_debug1("Checking redirection https://$redirection ($list)");
            if( $headers->{Status} == 200 ){
                $self->parse_data(data => $data, list => $list, cb => sub {
                    my $error = shift;
                    if( $error ){
                        log_error("Have error while update data");
                        $self->update_error($list, $cb);
                    }
                    else {
                        if( @$redirections ){
                            $get_redir->($redirections);
                        }
                        else {
                            $cb->($wait);
                        }
                    }
                });
            }
            else {
                log_error("Request to $redirection failed ".$headers->{Status});
                $self->update_error($list, $cb);
            }
            return;
        });
    };
    if( @redirections ){
        $get_redir->(\@redirections);
    }
    else {
        $cb->($wait);
    }
    return;
}


=head2 local_lookup_prefix()

Lookups a prefix in the local database only.

  $self->local_lookup_prefix(lists => $lists, prefix => 'abcd1234', cb => sub {...} );

Arguments

=over 4

=item lists

Required. Lookups against specific list names. Should be a reference to array.

=item prefix

Optional. Hex string representing most significant 8 bytes of a full-length, 256-bit hash.

=item cb

Required. Callback function that will be called after local_lookup_prefix() is finished.

=back

=cut

sub local_lookup_prefix {
    my ($self, %args)   = @_;
    my $lists           = $args{lists}      or croak "Missing lists";
    my $prefix          = $args{prefix}     or return ();
    my $cb              = $args{cb}         or die "Callback is required";

    # Step 1: get all add chunks for this prefix 
    # Do it for all lists
    $self->storage->get_add_chunks(prefix => $prefix, lists => $lists, cb => sub {
        my $add_chunks = shift;
        unless( scalar @$add_chunks ){
            $cb->([]); 
            return;
        }
        
        # Step 2: get all sub chunks for this prefix
        $self->storage->get_sub_chunks(prefix => $prefix, lists => $lists, cb => sub {
            my $sub_chunks = shift;
            # Step 3: filter out add_chunks with sub_chunks 
            foreach my $sub_chunk (@$sub_chunks) {
                my $i = 0;
                while ($i < scalar @$add_chunks) {
                    my $add_chunk = $add_chunks->[$i];
                    if ($add_chunk->{chunknum} != $sub_chunk->{add_num} || $add_chunk->{list} ne $sub_chunk->{list}) {
                        ++$i;
                        next;
                    }

                    if ($sub_chunk->{prefix} eq $add_chunk->{prefix}) {
                        splice(@$add_chunks, $i, 1);
                    }
                    else {
                        ++$i;
                    }
                }
            }
            $cb->( $add_chunks ); 
        });
    });
    return ;
}

=head2 local_lookup()

Lookups a URL against the local Safe Browsing database URL. This should be used for debugging purpose only. See the lookup for normal use.

  my $match = $sb->local_lookup(list => ['goog-malware-shavar,googpub-phish-shavar'], url => 'http://www.gumblar.cn');

Returns the name of the list if there is any match, returns an empty string otherwise.

Arguments

=over 4

=item list

Required. Lookups against specific list names. Should be a reference to array.

=item url

Required. URL to lookup.

=back

=cut

sub local_lookup {
    my ($self, %args)   = @_;
    my $lists           = $args{list}       ||  '';
    my $url             = $args{url}        or return '';

    # TODO: create our own URI management for canonicalization
    # fix for http:///foo.com (3 ///)
    $url =~ s/^(https?:\/\/)\/+/$1/;

    my $uri = URI->new($url)->canonical;
    die "Bad url ".$url if $uri->scheme !~ /^https?$/;
    
    # compute full hashes (32b) and prefixes (4b) for all canonical combinations of URLs (domain + path). result data in binary
    my @full_hashes = $self->full_hashes($uri);
    my @full_hashes_prefix = map (substr($_, 0, 4), @full_hashes);
    
    # check if any prefix (4 bytes long) match with local database.
    # prefix in match is a hex string (because prefixes are stored in databse like hex strings)
    # returns a reference to array of add chunks to callback
    
    foreach my $prefix (@full_hashes_prefix) {
        my @matches = $self->local_lookup_prefix(
            lists => $lists,
            prefix => sprintf("%x", unpack('N', $prefix)), 
            cb => sub { return @{+shift}; });
        return $matches[0]->{list} . " " . $matches[0]->{prefix} if (scalar @matches > 0);
    }

    return '';
}

=head2 update_error()

Handles server errors during a database update.

=cut

sub update_error {
    my ($self, $list, $cb) = @_;

    my $info = $self->data->get('updated/'.$list);
    $info->{errors} = 0 if (! exists $info->{errors});
    my $errors = $info->{errors} + 1;
    my $wait = 0;

    $wait = $errors == 1 ? 60
        : $errors == 2 ? int(30 * 60 * (rand(1) + 1)) # 30-60 mins
        : $errors == 3 ? int(60 * 60 * (rand(1) + 1)) # 60-120 mins
        : $errors == 4 ? int(2 * 60 * 60 * (rand(1) + 1)) # 120-240 mins
        : $errors == 5 ? int(4 * 60 * 60 * (rand(1) + 1)) # 240-480 mins
        : $errors  > 5 ? 480 * 60
        : 0;

    $self->data->set('updated/'.$list, {'time' => $info->{time}||AE::now(), 'wait' => $wait, errors => $errors});
    $cb->($wait);
    return;
}


=head2 parse_data()

Parses data came from a redirection.
Data is in binary - some protobuf structures in trail. Each protobuf structure has format:

  BODY      = (UINT32 CHUNKDATA)+
  UINT32    = Unsigned 32-bit integer in network byte order.    => length of following data fragment which must be unpacked as Protobuf
  CHUNKDATA = Encoded ChunkData protocol message, see below.    => this must be unpacked as Protobuf

This function unpacks each chunkdata and then calls parse_a() or parse_s() for further parsing.
Stores results from parse_a() and parse_s() in storage. 

Example:

  $self->parse_data(data => $data, list => 'goog-malware-shavar', cb => sub {...})

Arguments

=over 4

=item data

Optional. Contains response body from redirect link in binary - some protobuf structures.

=item list

Optional. Contains list name (eg.: 'goog-malware-shavar', 'googpub-phish-shavar').

=item cb

Required. Callback function that will be called after  parse_data() is finished.

=back

=cut

sub parse_data {
    my ($self, %args)   = @_;
    my $data            = $args{data}       || '';
    my $list            = $args{list}       || '';
    my $cb              = $args{cb}     or die "Callback is required";
    
    my $in_process=1;
    my $have_error = 0;
    my $watcher = sub {
        my $err = shift;
        $in_process--;
        $have_error ||= $err;
        log_debug2("Watcher parse: ".$in_process);
        if(!$in_process){
            $cb->($have_error);
        }
    };

    my $bulk_insert_a = [];
    my $bulk_insert_s = [];
    while (length $data > 0) {
        my $protobuf_len = unpack('N', substr($data, 0, 4, '')); # UINT32
        my $protobuf_data = AnyEvent::Net::SafeBrowsing3::ChunkData->decode(substr($data, 0, $protobuf_len, '')); # ref to perl hash structure

        # perl hash format of decoded protobuf data is 
        # (~ - for optional fields. they're available throught accessor):
        # {
        #    chunk_number => int32,
        #  ~ chunk_type   => 0 or 1 (for ADD / SUB. ADD default),
        #  ~ prefix_type  => 0 or 1 (for 4B / 32B. 4B default),
        #  ~ hashes       => packed bites as string,
        #    add_numbers  => [456789, 456123, ....] list of int32 values, used in sub_chunks only
        # }

        my $chunk_num = $protobuf_data->chunk_number();
        my $chunk_type = $protobuf_data->chunk_type();
        my $hash_length = $protobuf_data->prefix_type() ? 32 : 4;

        if ($chunk_type == 0) {
            # it is add chunk
            my $data = $self->parse_a(value => $protobuf_data->hashes(), hash_length => $hash_length);
            foreach my $item (@$data) {
                push @$bulk_insert_a, { chunknum => $chunk_num, chunk => $item, list => $list };    
            }       
        }
        elsif ($chunk_type == 1) {
            # it is sub chunk
            my $data = $self->parse_s(value => $protobuf_data->hashes(), hash_length => $hash_length, add_chunknums => $protobuf_data->add_numbers() );
            foreach my $item (@$data) {
                push @$bulk_insert_s, { chunknum => $chunk_num, chunk => $item, list => $list };    
            }
        }
        else {
            # it is unknown chunk
            log_error("Incorrect chunk type: $chunk_type, should be 0 or 1 (for a: or s:)");
            $cb->(1);
            return;
        } 

        log_debug1(join " ", "$list chunk", $chunk_type ? 's:' : 'a:', "$chunk_num:$hash_length:$protobuf_len", length($protobuf_data->hashes()||""), scalar(@$bulk_insert_a), ":", scalar(@$bulk_insert_s), "OK");
	if( @$bulk_insert_a > 1000 ){
            ++$in_process;
    	    $self->storage->add_chunks_a($bulk_insert_a, $watcher);
	    $bulk_insert_a = [];
	}
	if( @$bulk_insert_s > 1000 ){
            ++$in_process;
    	    $self->storage->add_chunks_s($bulk_insert_s, $watcher);
	    $bulk_insert_s = [];
	}
    }
    $in_process--; 
    ++$in_process if @$bulk_insert_a;
    ++$in_process if @$bulk_insert_s;
    
    $self->storage->add_chunks_a($bulk_insert_a, $watcher) if @$bulk_insert_a;
    $self->storage->add_chunks_s($bulk_insert_s, $watcher) if @$bulk_insert_s; 
    $cb->(0) if !@$bulk_insert_a && !@$bulk_insert_s;
    
    return;
}

=head2 parse_s()

Unpacks sub prefixes from protobuf structure and returns a list of these prefixes (represents prefixes as hex strings).

  my @data = $self->parse_s(value => $encoded_hashes, add_chunknums => $add_numbers, hash_length => 4);
  use Data::Dumper;
  print Dumper(\@data);
  # $VAR1 = [
  #           {
  #             'add_chunknum' => 123456,
  #             'prefix' => '1234abcd'
  #           },
  #           {
  #             'add_chunknum' => 98765,
  #             'prefix' => 'eeff1122'
  #           },
  #           ...
  #        ]

Arguments

=over 4

=item value

Prefixes in binary one by another.

=item add_chunknums

Reference to array of add-chunk numbers. Each add-chunk number corresponds to prefix with the same sequence number. 

=item hash_length

Length in bytes of each prefix. May be 4 or 32 (according to protocol).  

=back

=cut

sub parse_s {
    my ($self, %args)  = @_;
    my $value          = $args{value}          or return [{prefix => '', add_chunknum => ''}];
    my $add_chunknums  = $args{add_chunknums}  or return (); 
    my $hash_length    = $args{hash_length};
    
    # check that the number of add_chunknums is equal to the number of hashes
    if (scalar(@$add_chunknums) != length($value)/$hash_length) {
        log_error("Incorrect number of add-chunks");
        return ();
    }

    my @data = ();
    
    foreach my $add_chunknum (@$add_chunknums) {
        my $prefix = unpack 'H*', substr($value, 0, $hash_length, '');
        push(@data, { add_chunknum => $add_chunknum, prefix => $prefix });
        log_debug3("parsed s-prefix : $add_chunknum : $prefix");
    }

    return \@data;
}


=head2 parse_a()

Unpacks add prefixes from protobuf structure and returns a list of these prefix as hex strings

  my @data = $self->parse_a(value => $encoded_hashes, hash_length => 4);
  use Data::Dumper;
  print Dumper(\@data);

  # $VAR1 = [
  #           '1234absd',
  #           'eeddab65',
  #           ...
  #         ]

Arguments

=over 4

=item value

Prefixes in binary one by another.

=item hash_length

Length in bytes of each prefix. May be 4 or 32 (according to protocol).  

=back

=cut

sub parse_a {
    my ($self, %args)  = @_;
    my $value          = $args{value}         or return [{prefix => ''}];
    my $hash_length    = $args{hash_length}; 

    my @data = (); 
    
    while (length $value > 0) {
        my $prefix = unpack 'H*', substr($value, 0, $hash_length, '');
        push @data, { prefix => $prefix };
        log_debug3("parsed a-prefix : $prefix");
    }
    return \@data;
}

=head2 canonical_domain()

Find all canonical domains for given hostname.

These domains are:
 1. the exact hostname in the URL
 2. up to 4 hostnames formed by starting with the last 5 components and successively removing the leading component.
 
This subroutine prepares given hostname before getting domains:
 1. Remove all leading and trailing dots.
 2. Replace consecutive dots with a single dot.

Example:

  use URI;
  my $host = URI->new('http://a.b.c..d.e.f./1/2.html?param=1')->host; # 'a.b.c..d.e.f.' 
  my @domains = $self->canonical_domain($host);
  print join "\n", @domains;

  # 'a.b.c.d.e.f.g',
  # 'c.d.e.f.g',
  # 'd.e.f.g',
  # 'e.f.g',
  # 'f.g'

=cut

sub canonical_domain {
    my ($self, $domain)     = @_;
    
    # 3. If the hostname can be parsed as an IP address, normalize it to 4 dot-separated decimal values. 
    # The client should handle any legal IP- address encoding, including octal, hex, and fewer than 4 components.
    # see: http://habrahabr.ru/post/69587/
    # example: Canonicalize("http://3279880203/blah") => "http://195.127.0.11/blah";
    # (TODO in Clicker) 
    # 4. Lowercase the whole string.
    # (it's just lowercased by URI->host)
    
    $domain =~ s<^\.*([^.].*[^.])\.*$><$1>; # prepare 1
    $domain =~ s<\.{2,}><\.>g;              # prepare 2
    
    my @domains = ($domain);
    if ($domain =~ /^\d+\.\d+\.\d+\.\d+$/) { # loose check for IP address, should be enough
        return @domains;
    } 

    push(@domains, $domain) if ($domain =~ s/^(.*)\.  (([^.]+\.){4}  [^.]+) $/$2/x);
    
    while ($domain =~ s/^[^.]+\.(.*)$/$1/ and $domain =~ /\./) {
    push @domains, $domain;
    };
    
    return @domains;
}



=head2 canonical_path()

Finds all canonical path combinations for a given path.

These path combinations are:
 1. the exact path of the URL, including query parameters
 2. the exact path of the URL, without query parameters
 3. the 4 paths formed by starting at the root (/) and successively appending path components, including a trailing slash.
 
This subroutine prepares given path before getting combinations:
 1. replaces "/./" with "/", 
 2. replaces runs of consecutive slashes with a single slash character.
 3. removes "/../" along with the preceding path component. 
 (Path canonicalizations is not applied to the query parameters)

Example:

  use URI;
  my $adr = 'http://a.b.c/qqq/./2//3/4//6///8//5.html?param=1';
  my $path_query = URI->new($adr)->path_query;    # '/qqq/./2//3/4//6///8//5.html?param=1'
  my @paths = $self->canonical_path($path_query);
  print join "\n", @paths;

  # 'qqq/2/3/4/6/8/5.html?param=1',
  # 'qqq/2/3/4/6/8/5.html',
  # 'qqq/',
  # 'qqq/2/',
  # 'qqq/2/3/',
  # 'qqq/2/3/4/' 

Arguments

=over 4

=item path_query

Path + query components of uri (like returns function path_query() from module URI). For example /1/2.html?param=1 (with leading slash).

=back

=cut

sub canonical_path {
    my ($self, $path_query) = @_;
    
    my ($path, $query) = split('\?', $path_query); 
    
    my $path_orig = $path;
    $path =~ s</\./></>g;     # prepare 1
    $path =~ s<\/{2,}><\/>g;  # prepare 2
    $path =~ s<^.*/\.\./><>g; # prepare 3

    $path =~ s<^\/><>;
    
    my @paths = ('');
    push @paths, $path if $path;
    push @paths, "$path?$query" if $query;
    
    my $prev = '';

    for (my $i = 0; $i < 4; ++$i) {
        last if $path eq '';
        if ($path =~ s<^ ([^/]+)  (\/)? ><>x) {
            my $curr = defined($2) ? "$1$2" : $1; 
            last if !defined($curr);
        $prev .= "$curr";
            push @paths, $prev if ($prev ne $path_orig);
        } 
    }
    
    return @paths;
}

=head2 canonical()

Find all possible combinations of domain + path  for a given URL.

  my @urls = $self->canonical('http://a.b.c/1/2.html?param=1');
  print join "\n", @urls;

  # a.b.c/1/2.html?param=1
  # a.b.c/1/2.html
  # a.b.c/
  # a.b.c/1/
  # b.c/1/2.html?param=1
  # b.c/1/2.html
  # b.c/
  # b.c/1/

=cut

sub canonical {
    my ($self, $url) = @_;
    my @urls = ();
    my $uri = $self->canonical_uri($url);
    my @domains = $self->canonical_domain($uri->host);
    my @paths = $self->canonical_path($uri->path_query);
    foreach my $domain (@domains) {
        foreach my $path (@paths) {
            push(@urls, "$domain\/$path");
        }
    }
    return @urls;
}


=head2 canonical_uri()

Creates a canonical URI.

NOTE: URI cannot handle all the test cases provided by Google. This method is a hack to pass most of the test. A few tests are still failing. The proper way to handle URL canonicalization according to Google would be to create a new module to handle URLs. However, I believe most real-life cases are handled correctly by this function.

=cut

sub canonical_uri {
    my ($self, $url) = @_;
    $url = AnyEvent::Net::SafeBrowsing3::Utils->trim( $url );
    while ($url =~ s/^([^?]+)[\r\t\n]/$1/sgi) { } 
    my $uri = URI->new($url)->canonical; # does not deal with directory traversing
    if (! $uri->scheme() || $uri->scheme() eq '') {
        $uri = URI->new("http://$url")->canonical;
    }
    $uri->fragment('');
    my $escape = $uri->as_string;
    while ($escape =~ s/^([a-z]+:\/\/[^?]+)\/\//$1\//sgi) { }

    # Remove empty fragment
    $escape =~ s/#$//;

    # canonial does not handle ../ 
    while($escape =~ s/([^\/])\/([^\/]+)\/\.\.([\/?].*)$/$1$3/gi) {  }
    while($escape =~ s/([^\/])\/([^\/]+)\/\.\.$/$1/gi) {  }

    # May have removed ending /
    $escape .= "/" if ($escape =~ /^[a-z]+:\/\/[^\/\?]+$/);
    $escape =~ s/^([a-z]+:\/\/[^\/]+)(\?.*)$/$1\/$2/gi;

    # other weird case if domain = digits only, try to translte it to IP address
    if ((my $domain = URI->new($escape)->host) =~/^\d+$/) {
        my @ip = unpack("C4",pack("N",$domain));
        if( scalar( grep {$_ ne "" && $_ >= 0 && $_ <= 255} @ip) == 4 ){
            $uri = URI->new($escape);
            $uri->host(join ".", @ip);
            $escape = $uri->as_string;
        }
    }

    # Try to escape the path again
    $url = $escape;
    while (($escape = URI::Escape::uri_unescape($url)) ne $escape) { # wrong for %23 -> #
        $url = $escape;
    }

    # Fix for %23 -> #
    while($escape =~ s/#/%23/sgi) { }

    # Fix over escaping
    while($escape =~ s/^([^?]+)%%(%.*)$/$1%25%25$2/sgi) { }
    while($escape =~ s/^([^?]+)%%/$1%25%25/sgi) { }

    # URI has issues with % in domains, it gets the host wrong

    # 1. fix the host
    my $exception = 0;
    while ($escape =~ /^[a-z]+:\/\/[^\/]*([^a-z0-9%_.-\/:])[^\/]*(\/.*)$/) {
        my $source = $1;
        my $target = sprintf("%02x", ord($source));
        $escape =~ s/^([a-z]+:\/\/[^\/]*)\Q$source\E/$1%\Q$target\E/;
        $exception = 1;
    }

    # 2. need to parse the path again
    if ($exception && $escape =~ /^[a-z]+:\/\/[^\/]+\/(.+)/) {
        my $source = $1;
        my $target = URI::Escape::uri_unescape($source);

        while ($target ne URI::Escape::uri_unescape($target)) {
            $target = URI::Escape::uri_unescape($target);
        }
        $escape =~ s/\/\Q$source\E/\/$target/;

        while ($escape =~ s/#/%23/sgi) { } # fragement has been removed earlier
        while ($escape =~ s/^([a-z]+:\/\/[^\/]+\/.*)%5e/$1\&/sgi) { } # not in the host name

        while ($escape =~ s/%([^0-9a-f]|.[^0-9a-f])/%25$1/sgi) { }
    }

    return URI->new($escape);
}

=head2 full_hashes()

Returns all possible full hashes (sha256) for a given URL.

=cut

sub full_hashes {
    my ($self, $url) = @_;

    my @urls = $self->canonical($url);
    my @hashes = ();

    foreach my $url (@urls) {
        push(@hashes, sha256($url));
    }

    return @hashes;
}

=head2 request_full_hash()

Requests for full hashes for specific prefixes from Google.

  $self->request_ful_hashes( prefixes => $pref, cb => sub {...} ); 

Arguments

=over 4

=item prefixes

Reference to array of hash-prefixes in binary

=item cb

Callback function that will be called after request_full_hash() is finished.

=back

Returns a reference to list of full hashes in callback:

  [ 
    {list => listname1, prefix => prefix1, hash => hash1, timestamp => valid_to1}, 
    {list => listname2, prefix => prefix2, hash => hash2, timestamp => valid_to2},
    ...
  ]

=cut

sub request_full_hash {
    my ($self, %args)   = @_;
    my $prefixes        = $args{prefixes}; ref $prefixes eq 'ARRAY' or die "Arg prefixes is required and must be arrayref";
    my $cb              = $args{cb} or die "Args cb is required";
    my $size            = length $prefixes->[0];
    # Handle errors
    my $i = 0;
    my $errors;
    my $delay = sub {
    my $time = shift;
        if ((time() - $errors->{timestamp}) < $time) {
            splice(@$prefixes, $i, 1);
        }
        else {
            $i++;
        }
    };
    
    while ($i < scalar @$prefixes) {
        my $prefix = $prefixes->[$i];
        
        $errors = $self->data->get('full_hash_errors/'.unpack( 'H*', $prefix));
        if (defined $errors && $errors->{errors} > 2) { # 2 errors is OK
            $errors->{errors} == 3 ? $delay->(30 * 60) # 30 minutes
            : $errors->{errors} == 4 ? $delay->(60 * 60) # 1 hour
            : $delay->(2 * 60 * 60); # 2 hours
        }
        else {
            $i++;
        }
    }
    
    # request URL
    my $url = $self->server . "gethash?client=api&key=" . $self->key . "&appver=$VERSION&pver=" . $self->version;
    log_debug1( "Full hash url: ". $url);
    
    # request body
    # example:
    #     4:12          => size_of_each_prefix_in_bytes ":" total_length_of_prefixes_in_bytes
    #     123456781234  => chain of prefixes in binary
    
    my $prefix_list = join('', @$prefixes);
    my $header = "$size:" . (@$prefixes  * $size);
    my $body = $header."\n".$prefix_list;
    log_debug1( "Full hash data: $header\\n". unpack( 'H*', $prefix_list));
    
    http_post( $url, $body, %{$self->param_for_http_req}, sub {
        my ($data, $headers) = @_; 
        if( $headers->{Status} == 200 && length $data){
            log_debug1("Full hash request OK");
            log_debug3("Response body: ".$data);
            $self->data->delete('full_hash_errors/'.unpack( 'H*', $_ )) for @$prefixes;
            
            # parse response 
            # example 1:
            #    900                                                                  => CACHELIFETIME (in seconds)
            #    goog-malware-shavar:32:2:m                                           => LISTNAME ":" HASHSIZE ":" NUMRESPONSES [":m"] 
            #    01234567890123456789012345678901987654321098765432109876543210982    => HASHDATA_BINARY [METADATALEN 
            #    AA3                                                                  => METADATA_BINARY]*
            #    BBBgoogpub-phish-shavar:32:1
            #    99998888555544447777111122225555
            #
            # example 2:
            #    600
            #    googpub-phish-shavar:32:1
            #    01234567890123456789012345678901
            #
            # example 3:
            #    900    
            # ------------------
            my @hashes = ();
            # my @metadata = ();
            
            # 1) unpack CACHELIFETIME  (900)
            if ($data !~ /^(\d+)/) {
                log_error("error in parsing full hash response");
                $cb->([]);
                return;
            }
            my $cache_lifetime = $1;
            substr($data, 0, length($cache_lifetime."\n"), '');
            my $valid_to = $self->cache_time ? (time() + $self->cache_time) : (time() + $cache_lifetime);
            
            # 2) handle empty answer
            if ($data eq '') {
                                my $list = join (" | ", @$prefixes);
                log_debug1("Empty answer for prefixlist ($list) for $cache_lifetime seconds");
                # TODO store empty answers anywhere
                $cb->([]);
                return;
            }
            
            while (length $data > 0) {
               # 3) unpack list name, length of one hash and number of hashes in response
               #    (goog-malware-shavar:32:2:m)
                if ($data !~ /^([a-z\-]+):(\d+):(\d+)/) {
                    log_error("error in parsing full hash response");
                    $cb->([]);
                    return;
                }
                my ($list, $hash_size, $num_responses) = ($1, $2, $3);
                substr($data, 0, length($list.":".$hash_size.":".$num_responses),'');
                
                # 4) check if there is metadata  
                my $has_meta = 0;
                if ($data =~ /^:m/) {
                    $has_meta = 1;
                    substr($data, 0, length(":m\n"),'');        
                }
                else {
                    substr($data, 0, length("\n"),''); 
                }
                
                # 5) unpack hashes (binary). length of each hash = $hash_size
                for (my $i = 0; $i < $num_responses; ++$i) {
                    my $hash = substr($data, 0, $hash_size, ''); 
                    my $prefix = substr($hash, 0, 4);
                    push(@hashes, { list => $list, prefix => $prefix, hash => $hash, timestamp => $valid_to });
                }
                
                # 6) unpack metadata (2\nAA3\nBBBnext_text)
                # it's binary, in protobuf format. now it's not neccessary to unpack protobuf messages, 
                # so this metadata isn't stored anywhere.
                if ($has_meta) {
                    while ($data =~ /^(\d+)/) {
                        my $meta_len = $1;      
                        my $meta = substr($data, length($meta_len."\n"), $meta_len);
                        substr($data, 0,length($meta_len."\n".$meta), '');
                        # push(@metadata, $meta);
                    }
                }
            }
            
            $cb->(\@hashes);            
        }
        else {
            log_error("Full hash request failed ".$headers->{Status} );
            foreach my $prefix (@$prefixes) {
                my $errors = $self->data->get('full_hash_errors/'.unpack( 'H*', $prefix));
                if (defined $errors && ( $errors->{errors} >=2 || $errors->{errors} == 1 && (time() - $errors->{timestamp}) > 5 * 60)) { # 5 minutes
                    $self->data->set('full_hash_errors/'.unpack( 'H*', $prefix ).'/timestamp', time()); # more complicate than this, need to check time between 2 errors
                }
            }
        }
        return;
    });
    return;
}


Google::ProtocolBuffers->parse("
    package any_event.net.safe_browsing3;
    message ChunkData {
        required int32 chunk_number = 1;

         // The chunk type is either an add or sub chunk.        
        enum ChunkType {
            ADD = 0;
            SUB = 1;
        }
        optional ChunkType chunk_type = 2 [default = ADD];

        // Prefix type which currently is either 4B or 32B.  The default is set
        // to the prefix length, so it doesn't have to be set at all for most
        // chunks.
     
        enum PrefixType {
            PREFIX_4B = 0;
            FULL_32B = 1;
        }
    
        optional PrefixType prefix_type = 3 [default = PREFIX_4B];
        // Stores all SHA256 add or sub prefixes or full-length hashes. The number
        // of hashes can be inferred from the length of the hashes string and the
        // prefix type above.
    
        optional bytes hashes = 4;

        // Sub chunks also encode one add chunk number for every hash stored above.
    
        repeated int32 add_numbers = 5 [packed = true];
    }",

    { create_accessors => 1 } 
);    

no Mouse;
__PACKAGE__->meta->make_immutable();
 
=head1 SEE ALSO

See L<AnyEvent::Net::SafeBrowsing3::Storage>, L<AnyEvent::Net::SafeBrowsing3::Tarantool> for information on storing and managing the Safe Browsing database.

Google Safe Browsing v3 API: L<https://developers.google.com/safe-browsing/developers_guide_v3.html>

=head1 AUTHOR

Nikolay Shulyakovskiy, E<lt>shulyakovskiy@mail.ruE<gt> or E<lt>shulyakovskiy@yandex.ruE<gt>; 
Ekaterina Klishina, E<lt>e.klishina@mail.ruE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2015 by Nikolay Shulyakovskiy, Ekaterina Klishina

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;

