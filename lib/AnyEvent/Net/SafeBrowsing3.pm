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
# FOR DEBUG ONLY
use Data::Dumper;
use feature qw(say);

our $VERSION = '1.01';

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

  $sb->update(['goog-malware-shavar'], sub {warn "Next hope after ".$_[0], $cv->send()});
  $cv->recv;

TODO
  my $match = $sb->lookup(url => 'http://www.gumblar.cn/');
  
  if ($match eq MALWARE) {
	print "http://www.gumblar.cn/ is flagged as a dangerous site";
  }

  $storage->close();

=head1 DESCRIPTION

AnyEvent::Net::SafeBrowsing3 implements the Google Safe Browsing v3 API.

The library passes most of the unit tests listed in the API documentation. See the documentation (L<https://developers.google.com/safe-browsing/developers_guide_v2>) for more details about the failed tests.

The Google Safe Browsing database must be stored and managed locally. L<AnyEvent::Net::SafeBrowsing3::Tarantool> uses Tarantool as the storage back-end. Other storage mechanisms (databases, memory, etc.) can be added and used transparently with this module.
TODO
The source code is available on github at L<https://github.com/juliensobrier/Net-Google-SafeBrowsing3>.

If you do not need to inspect more than 10,000 URLs a day, you can use L<AnyEvent::Net::SafeBrowsing3::Lookup> with the Google Safe Browsing v2 Lookup API which does not require to store and maintain a local database. Use AnyEvent::Net::SafeBrowsing3::Empty for this one.

IMPORTANT: If you start with an empty database, you will need to perform several updates to retrieve all the Google Safe Browsing information. This may require up to 24 hours. This is a limitation of the Google API, not of this module.

=cut

=head1 CONSTRUCTOR

=over 4

=back

=head2 new()

Create a AnyEvent::Net::SafeBrowsing3 object

  my $sb = AnyEvent::Net::SafeBrowsing3->new(
	key 	=> "key", 
    storage	=> AnyEvent::Net::SafeBrowsing3::Tarantool->new(...),
	log     => AnyEvent::Net::SafeBrowsing3::Log->new({debug_level => 'debug3'}),
  );

Arguments

=over 4

=item server

Required. Safe Browsing Server.

=item mac_server

Safe Browsing MAC Server.

=item key

Required. Your Safe browsing API key

=item storage

Required. Object which handle the storage for the Safe Browsing database (AnyEvent::Net::SafeBrowsing3::Empty by default). See L<AnyEvent::Net::SafeBrowsing3::Storage> for more details.

=item mac

Optional. Set to 1 to enable Message Authentication Code (MAC). 0 (disabled) by default.

=item version

Optional. Safe Browsing version. 2.2 by default

=item log

Optional. Object for log writing. Default AnyEvent::Net::SafeBrowsing3::Log

=item data

Optional. Object which handle the storage for the additioanl params. Default AnyEvent::Net::SafeBrowsing3::Data

=item data_filepath

Optional. Path to data file 

=item http_timeout 

Optional. Timeout for request to Safe Browsing service. Default 60 sec

=item user_agent

Optional. User agent which be received to SafeBrowsing service. Default AnyEvent::Net::SafeBrowsing3 client $VERSION

=item cache_time

Time for chace result of full hashes. Default 45 min

=item default_retry

Retry timeout after unknown fail. Default 30 sec

=back

=cut

has server       => (is => 'rw', isa => 'Str', required => 1 );
#TODO is neccessary? has mac_server   => (is => 'rw', isa => 'Str' );
has key          => (is => 'rw', isa => 'Str', required => 1 );
has version      => (is => 'rw', isa => 'Str', default => '3.0' );
has log_class    => (is => 'rw', isa => 'Str', default => 'AnyEvent::Net::SafeBrowsing3::Log' );
has storage      => (is => 'rw', isa => 'Object', default => sub {AnyEvent::Net::SafeBrowsing3::Storage->new()});
has data         => (is => 'rw', isa => 'Object');
has data_filepath=> (is => 'rw', isa => 'Str', default => '/tmp/safebrowsing_data' );
has in_update    => (is => 'rw', isa => 'Int');
has force        => (is => 'rw', isa => 'Bool', default => '0');
has http_timeout => (is => 'ro', isa => 'Int', default => '60');
has user_agent   => (is => 'rw', isa => 'Str', default => 'AnyEvent::Net::SafeBrowsing3 client '.$VERSION );
has cache_time   => (is => 'ro', isa => 'Int', default => 45*60);
has default_retry=> (is => 'ro', isa => 'Int', default => 30);
#has protobuf_struct => (is =>'rw', lazy_build => 1);

=head1 PUBLIC FUNCTIONS

=over 4

=back

=head2 update()

Perform a database update.

  $sb->update('list', sub {});

Return the time of next hope to update db

This function can handle two lists at the same time. If one of the list should not be updated, it will automatically skip it and update the other one. It is faster to update two lists at once rather than doing them one by one.

NOTE: If you start with an empty database, you will need to perform several updates to retrieve all Safe Browsing information. This may require up to 24 hours. This is a limitation of API, not of this module.

Arguments

=over 4

=item list

Required. Update a specific list.

=item callback

Required. Callback function that will be called after db is updated.

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
					my $chunks_list = '';
					if ($a_range ne '') {
						$chunks_list .= "a:$a_range";
					}
					if ($s_range ne '') {
						$chunks_list .= ":" if ($a_range ne '');
						$chunks_list .= "s:$s_range";
					}
					my $body .= "$item;$chunks_list";
					$body .= "\n";
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

Perform a force database update.

  $sb->force_update('list', sub {});

Return the time of next hope to update db

Be careful if you call this method as noo frequent updates might result in the blacklisting of your API key.

Arguments

=over 4

=item list

Required. Update a specific list.

=item callback

Required. Callback function that will be called after db is updated.

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

Lookup a URL against the Safe Browsing database.

  my $match = $sb->lookup(list => 'name', url => 'http://www.gumblar.cn', cb => sub {});

Returns the name of the list if there is any match, returns an empty string otherwise.

Arguments

=over 4

=item list

Required. Lookup against a specific list.

=item url

Required. URL to lookup.

=item callback

Required. Callback function that will be called after db is updated.

=back

=cut

sub lookup {
	my ($self, %args) 	= @_;
	my $list 			= $args{list}		|| die "List is required";
	my $url 			= $args{url}		|| die "URL is required";
	my $cb              = $args{cb}         || die "Callback is required";

	# TODO: create our own URI management for canonicalization
	# fix for http:///foo.com (3 ///)
	$url =~ s/^(https?:\/\/)\/+/$1/;

	my $uri = URI->new($url)->canonical;
	die "Bad url ".$url if $uri->scheme !~ /^https?$/;
	my $domain = $uri->host;
	my @hosts = $self->canonical_domain_suffixes($domain); # only top-3 in this case
	my $processed = 0;
	my $ret_matched = [];
	my $watcher = sub {
		my $match = shift;
		push @$ret_matched, $match if $match;
		$processed++;
		if( $processed == @hosts ){
			$cb->($ret_matched);
		}
	};
	foreach my $host (@hosts) {
		log_debug1("Domain for key: $domain => $host");
		my $suffix = $self->prefix("$host/"); # Don't forget trailing hash
		log_debug2("Host key: ".unpack( 'V', $suffix));
		$self->lookup_suffix(lists => $list, url => $url, suffix => unpack( 'V', $suffix ), cb => $watcher);
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
	if( $self->data && $self->data_filepath ){
		die "Available only one parameter data or data_filepath";
	}
	$self->data( AnyEvent::Net::SafeBrowsing3::Data->new( path => $self->data_filepath ));
	return $self;
}

=head2 param_for_http_req()

Generate params for http request

=cut

sub param_for_http_req {
	my $self = shift;
	return {timeout => $self->http_timeout, tls_ctx => {verify => 1}, headers => { "user-agent" => $self->user_agent }}
}

=head2 process_update_data()

Process the data received from server.

data format:

n:1200
i:googpub-phish-shavar
u:cache.google.com/first_redirect_example
sd:1,2
i:acme-white-shavar
u:cache.google.com/second_redirect_example
ad:1-2,4-5,7
sd:2-6

And makes a list of redirection links (from "u:" tag).
Then calls parse_data() function foreach item in redirection list.

=cut

sub process_update_data {
	my ($self, $data, $cb) = @_;
	my @lines = split /\s/, $data;

        say "========= DUMPER ============";
        say Dumper(\@lines);
        say "=============================";

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
				$self->storage->delete_add_chunks(chunknums => $nums, list => $list, cb => sub {log_debug2(@_)});
				# Delete full hash as well
				$self->storage->delete_full_hashes(chunknums => $nums, list => $list, cb => sub {log_debug2(@_)}) ;
			}
		}
		elsif ($line =~ /sd:(\S+)$/) {
			unless( $list ){
				log_error("Unknown list. Skip.");
				next;
			}
			log_debug1("Delete Sub Chunks: $1");

			my $nums = AnyEvent::Net::SafeBrowsing3::Utils->expand_range($1);
			$self->storage->delete_sub_chunks(chunknums => $nums, list => $list, cb => sub {}) if @$nums;
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


=head2 lookup_suffix()

Lookup a host prefix.

=cut

sub lookup_suffix {
	my ($self, %args) 	= @_;
	my $lists 			= $args{lists} 		|| croak "Missing lists";
	my $url 			= $args{url}		|| return '';
	my $suffix			= $args{suffix}		|| return '';
	my $cb              = $args{cb}         || die "Callback is required";

	# Calculcate prefixes
	my @full_hashes = $self->full_hashes($url); # Get the prefixes from the first 4 bytes
	my @full_hashes_prefix = map (substr($_, 0, 4), @full_hashes);
 	# Local lookup
	$self->local_lookup_suffix(lists => $lists, url => $url, suffix => $suffix, full_hashes_prefix => [@full_hashes_prefix], cb => sub {
		my $add_chunks = shift;
		unless( scalar @$add_chunks ){
			$cb->();
			return;
		}
		# Check against full hashes
		my $found = '';
		my $processed = 0;
		my $watcher = sub {
			my $list = shift;
			$found ||= $list if $list;  
			$processed++;
			if($processed == @$add_chunks){
				if( $found ){
					$cb->($found);
				}
				else {
					log_debug2("No match");
					$cb->();
				}
			}
		};

		# get stored full hashes
		foreach my $add_chunk (@$add_chunks) {
			$self->storage->get_full_hashes( chunknum => $add_chunk->{chunknum}, timestamp => time() - $self->cache_time, list => $add_chunk->{list}, cb => sub {
				my $hashes = shift;
				if( @$hashes ){
					log_debug2("Full hashes already stored for chunk " . $add_chunk->{chunknum} . ": " . scalar @$hashes);
					my $fnd = '';
					log_debug1( "Searched hashes: ", \@full_hashes );
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
					# ask for new hashes
					# TODO: make sure we don't keep asking for the same over and over
					$self->request_full_hash(prefixes => [ map(pack( 'H*', $_->{prefix}) || pack( 'L', $_->{hostkey}), @$add_chunks) ], cb => sub {
						my $hashes = shift;
						log_debug1( "Full hashes: ", $hashes);
						$self->storage->add_full_hashes(full_hashes => $hashes, timestamp => time(), cb => sub {});
						$processed = 0;
						$found = '';
						my $watcher = sub {
							my $list = shift;
							$found ||= $list if $list;  
							$processed++;
							if($processed == @full_hashes){
								if( $found ){
									$cb->($found);
								}
								else {
									$cb->();
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
								log_debug2("Match: $full_hash");
								$watcher->($hash->{list});
							}
						}
					});
				}
			});
		}
	});
	return;
}

=head2 lookup_suffix()

Lookup a host prefix in the local database only.

=cut

sub local_lookup_suffix {
	my ($self, %args) 			= @_;
	my $lists 					= $args{lists} 				|| croak "Missing lists";
	my $url 					= $args{url}				|| return ();
	my $suffix					= $args{suffix}				|| return ();
	my $full_hashe_list 		= $args{full_hashes}		|| [];
	my $full_hashes_prefix_list = $args{full_hashes_prefix} || [];
	my $cb                      = $args{cb}                 || die "Callback is required";

	# Step 1: get all add chunks for this host key
	# Do it for all lists
	$self->storage->get_add_chunks(hostkey => $suffix, lists => $lists, cb => sub {
		my $add_chunks = shift;
		unless( scalar @$add_chunks ){
			$cb->([]); 
			return;
		}
		# Step 2: calculcate prefixes
		# Get the prefixes from the first 4 bytes
		my @full_hashes_prefix = @{$full_hashes_prefix_list};
		if (scalar @full_hashes_prefix == 0) {
			my @full_hashes = @{$full_hashe_list};
			@full_hashes = $self->full_hashes($url) if (scalar @full_hashes == 0);

			@full_hashes_prefix = map (substr($_, 0, 4), @full_hashes);
		}
		# Step 3: filter out add_chunks with prefix
		my $i = 0;
		while ($i < scalar @$add_chunks) {
			if ($add_chunks->[$i]->{prefix} ne '') {
				my $found = 0;
				foreach my $hash_prefix (@full_hashes_prefix) {
					if ( $add_chunks->[$i]->{prefix} eq unpack( 'H*', $hash_prefix)) {
						$found = 1;
						last;
					}
				}
				if ($found == 0) {
					log_debug2("No prefix found");
					splice(@$add_chunks, $i, 1);
				}
				else {
					$i++;
				}
			}
			else {
				$i++;
			}
		}
		unless( scalar @$add_chunks ){
			$cb->([]); 
			return;
		}
		# Step 4: get all sub chunks for this host key
		$self->storage->get_sub_chunks(hostkey => $suffix, lists => $lists, cb => sub {
			my $sub_chunks = shift;
			foreach my $sub_chunk (@$sub_chunks) {
				my $i = 0;
				while ($i < scalar @$add_chunks) {
					my $add_chunk = $add_chunks->[$i];

					if ($add_chunk->{chunknum} != $sub_chunk->{addchunknum} || $add_chunk->{list} ne $sub_chunk->{list}) {
						$i++;
						next;
					}

					if ($sub_chunk->{prefix} eq $add_chunk->{prefix}) {
						splice(@$add_chunks, $i, 1);
					}
					else {
						$i++;
					}
				}
			}
			$cb->( $add_chunks ); 
		});
	});
	return ;
}

=head2 local_lookup()

Lookup a URL against the local Safe Browsing database URL. This should be used for debugging purpose only. See the lookup for normal use.

  my $match = $sb->local_lookup(url => 'http://www.gumblar.cn');

Returns the name of the list if there is any match, returns an empty string otherwise.

Arguments

=over 4

=item list

Required. Lookup against a specific list.

=item url

Required. URL to lookup.

=item callback

Required. Callback function that will be called after db is updated.

=back

=cut

sub local_lookup {
	my ($self, %args) 	= @_;
	my $list 			= $args{list}		|| '';
	my $url 			= $args{url}		|| return '';

	my @lists = @{$self->{list}};
	@lists = @{[$args{list}]} if ($list ne '');


	# TODO: create our own URI management for canonicalization
	# fix for http:///foo.com (3 ///)
	$url =~ s/^(https?:\/\/)\/+/$1/;

	my $uri = URI->new($url)->canonical;

	my $domain = $uri->host;
	
	my @hosts = $self->canonical_domain_suffixes($domain); # only top-3 in this case

	foreach my $host (@hosts) {
		debug1("Domain for key: $domain => $host");
		my $suffix = $self->prefix("$host/"); # Don't forget trailing hash
		debug1("Host key: $suffix");

		my @matches = $self->local_lookup_suffix(lists => [@lists], url => $url, suffix => $suffix);
		return $matches[0]->{list} . " " . $matches[0]->{chunknum}  if (scalar @matches > 0);
	}

	return '';

}

=head2 get_mac_keys()

Request the Message Authentication Code (MAC) keys

=cut

sub get_mac_keys {
	my ($self, $cb) = @_;
	my $keys = $self->data->get('mac_keys');
	if ($keys->{client_key} eq '' || $keys->{wrapped_key} eq '') {
		$self->request_mac_keys(sub{
			my ($client_key, $wrapped_key) = @_;
			$self->data->set('mac_keys', {client_key => $client_key, wrapped_key => $wrapped_key});
			$cb->($client_key, $wrapped_key);
		});
	}
	else{
		$cb->($keys->{client_key}, $keys->{wrapped_key});
	}
	return;
}

=head2 delete_mac_keys()

Request the Message Authentication Code (MAC) keys

=cut

sub delete_mac_keys {
	my ($self, $cb) = @_;
	$self->data->set('mac_keys', {});
	return;
}


=head2 request_mac_keys()

Request the Message Authentication Code (MAC) keys.

=cut

sub request_mac_keys {
	my ($self, $cb) = @_;
	my $client_key = '';
	my $wrapped_key = '';
	my $url = $self->mac_server."newkey?client=api&apikey=".$self->key."&appver=$VERSION&pver=".$self->version;
	debug1( "Url for get keys: ".$url );
	http_get($url, %{$self->param_for_http_req}, sub {
		my ($data, $headers) = @_; 
		if( $headers->{Status} == 200 ){
			if ($data =~ s/^clientkey:(\d+)://mi) {
				my $length = $1;
				rog_debug1("MAC client key length: $length");
				$client_key = substr($data, 0, $length, '');
				log_debug2("MAC client key: $client_key");
				substr($data, 0, 1, ''); # remove 
				if ($data =~ s/^wrappedkey:(\d+)://mi) {
					$length = $1;
					log_debug1("MAC wrapped key length: $length");
					$wrapped_key = substr($data, 0, $length, '');
					log_debug2("MAC wrapped key: $wrapped_key");
					$cb->(decode_base64($client_key), $wrapped_key);
				}
				else {
					$cb->('', '');
				}
			}
		}
		else {
			log_error("Key request failed: " . $headers->{Status});
			$cb->('', '');
		}
	});
	return;
}

=head2 update_error()

Handle server errors during a database update.

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

=head2 parse_s()

Parse data from a rediration (add asnd sub chunk information).

=cut

#======================================
=head2 parse_data_v3

Parse data from a rediraction.
Data comes in ProtoBuf format

=cut

# parse_data_v3(
# #      data => $data, 
# #      list => $list, 
# #      cb => sub {...})
# # процедура (ничего не возвращает)
# # ARGUMENTS:
# # $data - тело ответа на https-запрос по redirection ссылке. двоичные данные, содержат несколько структур ProtoBuf
# #     -----------------------------------------------------------
# #     BODY      = (UINT32 CHUNKDATA)+
# #     UINT32    = Unsigned 32-bit integer in network byte order.    => число=длина след.фрагмента данных, который нужно распоковать как Protobuf
# #     CHUNKDATA = Encoded ChunkData protocol message, see below.    => данные длиной UINT32 байт, которые можно распоковать с помощью ProtoBuf
# #     -----------------------------------------------------------
# # 
# # $list - название списка (available list types: goog-malware-shavar, goog-regtest-shavar, goog-whitedomain-shavar, googpub-phish-shavar)
# # $cb - callback function

#======================================

sub parse_data {
    my ($self, %args) 	= @_;
    my $data 		= $args{data} 		|| '';
    my $list 		= $args{list} 		|| '';
    my $cb		= $args{cb} 		or die "Callback is required";
	
    my $protobuf_len = 0;
    my $protobuf_data = '';
	
    my $bulk_insert_a = [];
    my $bulk_insert_s = [];

	
    # читаем побайтно данные из $data (выдергивая их)
    while (length $data > 0) {
        $protobuf_len = unpack('N', substr($data, 0, 4, '')); # UINT32
        say Dumper($self->protobuf_struct);
        $protobuf_data = $self->protobuf_struct->decode(substr($data, 0, $protobuf_len, '')); # ref to perl hash structure
        #$protobuf_data = ChunkData->decode(substr($data, 0, $protobuf_len, '')); # ref to perl hash structure

	# perl hash format of decoded protobuf data is 
	# (~ - for optional fields. they're available throught accessor):
	# {
	#    chunk_number => int32,
	#  ~ chunk_type   => 0 or 1 (for ADD / SUB. ADD default),
	#  ~ prefix_type  => 0 or 1 (for 4B / 32B. 4B default),
	#  ~ hashes       => packed bites as string,
	#    add_numbers  => [456789, 456123, ....] список из int32, только в sub чанке используется
	# }

	my $chunk_num = $protobuf_data->chunk_number();
	my $chunk_type = $protobuf_data->chunk_type();
	my $hash_length = $protobuf_data->prefix_type() ? 32 : 4;
	
	if ($chunk_type == 0) {
            # it is add chunk
	    my @data = parse_a_v3(value => $protobuf_data->hashes(), 
			    hash_length => $hash_length);
	    foreach my $item (@data) {
	        push @$bulk_insert_a, { chunknum => $chunk_num, chunk => $item, list => $list };	
	    }	    	
	}
	elsif ($chunk_type == 1) {
	    # it is sub chunk
	    my @data = parse_s_v3( value => $protobuf_data->hashes(), 
                               hash_length => $hash_length,
                               add_chunknum => \$protobuf_data->add_numbers() );
            foreach my $item (@data) {
        	push @$bulk_insert_s, { chunknum => $chunk_num, chunk => $item, list => $list };	
            }
	}
	else {
	    # it is unknown chunk
	    log_error("Incorrect chunk type: $chunk_type, should be 0 or 1 (for a: or s:)");
	    $cb->(1);
	    return;
	} 
        # OLD: log_debug1("$type$chunk_num:$hash_length:$chunk_length OK");
	log_debug1(join "", $chunk_type ? 's:' : 'a:', "$chunk_num:$hash_length:$protobuf_len OK");
    }

    my $in_process = 0; # сколько хранилищ (add, sub) обновляется
    my $have_error = 0;

    my $watcher = sub {
	my $err = shift;
	$in_process--;
	$have_error ||= $err;
	log_debug2("Watcher parse: ".length( $data )."; ".$in_process);
	if(!$in_process){
            $cb->($have_error);
	}
    };
	
    ++$in_process if @$bulk_insert_a;
    ++$in_process if @$bulk_insert_s;
	
    #TODO add_chunks_a, add_chunks_s
    $self->storage->add_chunks_a($bulk_insert_a, $watcher) if @$bulk_insert_a;
    $self->storage->add_chunks_s($bulk_insert_s, $watcher) if @$bulk_insert_s; 
	
    return;
}

#===================================

sub parse_data_v2 {
	my ($self, %args) 	= @_;
	my $data			= $args{data}		 || '';
	my $list  			= $args{list}		 || '';
	my $cb              = $args{cb}          || die "Callback is required";
		my $chunk_num = 0;
	my $hash_length = 0;
	my $chunk_length = 0;
	my $bulk_insert_a = [];
	my $bulk_insert_s = [];
	while (length $data > 0) {
#		$in_process++;
		my $type = substr($data, 0, 2, ''); # s:34321:4:137
		if ($data  =~ /^(\d+):(\d+):(\d+)/sgi) {
			$chunk_num = $1;
			$hash_length = $2;
			$chunk_length = $3;
				# shorten data
			substr($data, 0, length($chunk_num) + length($hash_length) + length($chunk_length) + 3, '');
			my $encoded = substr($data, 0, $chunk_length, '');
			if ($type eq 's:') {
				foreach ($self->parse_s(value => $encoded, hash_length => $hash_length)){
					push @$bulk_insert_s, {chunknum => $chunk_num, chunk => $_, list => $list};
				}
				#$self->storage->add_chunks_s(chunknum => $chunk_num, chunks => [@chunks], list => $list, cb => $watcher); # Must happen all at once => not 100% sure
			}
			elsif ($type eq 'a:') {
				foreach( $self->parse_a(value => $encoded, hash_length => $hash_length)){
					push @$bulk_insert_a, {chunknum => $chunk_num, chunk => $_, list => $list}
				}
				#$self->storage->add_chunks_a(chunknum => $chunk_num, chunks => [@chunks], list => $list, cb => $watcher); # Must happen all at once => not 100% sure
			}
			else {
				log_error("Incorrect chunk type: $type, should be a: or s:");
				$cb->(1);
				return;
			}
			log_debug1("$type$chunk_num:$hash_length:$chunk_length OK");
		}
		else {
			log_error("could not parse header");
#			$watcher->(1);
			$cb->(1);
			return;
		}
	}
	my $in_process = 0;
	my $have_error = 0;
	my $watcher = sub {
		my $err = shift;
		$in_process--;
		$have_error ||= $err;
		log_debug2("Watcher parse: ".length( $data )."; ".$in_process);
		if(!$in_process){
			$cb->($have_error);
		}
	};
	$in_process++ if @$bulk_insert_s;
	$in_process++ if @$bulk_insert_a;
	$self->storage->add_chunks_s($bulk_insert_s, $watcher) if @$bulk_insert_s;
	$self->storage->add_chunks_a($bulk_insert_a, $watcher) if @$bulk_insert_a;
	return ;
}

=head2 parse_s()

Parse s chunks information for a database update.

=cut

sub parse_s {
	my ($self, %args) 	= @_;
	my $value 			= $args{value}			|| return ();
	my $hash_length 	= $args{hash_length}	|| 4;

	my @data = ();

	if( $value ){
		while (length $value > 0) {
			my $host = unpack 'V', substr($value, 0, 4, '');
			my $count = unpack 'C', substr($value, 0, 1, ''); # hex value
			if ($count == 0) { # ADDCHUNKNUM only
				my $add_chunknum = unpack 'N', substr($value, 0, 4, ''); #chunk num
				push(@data, { host => $host, add_chunknum => $add_chunknum, prefix => '' });
				log_debug1("$host $add_chunknum");
			}
			else { # ADDCHUNKNUM + PREFIX
				for(my $i = 0; $i < $count; $i++) {
					my $add_chunknum = unpack 'N', substr($value, 0, 4, ''); # DEC
					my $prefix = unpack 'H*', substr($value, 0, $hash_length, '');
					push(@data, { host => $host, add_chunknum => $add_chunknum, prefix =>  $prefix });
					log_debug1("$host $add_chunknum $prefix");
				}
			}
		}
	}
	else {
		push(@data, { add_chunknum => 0, host => 0, prefix => '' });
		log_debug1("Empty packet");
	}
	return @data;
}


=head2 parse_a()

Parse a chunks information for a database update.

=cut

sub parse_a {
	my ($self, %args)  = @_;
	my $value          = $args{value}       || return ();
	my $hash_length    = $args{hash_length} || 4;

	my @data = ();

	if( $value ){
		while (length $value > 0) {
			my $host = unpack 'V', substr($value, 0, 4, '');
			my $count = unpack 'C', substr($value, 0, 1, '');
			if ($count > 0) { # ADDCHUNKNUM only
				for(my $i = 0; $i < $count; $i++) {
					my $prefix = unpack 'H*', substr($value, 0, $hash_length, '');
					push(@data, { host => $host, prefix =>  $prefix });
					log_debug1($host." ".$prefix);
				}
			}
			else {
				push(@data, { host => $host, prefix =>  '' });
				log_debug1($host);
			}
		}
	}
	else {
		push(@data, { host => 0, prefix => '' });
		log_debug1("Empty packet");
	}
	return @data;
}

=head2 canonical_domain_suffixes()

Find all suffixes for a domain.

=cut

sub canonical_domain_suffixes {
	my ($self, $domain) 	= @_;
	my @domains = ();
	if ($domain =~ /^\d+\.\d+\.\d+\.\d+$/) { # loose check for IP address, should be enough
		return ($domain);
	} 
	my @parts = split/\./, $domain; # take 3 components
	if (scalar @parts >= 3) {
		@parts = splice (@parts, -3, 3);
		push(@domains, join('.', @parts));
		splice(@parts, 0, 1);
	}
	push(@domains, join('.', @parts));
	return @domains;
}


=head2 canonical_domain()

Find all canonical domains a domain.

=cut

sub canonical_domain {
	my ($self, $domain) 	= @_;
	my @domains = ($domain);
	if ($domain =~ /^\d+\.\d+\.\d+\.\d+$/) { # loose check for IP address, should be enough
		return @domains;
	} 
	my @parts = split/\./, $domain;
	splice(@parts, 0, -6); # take 5 top most compoments
	while (scalar @parts > 2) {
		shift @parts;
		push(@domains, join(".", @parts) );
	}
	return @domains;
}

=head2 canonical_path()

Find all canonical paths for a URL.

=cut

sub canonical_path {
	my ($self, $path) 	= @_;
	my @paths = ($path); # return full path
	if ($path =~ /\?/) {
		$path =~ s/\?.*$//;
		push(@paths, $path);
	}
	my @parts = split /\//, $path;
	my $previous = '';
	while (scalar @parts > 1 && scalar @paths < 6) {
		my $val = shift(@parts);
		$previous .= "$val/";

		push(@paths, $previous);
	}
	return @paths;
}

=head2 canonical()

Find all canonical URLs for a URL.

=cut

sub canonical {
	my ($self, $url) = @_;
	my @urls = ();
	my $uri = $self->canonical_uri($url);
	my @domains = $self->canonical_domain($uri->host);
	my @paths = $self->canonical_path($uri->path_query);
	foreach my $domain (@domains) {
		foreach my $path (@paths) {
			push(@urls, "$domain$path");
		}
	}
	return @urls;
}


=head2 canonical_uri()

Create a canonical URI.

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

=head2 canonical()

Return all possible full hashes for a URL.

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

=head2 prefix()

Return a hash prefix. The size of the prefix is set to 4 bytes.

=cut

sub prefix {
	my ($self, $string) = @_;
	return sha256($string);
}

=head2 request_full_hash()

Request full full hashes for specific prefixes from Google.

=cut

sub request_full_hash {
	my ($self, %args) 	= @_;
	my $prefixes		= $args{prefixes}; ref $prefixes eq 'ARRAY'	|| die "Arg prefixes is required and must be arrayref";
	my $cb              = $args{cb}                                 || die "Args cb is required";
	my $size			= length $prefixes->[0];
# 	# Handle errors
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

	my $url = $self->server . "gethash?client=api&apikey=" . $self->key . "&appver=$VERSION&pver=" . $self->version;
	log_debug1( "Full hash url: ". $url);

	my $prefix_list = join('', @$prefixes);
	my $header = "$size:" . scalar @$prefixes * $size;
	my $body = $header."\n".$prefix_list;
	log_debug1( "Full hash data: ". $body);
	http_post( $url, $body, %{$self->param_for_http_req}, sub {
		my ($data, $headers) = @_; 
		if( $headers->{Status} == 200 && length $data){
			log_debug1("Full hash request OK");
			log_debug3("Response body: ".$data);
			$self->data->delete('full_hash_errors/'.unpack( 'H*', $_ )) for @$prefixes;
			my @hashes = ();

			# goog-malware-shavar:22428:32HEX
			while (length $data > 0) {
				if ($data !~ /^([a-z\-]+):(\d+):(\d+)/) {
					log_error("list not found");
					$cb->([]);
					return;
				}
				my ( $list, $chunknum, $length) = ($1, $2, $3);
				substr($data,0,length($list.":".$chunknum.":".$length."\n"),'');
				my $current = 0;
				while ($current < $length) {
					my $hash = substr($data, 0, 32, '');
					push(@hashes, { hash => $hash, chunknum => $chunknum, list => $list });

					$current += 32;
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

#sub _build_protobuf_struct {
#    Google::ProtocolBuffers->parse("
#        message ChunkData {
#            required int32 chunk_number = 1;
#
#            // The chunk type is either an add or sub chunk.
#            enum ChunkType {
#                ADD = 0;
#                SUB = 1;
#            }
#            optional ChunkType chunk_type = 2 [default = ADD];
#
#            // Prefix type which currently is either 4B or 32B.  The default is set
#            // to the prefix length, so it doesn't have to be set at all for most
#            // chunks.
#         
#            enum PrefixType {
#                PREFIX_4B = 0;
#                FULL_32B = 1;
#            }
#        
#            optional PrefixType prefix_type = 3 [default = PREFIX_4B];
#            // Stores all SHA256 add or sub prefixes or full-length hashes. The number
#            // of hashes can be inferred from the length of the hashes string and the
#            // prefix type above.
#        
#            optional bytes hashes = 4;
#
#            // Sub chunks also encode one add chunk number for every hash stored above.
#        
#            repeated int32 add_numbers = 5 [packed = true];
#        }",
#
#        { create_accessors => 1 } 
#    );    
#    return ;
#}

no Mouse;
__PACKAGE__->meta->make_immutable();
 
=head1 SEE ALSO

See L<AnyEvent::Net::SafeBrowsing3::Storage>, L<AnyEvent::Net::SafeBrowsing3::Tarantool> for information on storing and managing the Safe Browsing database.

Google Safe Browsing v3 API: L<https://developers.google.com/safe-browsing/developers_guide_v3.html>

=head1 AUTHOR

Nikolay Shulyakovskiy, E<lt>shulyakovskiy@mail.ruE<gt> or E<lt>shulyakovskiy@yandex.ruE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2014 by Nikolay Shulyakovskiy

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;

