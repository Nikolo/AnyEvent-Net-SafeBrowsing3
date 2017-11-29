package AnyEvent::Net::SafeBrowsing3::Tarantool;

use utf8;
use strict;
use Mouse;
use AnyEvent::Tarantool;
use AnyEvent::Tarantool::Cluster;

extends 'AnyEvent::Net::SafeBrowsing3::Storage';

=head1 NAME

AnyEvent::Net::SafeBrowsing3::Tarantool - Tarantool as back-end storage for the Safe Browsing v3 database 

=head1 SYNOPSIS

AnyEvent::Net::SafeBrowsing3::Storage cannot be used directly. Instead, use a class inheriting AnyEvent::Net::SafeBrowsing3::Storage, like L<AnyEvent::Net::SafeBrowsing3::Tarantool>.


  use AnyEvent::Net::SafeBrowsing3::Tarantool;

  my $storage = AnyEvent::Net::SafeBrowsing3::Tarantool->new({host => '127.0.0.1', port => '33013', a_chunks_space => 0, s_chunks_space => 1, full_hashes_space => 2, connected_cb =>  $cb});
  ...
  $storage->close();

=head1 DESCRIPTION

This is an implementation of L<AnyEvent::Net::SafeBrowsing3::Storage> using Tarantool.

=cut


=head1 CONSTRUCTOR

=over 4

=back

=head2 new()

Create a AnyEvent::Net::SafeBrowsing3::Tarantool object

  my $storage = AnyEvent::Net::SafeBrowsing3::Tarantool->new({
      master_server      => '127.0.0.1:33013',
	  slave_server       => '127.0.0.1:34014', 
	  a_chunks_space     => 0, 
	  s_chunks_space     => 1, 
	  full_hashes_space  => 2, 
	  connected_cb       => sub {}
  });

Arguments

=over 4

=item master_server

Required. Tarantool master servers host:port

=item slave_server

Optional. Tarantool slave servers host:port

=item a_chunks_space

Required. Number of space for add chunks

=item s_chunks_space

Required. Number of space for add chunks

=item full_hashes_space

Required. Number of space for full hashes

=item connected_cb

Required. Callback CodeRef

=back

=cut

has a_chunks_space    => (is => 'rw', isa => 'Int', required => 1);
has s_chunks_space    => (is => 'rw', isa => 'Int', required => 1);
has full_hashes_space => (is => 'rw', isa => 'Int', required => 1);
has timeout           => (is => 'ro', isa => 'Int', default  => 1);
has all_connected     => (is => 'ro', isa => 'CodeRef', default => sub {return sub{}});

=head1 PUBLIC FUNCTIONS

=over 4

See L<AnyEvent::Net::SafeBrowsing3::Storage> for a complete list of public functions.

=back

=cut

sub BUILD {
	my $self = shift;
	eval "use ".$self->log_class.";";
	die $@ if $@;
	my $servers = [];
	die "master_server is required" unless $self->master_server;
	foreach( split ',', $self->master_server ){
		my $srv = {master => 1};
		($srv->{host}, $srv->{port}) = split ":", $_;
		push @$servers, $srv;
	}
	foreach( split ',', $self->slave_server ){
		my $srv = {};
		($srv->{host}, $srv->{port}) = split ":", $_;
		push @$servers, $srv;
	}
	$self->dbh(AnyEvent::Tarantool::Cluster->new(
		servers => $servers,
		timeout => $self->timeout,
		spaces => {
			$self->a_chunks_space() => {
				name         => 'a_chunks',
				fields       => [qw/list chunknum prefix/],
				types        => [qw/STR  NUM      STR/],
				indexes      => {
					0 => {
						name => 'idx_a_uniq',
						fields => ['list', 'chunknum', 'prefix'],
					},
					1 => {
						name => 'idx_a_list_prefix',
						fields => ['list', 'prefix'],
					},
				},
			},
			$self->s_chunks_space() => {
				name         => 's_chunks',
				fields       => [qw/list chunknum add_num prefix/],
				types        => [qw/STR  NUM      NUM     STR/],
				indexes      => {
					0 => {
						name => 'idx_s_uniq',
						fields => ['list', 'chunknum', 'add_num', 'prefix'],
					},
					1 => {
						name => 'idx_s_list_prefix',
						fields => ['list', 'prefix'],
					},
				},
			},
			$self->full_hashes_space() => {
				name         => 'full_hashes',
				fields       => [qw/list prefix hash timestamp/],
				types        => [qw/STR  STR    STR  NUM/],
				indexes      => {
					0 => {
						name => 'idx_h_uniq',
						fields => ['list', 'prefix', 'hash'],
					},
					1 => {
						name => 'idx_h_prefix',
						fields => ['list', 'prefix'],
					},
					2 => {
						name => 'idx_h_hash',
						fields => ['list', 'hash'],
					},
				}
			},
		},
		all_connected => $self->all_connected,
	));
	return $self;
}

sub get_regions {
	my ($self, %args) = @_;
	my $list          = $args{list}                          or die "list arg is required";
	my $cb            = $args{cb}; ref $args{'cb'} eq 'CODE' or die "cb arg is required and must be CODEREF";
	if ($self->dbh && $self->dbh->master) {
		$self->dbh->master->lua( 'safebrowsing3.get_regions3', [$self->a_chunks_space(), $self->s_chunks_space(), $list], {in => 'ppp', out => 'p'}, sub {
			my ($data, $error) = @_;
			if( $error ){
				log_error( 'Tarantool error: '.$error );
				$cb->();
			}
			else {
				if( $data->{tuples}->[0]->[0] && $data->{tuples}->[0]->[0] ne ';' ){
					my ($ret_a, $ret_s) = ('','');
					($ret_a, $ret_s) = split(';', $data->{tuples}->[0]->[0]);
					$cb->($ret_a, $ret_s);
				}
				else {
					$cb->('','');
				}
			}
			return;
		});
	}
	else {
		log_error( 'SafeBrowsing3 tarantool master-server is unavailable' );
		$cb->();
	}
	return;
}

sub delete_add_chunks {
	my ($self, %args) = @_;
	my $chunknums     = $args{chunknums}                         or die "chunknums arg is required";
	my $list          = $args{'list'}                            or die "list arg is required";
	my $cb            = $args{'cb'};   ref $args{'cb'} eq 'CODE' or die "cb arg is required and must be CODEREF";
	if ($self->dbh && $self->dbh->master) {
		$self->dbh->master->lua( 'safebrowsing3.del_chunks_a3', [$self->a_chunks_space(),JSON::XS->new->encode([map +{list => $list, chunknum => $_}, @$chunknums])], {in => 'pp', out => 'p'}, sub {
			my ($result, $error) = @_;
			log_error( "Tarantool error: ",$error ) if $error;
			$cb->($error ? 1 : 0);
		});
	}
	else {
		log_error( 'SafeBrowsing3 tarantool master-server is unavailable' );
		$cb->(1);
	}
	return;
}

sub delete_sub_chunks {
	my ($self, %args) = @_;
	my $chunknums     = $args{chunknums}                         or die "chunknums arg is required";
	my $list          = $args{'list'}                            or die "list arg is required";
	my $cb            = $args{'cb'};   ref $args{'cb'} eq 'CODE' or die "cb arg is required and must be CODEREF";
	if ($self->dbh && $self->dbh->master) {
		$self->dbh->master->lua( 'safebrowsing3.del_chunks_s3', [$self->s_chunks_space(),JSON::XS->new->encode([map +{list => $list, chunknum => $_}, @$chunknums])], {in => 'pp', out => 'p'}, sub {
			my ($result, $error) = @_;
			log_error( "Tarantool error: ",$error ) if $error;
			$cb->($error ? 1 : 0);
		});
	}
	else {
		log_error( 'SafeBrowsing3 tarantool master-server is unavailable' );
		$cb->(1);
	}
	return;
}

# select tuples from a_chunks using index1 (list + prefix)
# in callback returns reference to array of fields:
# (list, chunknum, prefix)
# $ret = [ {list => res1_list, chunknum => res1_chunknum, prefix => res1_prefix},
#          {list => res2_list, chunknum => res2_chunknum, prefix => res2_prefix},
#          ..... ]
sub get_add_chunks {
	my ($self, %args) = @_;
	my $prefix        = $args{prefix}                            or die "prefix arg is required";
	my $list          = $args{'lists'}                           or die "lists arg is required";
	my $cb            = $args{'cb'};   ref $args{'cb'} eq 'CODE' or die "cb arg is required and must be CODEREF";

	if ($self->dbh && $self->dbh->slave) {
		$self->dbh->slave->select('a_chunks', [map [$_, $prefix], @$list], {index => 1}, sub{
			my ($result, $error) = @_;
			if( $error || !$result->{count} ){
				log_error( "Tarantool error: ".$error ) if $error;
				$cb->([]);
			}
			else {
				if ($self->dbh && $self->dbh->master) {
					my $space = $self->dbh->master->{spaces}->{a_chunks};
					my $ret = [];
					foreach my $tup ( @{$result->{tuples}} ){
						push @$ret, {map {$_->{name} => $tup->[$_->{no}]||''} @{$space->{fields}}}
					}
					$cb->($ret); 
				}
				else {
					log_error( 'SafeBrowsing3 tarantool master-server is unavailable' );
					$cb->([]);
				}
			}
		});
	}
	else {
		log_error( 'SafeBrowsing3 tarantool slave-server is unavailable' );
		$cb->([]);
	}
	return;
}

# select tuples from s_chunks using index1 (list + prefix)
# in callback returns reference to array of fields:
# (list, chunknum, add_num, prefix)
# $ret = [ {list => res1_list, chunknum => res1_chunknum, add_num => res1_add_num, prefix => res1_prefix},
#          {list => res2_list, chunknum => res2_chunknum, add_num => res2_add_num, prefix => res2_prefix},
#          ..... ]
sub get_sub_chunks {
	my ($self, %args) = @_;
	my $prefix        = $args{prefix}                            or die "prefix arg is required";
	my $list          = $args{'lists'}                           or die "lists arg is required";
	my $cb            = $args{'cb'};   ref $args{'cb'} eq 'CODE' or die "cb arg is required and must be CODEREF";
	if ($self->dbh && $self->dbh->slave) {
		$self->dbh->slave->select('s_chunks', [map [$_,$prefix], @$list], {index => 1}, sub{
			my ($result, $error) = @_;
			if( $error || !$result->{count} ){
				log_error( "Tarantool error: ".$error ) if $error;
				$cb->([]);
			}
			else {
				if ($self->dbh && $self->dbh->master) {
					my $space = $self->dbh->master->{spaces}->{s_chunks};
					my $ret = [];
					foreach my $tup ( @{$result->{tuples}} ){
						push @$ret, {map {$_->{name} => $tup->[$_->{no}]||''} @{$space->{fields}}}
					}
					$cb->($ret); 
				}
				else {
					log_error( 'SafeBrowsing3 tarantool master-server is unavailable' );
					$cb->([]);
				}
			}
		});
	}
	else {
		log_error( 'SafeBrowsing3 tarantool slave-server is unavailable' );
		$cb->([]);
	}
	return;
}

sub delete_full_hashes {
	my ($self, %args) = @_;
	my $chunknums     = $args{chunknums}                         || die "chunknums arg is required";
	my $list          = $args{'list'}                            || die "list arg is required";
	my $cb            = $args{'cb'};   ref $args{'cb'} eq 'CODE' || die "cb arg is required and must be CODEREF";
	if ($self->dbh && $self->dbh->master) {
		$self->dbh->master->lua( 'safebrowsing3.del_full_hash3', [$self->full_hashes_space(),JSON::XS->new->encode([map +{list => $list, chunknum => $_}, @$chunknums])], {in => 'pp', out => 'p'}, sub {
			my ($result, $error) = @_;
			log_error( "Tarantool error: ",$error ) if $error;
			$cb->($error ? 1 : 0);
		});
	}
	else {
		log_error( 'SafeBrowsing3 tarantool master-server is unavailable' );
		$cb->(1);
	}
	return;
}

# searches full hashes by prefix (4 byte)
# if found hash with expired date, remove it from database
sub get_full_hashes {
	my ($self, %args) = @_;
	my $prefix        = $args{'prefix'}                          or die "prefix arg is required";
	my $list          = $args{'list'}                            or die "lists arg is required";
	my $timestamp     = $args{'timestamp'}                       or die "timestamp arg is required";
	my $cb            = $args{'cb'};   ref $args{'cb'} eq 'CODE' or die "cb arg is required and must be CODEREF";

	if ($self->dbh && $self->dbh->slave) {
		$self->dbh->slave->select('full_hashes', [[$list,$prefix]], {index => 1}, sub{
			my ($result, $error) = @_;
			if( $error || !$result->{count} ){
				log_error( "Tarantool error (select full hashes): ".$error ) if $error;
				$cb->([]);
			}
			else {
				if ($self->dbh && $self->dbh->master) {
					my $space = $self->dbh->master->{spaces}->{full_hashes};
					my $ret = [];
					foreach my $tup ( @{$result->{tuples}} ){
						if( $tup->[$space->{fast}->{timestamp}->{no}] < $timestamp ){
							if ($self->dbh && $self->dbh->master) {
								$self->dbh->master->delete('full_hashes', [$tup->[0], $tup->[1], $tup->[2]], sub {
									my ($result, $error) = @_;
									log_error( "Tarantool error: ".$error ) if $error;
								});
							}
							else { log_error( "Can't call delete method: SafeBrowsing3 tarantool master-server is unavailable" ) }
						}
						else {
							push @$ret, {map {$_->{name} => $tup->[$_->{no}]||''} @{$space->{fields}}}
						}
					}
					$cb->($ret); 
				}
				else {
					log_error( 'SafeBrowsing3 tarantool master-server is unavailable' );
					$cb->([]);
				}
			}
		});
	}
	else {
		log_error( 'SafeBrowsing3 tarantool slave-server is unavailable' );
		$cb->([]);
	}
	return;
}

sub add_chunks_s {
	my ($self, $chunks, $cb) = @_;
	ref $cb eq 'CODE' || die "cb arg is required and must be CODEREF";
	if ($self->dbh && $self->dbh->master) {
		$self->dbh->master->lua( 'safebrowsing3.add_chunks_s3', [$self->s_chunks_space(),JSON::XS->new->encode($chunks)], {in => 'pp', out => 'p'}, sub {
			my ($result, $error) = @_;
			log_error( "Tarantool error: ", $error ) if $error;
			$cb->($error ? 1 : 0);
		});
		log_debug1("STORED s chunks");
	}
	else {
		log_error( 'SafeBrowsing3 tarantool master-server is unavailable' );
		$cb->(1);
	}
}

sub add_chunks_a {
	my ($self, $chunks, $cb) = @_;
	ref $cb eq 'CODE' or die "cb arg is required and must be CODEREF";
	if ($self->dbh && $self->dbh->master) {
		$self->dbh->master->lua( 'safebrowsing3.add_chunks_a3', [$self->a_chunks_space(),JSON::XS->new->encode($chunks)], {in => 'pp', out => 'p'}, sub {
			my ($result, $error) = @_;
			log_error( "Tarantool error: ", $error ) if $error;
			$cb->($error ? 1 : 0);
		});
		log_debug1("STORED a chunks");
	}
	else {
		log_error( 'SafeBrowsing3 tarantool master-server is unavailable' );
		$cb->(1);
	}
}

sub add_full_hashes {
	my ($self, %args) 	= @_;
	my $full_hashes   = $args{full_hashes}                       or die "full_hashes arg is required";
	my $cb            = $args{'cb'};   ref $args{'cb'} eq 'CODE' or die "cb arg is required and must be CODEREF";

	my $err = 0;
	foreach my $fhash (@$full_hashes) {
	        if ($self->dbh && $self->dbh->master) {
			$self->dbh->master->insert('full_hashes', [$fhash->{list}, unpack("H*", $fhash->{prefix}), unpack("H*", $fhash->{hash}), $fhash->{timestamp}], sub {
				my ($result, $error) = @_;
				log_error( "Tarantool error: ".$error ) if $error;
				log_debug1(join " ", "added full hash. prefix = ", $fhash->{prefix}, " hash = ", $fhash->{hash});
				$err ||= $error;
			});
		}
		else {
			$err ||= 1;
			log_error( 'SafeBrowsing3 tarantool master-server is unavailable' );
		}
	}
	$cb->($err ? 1 : 0);
	return;
}


no Mouse;
__PACKAGE__->meta->make_immutable();

=head1 SEE ALSO

See L<AnyEvent::Net::SafeBrowsing3> for handling Safe Browsing v3.

See L<AnyEvent::Net::SafeBrowsing3::Storage> for the list of public functions.

Google Safe Browsing v3 API: L<https://developers.google.com/safe-browsing/developers_guide_v3>

=head1 AUTHOR

Nikolay Shulyakovskiy, E<lt>shulyakovskiy@mail.ruE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2015 by Nikolay Shulyakovskiy

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.


=cut

1;

