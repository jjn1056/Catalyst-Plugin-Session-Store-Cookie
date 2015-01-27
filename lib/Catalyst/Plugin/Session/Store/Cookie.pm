package Catalyst::Plugin::Session::Store::Cookie;

use Moose;
use Session::Storage::Secure;
use MRO::Compat;

extends 'Catalyst::Plugin::Session::Store';
with 'Catalyst::ClassData';

our $VERSION = '0.001';

__PACKAGE__->mk_classdata($_)
  for qw/_secure_store _store_cookie_name _store_cookie_expires/;

sub get_session_data {
  my ($self, $key) = @_;
  $self->_needs_early_session_finalization(1);
  my $cookie = $self->req->cookie($self->_store_cookie_name);
  $self->{__cookie_session_store_cache__} = defined($cookie) ? $self->_secure_store->decode($cookie->value) : {};

  return $self->{__cookie_session_store_cache__}->{$key};
}

sub store_session_data {
  my ($self, $key, $data) = @_;

  $self->{__cookie_session_store_cache__} = +{
    %{$self->{__cookie_session_store_cache__}},
    $key => $data};

  return $self->res->cookies->{$self->_store_cookie_name} = {
    value => $self->_secure_store->encode($self->{__cookie_session_store_cache__}),
    expires => $self->_store_cookie_expires};
}

sub delete_session_data {
  my ($self, $key) = @_;
  delete $self->{__cookie_session_store_cache__}->{$key};
}

# Docs say 'this may be used in the future', like 10 years ago...
sub delete_expired_sessions { }

sub setup_session {
  my $class = shift;
  my $cfg = $class->_session_plugin_config;
  $class->_store_cookie_name($cfg->{storage_cookie_name} || lc($class).'_sstore');
  $class->_store_cookie_expires($cfg->{storage_cookie_expires} || '+1d');
  $class->_secure_store(
    Session::Storage::Secure->new(
      secret_key => $cfg->{secret_key},
      sereal_encoder_options => { snappy => 1, stringify_unknown => 1 },
      sereal_decoder_options => { validate_utf8 => 1 }));

  return $class->maybe::next::method(@_);
}

__PACKAGE__->meta->make_immutable;

=head1 NAME

Catalyst::Plugin::Session::Store::Cookie - Store session data in the cookie

=head1 SYNOPSIS

    TBD

=head1 DESCRIPTION

What's old is new again...

Store session data in the client cookie.  Handy when you don't want to setup
yet another storage system just for supporting sessions and authentication.
Can be very fast since you avoid the overhead of requesting and deserializing
session information from whatever you are using to store it.  Since Sessions
in L<Catalyst> are global you can use this to reduce per request overhead.

The downsides are that you can really only count on about 4Kb of storage space
on the cookie.  Also, that cookie data becomes part of every request so that
will increase overhead on the request side of the network.  In other words a big
cookie means more data over the wire (maybe you are paying by the byte...?)

In any case if all you are putting in the session is a user id and a few basic
things this will probably be totally fine and likely a lot more sane that using
something non persistant like memcache.  On the other hand if you like to dump
a bunch of stuff into the user session, this will likely not work out.  We
do try to compress information when we store it, so you can get a lot into that
4Kb if you find it wise...

For security, we encrypt the compressed serialized information.  Please see the
security section below.

B<NOTE> Since we need to store all the session info in the cookie, the session
state will be set at ->finalize_headers stage (rather than at ->finalize_body
which is the default for session storage plugins).  What this means is that if
you use the streaming or socket interfaces ($c->response->write, $c->response->write_fh
and $c->req->io_fh) your session state will get saved early.  For example you
cannot do this:

    $c->res->write("some stuff");
    $c->session->{key} = "value";

That key 'key' will not be recalled when the session is recovered for the following
request.  In general this should be an easy issue to work around, but you need
to be aware of it.

=head1 CONFIGURATION

This plugin supports the following configuration settings, which are stored as
a hash ref under the configuration key 'Plugin::Session::Store::Cookie', for
example:

    package MyApp;

    use Catalyst qw/
      Session
      Session::State::Cookie
      Session::Store::Cookie
    /;

    __PACKAGE__->config('Plugin::Session::Store::Cookie' => \%store_config);
    __PACKAGE__->setup;

=head1 AUTHOR
 
John Napiorkowski L<email:jjnapiork@cpan.org>
  
=head1 SEE ALSO
 
L<Catalyst>, L<Catalyst::Plugin::Session>

=head1 COPYRIGHT & LICENSE
 
Copyright 2015, John Napiorkowski L<email:jjnapiork@cpan.org>
 
This library is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut

