package Catalyst::Plugin::Session::Store::Cookie;

use Moose;
use Session::Storage::Secure;
use MRO::Compat;
use Catalyst::Utils;

extends 'Catalyst::Plugin::Session::Store';
with 'Catalyst::ClassData';

our $VERSION = '0.002';

__PACKAGE__->mk_classdata($_)
  for qw/_secure_store _store_cookie_name _store_cookie_expires/;

sub get_session_data {
  my ($self, $key) = @_;
  $self->_needs_early_session_finalization(1);
  my $cookie = $self->req->cookie($self->_store_cookie_name);
  $self->{__cookie_session_store_cache__} = defined($cookie) ? 
    $self->_secure_store->decode($cookie->value) : {};

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
  $class->_store_cookie_name($cfg->{storage_cookie_name} || Catalyst::Utils::appprefix($class) . '_store');
  $class->_store_cookie_expires($cfg->{storage_cookie_expires} || '+1d');
  $class->_secure_store(
    Session::Storage::Secure->new(
      secret_key => $cfg->{storage_secret_key} ||
        die "storage_secret_key' configuration param for 'Catalyst::Plugin::Session::Store::Cookie' is missing!",
      sereal_encoder_options => { snappy => 1, stringify_unknown => 1 },
      sereal_decoder_options => { validate_utf8 => 1 }));

  return $class->maybe::next::method(@_);
}

__PACKAGE__->meta->make_immutable;

=head1 NAME

Catalyst::Plugin::Session::Store::Cookie - Store session data in the cookie

=head1 SYNOPSIS

    package MyApp;

    use Catalyst qw/
      Session
      Session::State::Cookie
      Session::Store::Cookie
    /;

    my %store_config = (
      'Plugin::Session' => {
        storage_cookie_name => ...,
        storage_cookie_expires => ...,
        storage_secret_key => ...,
    );

    __PACKAGE__->config('Plugin::Session::Store::Cookie' => \%store_config);
    __PACKAGE__->setup;

=head1 DESCRIPTION

What's old is new again...

Store session data in the client cookie, like in 1995.  Handy when you don't
want to setup yet another storage system just for supporting sessions and
authentication. Can be very fast since you avoid the overhead of requesting and
deserializing session information from whatever you are using to store it.
Since Sessions in L<Catalyst> are global you can use this to reduce per request
overhead.  On the other hand you may just use this for early prototying and
then move onto something else for production.  I'm sure you'll do the right
thing ;)

The downsides are that you can really only count on about 4Kb of storage space
on the cookie.  Also, that cookie data becomes part of every request so that
will increase overhead on the request side of the network.  In other words a big
cookie means more data over the wire (maybe you are paying by the byte...?)

Also there are some questions as to the security of this approach.  We encrypt 
information with L<Session::Storage::Secure> so you should review that and the
notes that it includes.  Using this without SSL/HTTPS is not recommended.  Buyer
beware.

In any case if all you are putting in the session is a user id and a few basic
things this will probably be totally fine and likely a lot more sane that using
something non persistant like memcached.  On the other hand if you like to dump
a bunch of stuff into the user session, this will likely not work out.

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
a hash ref under the configuration key 'Plugin::Session::Store::Cookie'.  See
L</SYNOPSIS> for example.

=head2 storage_cookie_name

The name of the cookie that stores your session data on the client.  Defaults
to '${$myapp}_sstore' (where $myappp is the lowercased version of your application
subclass).  You may wish something less obvious.

=head2 storage_cookie_expires

How long before the cookie that is storing the session info expires.  defaults
to '+1d'.  Lower is more secure but bigger hassle for your user.  You choose the
right balance.

=head2 storage_secret_key

Used to fill the 'secret_key' initialization parameter for L<Session::Storage::Secure>.
Don't let this be something you can guess or something that escapes into the
wild...

There is no default for this, you need to supply.

=head1 AUTHOR
 
John Napiorkowski L<email:jjnapiork@cpan.org>
  
=head1 SEE ALSO
 
L<Catalyst>, L<Catalyst::Plugin::Session>, L<Session::Storage::Secure>

=head1 COPYRIGHT & LICENSE
 
Copyright 2015, John Napiorkowski L<email:jjnapiork@cpan.org>
 
This library is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut

