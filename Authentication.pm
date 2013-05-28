package Apache2::Auth::Proxy::Authentication;

use strict;
use warnings;

use Apache2::Access;
use Apache2::Module qw/add/;
use Apache2::Directive;
use Apache2::RequestUtil;
use Apache2::RequestRec;
use Apache2::Const -compile => qw/FLAG/;
use Apache2::Log;
use LWP::UserAgent;    # libwww-perl

use Data::Dumper;

use Apache2::Const -compile => qw(OK DECLINED HTTP_UNAUTHORIZED);

my $conf;

my @directives = (
	{
		name => "HTTPAuthProxyURI",
	},
	{
		name => "HTTPAuthProxySSL",
		args_how => Apache2::Const::FLAG,
	},
	{
		name => "HTTPAuthProxySSLVerifyHostname",
		args_how => Apache2::Const::FLAG

	}
);

Apache2::Module::add(__PACKAGE__, \@directives);

sub HTTPAuthProxyURI {
	my ($self, $parms, $arg) = @_;
	$conf->{'HTTPAuthProxyURI'} = $arg;
}

sub HTTPAuthProxySSL {
	my ($self, $params, $arg) = @_;
	$self->{'HTTPAuthProxySSL'} = $arg;
}

sub HTTPAuthProxySSLVerifyHostname {
	my ($self, $params, $arg) = @_;
	$self->{'HTPAuthProxySSLVerifyHostname'} = $arg;
}



sub handler {
	my $r = shift;
	my ($status, $password) = $r->get_basic_auth_pw;
	return $status unless $status == Apache2::Const::OK;
	$r->log_error("Empty password for user '".$r->user."'") if $password eq "";
	if(checkPassword($r->user,$password, $r)){
		return Apache2::Const::OK;
	}else{
		my $pwlen = length($password);
		$r->log_reason("Incorrect password for user '".$r->user()." ($password), '", $r->filename);
	}
	
	$r->note_basic_auth_failure;
	return Apache2::Const::HTTP_UNAUTHORIZED;
}

sub checkPassword {
	my ($username,$password, $r) = @_;
#	my $url = "https://admin.positive-internet.com";
#	my $netloc = "admin.positive-internet.com:443";
#	my $realm = "DB Admin";
	my $url = "http://truth.posiweb.net/ips";
	my $netloc = "truth.posiweb.net:80";
	my $realm = "Here be dragons. And cake.";
	$r->log_reason("VERIFY_HOSTNAME set to :".$conf->{'HTTPAuthProxySSLVerifyHostname'});
	$ENV{'PERL_LWP_SSL_VERIFY_HOSTNAME'} = $conf->{'HTTPAuthProxySSLVerifyHostname'};
	my $ua = LWP::UserAgent->new();
	$ua->credentials($netloc, $realm, $username, $password);
	my $response = $ua->head($url);
	if($response->is_success){
		return "1";
	}else{
		$r->log_reason("LWP said ".$response->status_line, $r->filename);
	}
	return;
}

sub checkPasswordInCache {
	my $cacheFile = "/tmp/.htpasswdcache";
	




}

1;
