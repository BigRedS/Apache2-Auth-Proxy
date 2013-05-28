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
use Apache::Htpasswd;   # libapache-htpasswd-perl
use Data::Dumper;

use Apache2::Const -compile => qw(OK DECLINED HTTP_UNAUTHORIZED);

sub handler {
	my $r = shift;
	my ($status, $password) = $r->get_basic_auth_pw;
	return $status unless $status == Apache2::Const::OK;
	$r->log_error("Empty password for user '".$r->user."'") if $password eq "";
	if(checkPassword($r->user,$password, $r)){
		return Apache2::Const::OK;
	}else{
		my $pwlen = length($password);
		$r->log_reason("Incorrect password for user '".$r->user()."' with password of $pwlen characters, '", $r->filename);
	}
	
	$r->note_basic_auth_failure;
	return Apache2::Const::HTTP_UNAUTHORIZED;
}


sub checkPassword {
	my ($username,$password, $r) = @_;
	my $url    = $ENV{'AUTHPROXY_URL'};
	my $netloc = $ENV{'AUTHPROXY_NETLOC'};
	my $realm  = $ENV{'AUTHPROXY_REALM'};
	$ENV{'PERL_LWP_SSL_VERIFY_HOSTNAME'} = $ENV{'AUTHPROXY_SSL_VERIFY_HOSTNAME'};

	my $f_cache = $ENV{'AUTHPROXY_CACHE_FILE'} || "/tmp/authproxy.cache";
	my $htpasswd = Apache::Htpasswd->new({
		passwdFile => $f_cache,
	});

	if (-f $f_cache && checkPasswordInCache($htpasswd, $username, $password)){
		$r->log_error("Auth from cache succeeded for '".$r->user."'");
		return 1;
	}else{
		$r->log_error("Auth from cache failed for '".$r->user."'");
		if(checkPasswordAgainstRemote($username, $password, $url, $netloc, $realm, $r)){
			$r->log_error("Auth from remote succeeded for '".$r->user."'");
			my $ret = updateCache($htpasswd, $username, $password, $r);
			$r->log_error("Updated Cache : [$ret]");
			return 1;
		}else{
			$r->log_error("Auth failed in cache and from remote for '".$r->user."'");
			$r->note_basic_auth_failure;
			return undef;
		}
	}

}

sub updateCache {
	my ($htpasswd,$username,$password, $r) = @_;
	if($htpasswd->fetchInfo($username) == 0){
		$r->log_error("User doesn't exist in cache; adding");
		$htpasswd->htpasswd($username, $password);
	}else{
		$r->log_error("Found stale entry in cache, updating");
		$htpasswd->htpasswd($username, $password, {'overwrite' => 1 });
	}
	return 2 unless $htpasswd->writeInfo($username, time());
}

sub checkPasswordInCache {
	my ($htpasswd, $username,$password) = @_;
	my $cache_ttl = $ENV{'AUTHPROXY_CACHE_TTL'} || 86400;
	if($htpasswd->htCheckPassword($username,$password)){
		# If the last update (against the remote server) was 
		# less than a TTL ago we will trust the htpasswd file. 
		# We make no distinction between the htpasswd (cache) file
		# having the wrong entry and having no entry.
		if( my $lastUpdate = $htpasswd->fetchInfo($username) ){
			if($lastUpdate > (time() - $cache_ttl) ){
				if($htpasswd->htCheckPassword($username, $password)){
					return ($username, $password);
				}
				return undef;
			}
			# If the last update was older than that, we shall simply 
			# delete the record
			$r->log_error("Deleting stale entry for '$username' from $lastUpdate")
			$htpasswd->htDelete($username);
			return undef;
		}
		return undef;
	}

}

sub checkPasswordAgainstRemote{
	my ($username, $password, $url, $netloc, $realm, $r) = @_;
	my $ua = LWP::UserAgent->new();
	$ua->credentials($netloc, $realm, $username, $password);
	my $response = $ua->head($url);
	if($response->is_success){
		return ($username,$password);
	}else{
		$r->log_error("LWP said: '".$response->status_line."'", $r->filename);
	}
	return;
}

1;
