package Apache2::Auth::Proxy::Authorization
  
use strict;
use warnings;
  
use Apache2::Access;
use Apache2::RequestUtil;
use Apache2::Log;

use Apache2::Const -compile => qw(OK HTTP_UNAUTHORIZED);
  
sub handler {
    my $r = shift;

    my $user = $r->user;
    if ($user) {
      return Apache2::Const::OK;
    }
    $r->note_basic_auth_failure;
    $r->log_reason("Authz",$r->filename);
    return Apache2::Const::HTTP_UNAUTHORIZED;
}

1;
