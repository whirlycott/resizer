#!/usr/bin/perl -w

# Copyright 2012 Philip Jacob <phil@whirlycott.com>
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

use strict;
use warnings;
use CGI;
use Digest::SHA qw(hmac_sha1_hex);
use LWP::Simple;
use Image::Size;
use MIME::Base64;
use Scalar::Util qw(looks_like_number);
use File::Temp;
use Log::Message::Simple qw(carp croak cluck confess);

########################################################################
# BEGIN CONFIGURATION
#

# You *must* change this!  Yes, you, the one reading this!  Change this to some random and 
# secret string before you deploy it.  
my $secret = "17b2a1b1c00651a50f842aeb637afca796343629";

# Quality for the image (in percent).
my $quality = 95;

# Emit far-future cache control and expires headers?  Set to 0 if not.
my $caching_days = 365;

# Adjust the path to contain the netpbm binaries.
$ENV{'PATH'} = "/usr/local/bin/:/usr/bin/:/bin/";

#
# END CONFIGURATION
########################################################################

# Get the params
my $cgi 	= CGI->new();
my $x 		= $cgi->param('x') ? $cgi->param('x') : "";
my $y 		= $cgi->param('y') ? $cgi->param('y') : "";
my $en_url 	= $cgi->param('url') ? $cgi->param('url') : "";
my $hmac 	= $cgi->param('hmac') ? $cgi->param('hmac') : "";

# Decode the URL
my $url = decode_base64($en_url);
debug("Trying to resize $url to $x x $y");

# Verify the checksum.  The purpose of this is to stop people from using your webservice without 
# your authorization.  This is a heavy script and it would be no big deal to cause a DoS attack.
# I know you think that a simple sha1 will suffice, but you would be wrong.
# See http://benlog.com/articles/2008/06/19/dont-hash-secrets/
my $digest = hmac_sha1_hex("$x $y $en_url", $secret);
if ($digest ne $hmac) {
	fatal("Checksum mismatch: $digest");
}

# Validate the params.
# TODO - tighten up security around acceptable URLs.
if ( !looks_like_number($x) || !looks_like_number($y) || !$url || !$hmac ) {
	fatal("The input params didn't validate ($x, $y, $url, $hmac)");
}

# Get the source image and put it into a file.
debug("Getting $url");
my $content = get($url) || fatal("Couldn't get $url");

# Make some temp files.
my $input  = new File::Temp();
my $output = new File::Temp();

# Write the input.
print $input $content;

# Enable autoflushing of filehandles.  Don't change this.
$| = 1;

# Resize or pad the image?
my ($calculated_x, $calculated_y) = get_image_size($input);
debug("Input image dimensions calculated as $calculated_x and $calculated_y"); 

my $command = "";
if ($calculated_x <= $x && $calculated_y <= $y) {
    # Pad it up
    debug("Padding...");
    $command = "anytopnm $input | pnmpad -white -width=$x -height=$y -halign=0.5 -valign=0.5 | pnmtojpeg -quality=$quality > $output";

} else {
    # Scale it down
    debug("Scaling down...");
    $command = "anytopnm $input | pamscale -xyfit $x $y | pnmpad -white -width=$x -height=$y -halign=0.5 -valign=0.5 | pnmtojpeg -quality=$quality > $output";
}

# Kick off the resizing.
my $retcode = `$command`;

# Get the file size for the content-length header.
my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks) = stat($output);

# Emit headers
print $cgi->header(
			-type => "image/jpeg", 
			-Content_length => $size,
			-expires => $caching_days ? "+" . $caching_days . "d" : "now",
			-Cache_Control => $caching_days ? $caching_days * 86400 : 0);

while (<$output>) {
	print $_;
}

# Subs

sub get_image_size {
	my ($fh) = @_;
	my ($x_actual, $y_actual, $type) = imgsize($fh);
	if (!defined $x_actual || !defined $y_actual) {
		fatal("Couldn't get the image dimensions");
	}
	return ($x_actual, $y_actual);
}

sub debug {
	my ($msg) = @_;
	carp("$0 $msg");
}

sub fatal {
	my ($msg) = @_;
	print $cgi->header(-status => 500, -content_type => "text/plain"), $msg;
	croak("$0 $msg");
	exit 1;
}
