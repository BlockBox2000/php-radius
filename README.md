# php-radius
A simple pure PHP RADIUS client supporting Standard and Vendor-Specific Attributes in single file
## Author:

* Daren Yeh <dhy901224@gmail.com>
* Tiffany Liu <tiffany917306775@gmail.com>

## Description:

BlockBox-Radius is a simple pure PHP RADIUS client for authenticating users against
a RADIUS server following the RFC 2865 rules (http://www.ietf.org/rfc/rfc2865.txt)
The current branch is tested to work with the following RADIUS servers:

- Microsoft Windows Server Network Policy Server
- FreeRADIUS 2 and above 
- WinRadius

## System Requirements:

PHP 5.x - 8.x

## Installation: 

Just download the release archive and extract to a location
on your server.  In your application, `require_once 'b2radius.inc';` and
then you can use the class.

## Usage:

require_once('b2radius.inc');<br>
$radius = new Radius($ip_radius_server = 'radius_server_ip_address', $shared_secret = 'radius_shared_secret'[, $radius_suffix = 'optional_radius_suffix'[, $udp_timeout = udp_timeout_in_seconds[, $authentication_port = 1812]]]);<br>
$result = $radius->Access_Request($username = 'username', $password = 'password'[, $udp_timeout = udp_timeout_in_seconds]);<br>

## Examples:

<?<br>
    require_once('b2radius.inc');<br>
<br>
    $radius = new Radius('127.0.0.1', 'testing123'); <br>
    $radius->SetNasPort(0);<br>
    $radius->SetNasIpAddress('1.2.3.4');<br>
    $radius->SetAttribute(NAS_Identifier,'CPSwitch');<br>
<br>
// SetVendorAttribute($vendor, $type, $case, $value);<br>
// $case : T - Text, S - String, A - IPv4, I - Integer 32 bit unsigned value<br>
<br>
    $radius->SetVendorAttribute(2636,50,'S',"test");<br>
// 2636 vendor juniper, 50 type Juniper-CWA-Redirect, 'S' case String, "test"<br>
<br>
    $radius->SetVendorAttribute(14823,2,'I',98);<br>
// 14823 vendor aruba, 2 type Aruba-User-Vlan, 'I' case int32, 98<br>
<br>
    if ($radius->AccessRequest('darenyeh', 'yhdgteHi')) {<br>
        echo "Authentication accepted.\n";<br>
    } else {<br>
        echo "Authentication rejected.\n";<br>
    }<br>
    echo $radius->GetReadableReceivedAttributes();<br>
?><br>

## Roadmap:

1. RADIUS Accounting
2. RADIUS CoA Disconnect
3. RADIUS CoA Request
