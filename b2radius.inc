<?php

class Radius
{
    var $_ip_radius_server;       // Radius server IP address
    var $_shared_secret;          // Shared secret with the radius server
    var $_radius_suffix;          // Radius suffix (default is '');
    var $_udp_timeout;            // Timeout of the UDP connection in seconds (default value is 5)
    var $_authentication_port;    // Authentication port (default value is 1812)
    var $_accounting_port;        // Accouting port (default value is 1813)
    var $_coa_port;    		  // CoA port (default value is 3799)
    var $_nas_ip_address;         // NAS IP address
    var $_nas_port;               // NAS port
    var $_encrypted_password;     // Encrypted password, as described in the RFC 2865
    var $_user_ip_address;        // Remote IP address of the user
    var $_request_authenticator;  // Request-Authenticator, 16 octets random number
    var $_response_authenticator; // Request-Authenticator, 16 octets random number
    var $_username;               // Username to sent to the Radius server
    var $_password;               // Password to sent to the Radius server (clear password, must be encrypted)
    var $_identifier_to_send;     // Identifier field for the packet to be sent
    var $_identifier_received;    // Identifier field for the received packet
    var $_radius_packet_to_send;  // Radius packet code (1=Access-Request, 2=Access-Accept, 3=Access-Reject, 4=Accounting-Request, 5=Accounting-Response, 11=Access-Challenge, 12=Status-Server (experimental), 13=Status-Client (experimental), 255=Reserved
    var $_radius_packet_received; // Radius packet code (1=Access-Request, 2=Access-Accept, 3=Access-Reject, 4=Accounting-Request, 5=Accounting-Response, 11=Access-Challenge, 12=Status-Server (experimental), 13=Status-Client (experimental), 255=Reserved
    var $_attributes_to_send = array();     // Radius attributes to send
    var $_attributes_received = array();    // Radius attributes received
    var $_socket_to_server;       // Socket connection
    var $_debug_mode;             // Debug mode flag
    var $_attributes_info;        // Attributes info array
    var $_radius_packet_info;     // Radius packet codes info array
    var $_last_error_code;        // Last error code
    var $_last_error_message;     // Last error message

    public function __construct(
        $ip_radius_server = '127.0.0.1',
        $shared_secret = '',
        $radius_suffix = '',
        $udp_timeout = 5,
        $authentication_port = 1812,
        $accounting_port = 1813,
        $coa_port = 3799
    ) {
	define("User_Name",1); // string
	define("User_Password",2); // string
	define("CHAP_Password",3); // octets
	define("NAS_IP_Address",4); // ipaddr
	define("NAS_Port",5); //      integer
	define("Service_Type",6); //  integer
	define("Framed_IP_Address",8); //   ipaddr
	define("Filter_Id",11); //     string  
	define("Session_Timeout",27); //     integer
	define("Idle_Timeout",28); //     integer
	define("Termination_Action",29); //     integer
	define("Called_Station_Id",30); //     string
	define("Calling_Station_Id",31); //     string
	define("NAS_Identifier",32); //     string
	define("NAS_Port_Type",61); //     integer
	define("Acct_Status_Type",40); // integer - 1 : start, 2 : stop, 3 : Interim-Update
	define("Acct_Delay_Time",41); //     integer
	define("Acct_Input_Octets",42); //     integer
	define("Acct_Output_Octets",43); //     integer
	define("Acct_Session_Id",44); //     string
	define("Acct_Authentic",45); //     integer
	define("Acct_Session_Time",46); //     integer
	define("Acct_Input_Packets",47); //     integer
	define("Acct_Output_Packets",48); //     integer
	define("Acct_Terminate_Cause",49); //     integer
	define("Event_Timestamp",55); // date

        $this->_radius_packet_info[1] = 'Access-Request';
        $this->_radius_packet_info[2] = 'Access-Accept';
        $this->_radius_packet_info[3] = 'Access-Reject';
        $this->_radius_packet_info[4] = 'Accounting-Request';
        $this->_radius_packet_info[5] = 'Accounting-Response';
        $this->_radius_packet_info[11] = 'Access-Challenge';
        $this->_radius_packet_info[12] = 'Status-Server (experimental)';
        $this->_radius_packet_info[13] = 'Status-Client (experimental)';
        $this->_radius_packet_info[255] = 'Reserved';
        
        $this->_attributes_info[1] = array('User-Name', 'S');
        $this->_attributes_info[2] = array('User-Password', 'S');
        $this->_attributes_info[3] = array('CHAP-Password', 'S'); // Type (1) / Length (1) / CHAP Ident (1) / String
        $this->_attributes_info[4] = array('NAS-IP-Address', 'A');
        $this->_attributes_info[5] = array('NAS-Port', 'I');
        $this->_attributes_info[6] = array('Service-Type', 'I');
        $this->_attributes_info[7] = array('Framed-Protocol', 'I');
        $this->_attributes_info[8] = array('Framed-IP-Address', 'A');
        $this->_attributes_info[9] = array('Framed-IP-Netmask', 'A');
        $this->_attributes_info[10] = array('Framed-Routing', 'I');
        $this->_attributes_info[11] = array('Filter-Id', 'T');
        $this->_attributes_info[12] = array('Framed-MTU', 'I');
        $this->_attributes_info[13] = array('Framed-Compression', 'I');
        $this->_attributes_info[14] = array( 'Login-IP-Host', 'A');
        $this->_attributes_info[15] = array('Login-service', 'I');
        $this->_attributes_info[16] = array('Login-TCP-Port', 'I');
        $this->_attributes_info[17] = array('(unassigned)', '');
        $this->_attributes_info[18] = array('Reply-Message', 'T');
        $this->_attributes_info[19] = array('Callback-Number', 'S');
        $this->_attributes_info[20] = array('Callback-Id', 'S');
        $this->_attributes_info[21] = array('(unassigned)', '');
        $this->_attributes_info[22] = array('Framed-Route', 'T');
        $this->_attributes_info[23] = array('Framed-IPX-Network', 'I');
        $this->_attributes_info[24] = array('State', 'S');
        $this->_attributes_info[25] = array('Class', 'S');
        $this->_attributes_info[26] = array('Vendor-Specific', 'S'); // Type (1) / Length (1) / Vendor-Id (4) / Vendor type (1) / Vendor length (1) / Attribute-Specific...
        $this->_attributes_info[27] = array('Session-Timeout', 'I');
        $this->_attributes_info[28] = array('Idle-Timeout', 'I');
        $this->_attributes_info[29] = array('Termination-Action', 'I');
        $this->_attributes_info[30] = array('Called-Station-Id', 'S');
        $this->_attributes_info[31] = array('Calling-Station-Id', 'S');
        $this->_attributes_info[32] = array('NAS-Identifier', 'S');
        $this->_attributes_info[33] = array('Proxy-State', 'S');
        $this->_attributes_info[34] = array('Login-LAT-Service', 'S');
        $this->_attributes_info[35] = array('Login-LAT-Node', 'S');
        $this->_attributes_info[36] = array('Login-LAT-Group', 'S');
        $this->_attributes_info[37] = array('Framed-AppleTalk-Link', 'I');
        $this->_attributes_info[38] = array('Framed-AppleTalk-Network', 'I');
        $this->_attributes_info[39] = array('Framed-AppleTalk-Zone', 'S');

        $this->_attributes_info[40] = array('Acct-Status-Type', 'I');
        $this->_attributes_info[41] = array('Acct-Delay-Time', 'I');
        $this->_attributes_info[42] = array('Acct-Input-Octets', 'I');
        $this->_attributes_info[43] = array('Acct-Output-Octets', 'I');
        $this->_attributes_info[44] = array('Acct-Session-Id', 'S');
        $this->_attributes_info[45] = array('Acct-Authentic', 'I');
        $this->_attributes_info[46] = array('Acct-Session-Time', 'I');
        $this->_attributes_info[47] = array('Acct-Input-Packets', 'I');
        $this->_attributes_info[48] = array('Acct-Output-Packets', 'I');
        $this->_attributes_info[49] = array('Acct-Terminate-Cause', 'S');
        $this->_attributes_info[55] = array('Event-Timestamp', 'S');

        $this->_attributes_info[60] = array('CHAP-Challenge', 'S');
        $this->_attributes_info[61] = array('NAS-Port-Type', 'I');
        $this->_attributes_info[62] = array('Port-Limit', 'I');
        $this->_attributes_info[63] = array('Login-LAT-Port', 'S');
        $this->_attributes_info[64] = array('Tunnel-Type', 'I');
        $this->_attributes_info[65] = array('Tunnel-Medium-Type', 'I');
        $this->_attributes_info[76] = array('Prompt', 'I');
        $this->_attributes_info[81] = array('Tunnel-Private-Group-Id', 'S');

	$this->_AVALUE["Service-Type"][1]="Login-User";
	$this->_AVALUE["Service-Type"][2]="Framed-User";
	$this->_AVALUE["Service-Type"][3]="Callback-Login-User";
	$this->_AVALUE["Service-Type"][4]="Callback-Framed-User";
	$this->_AVALUE["Service-Type"][5]="Outbound-User";
	$this->_AVALUE["Service-Type"][6]="Administrative-User";
	$this->_AVALUE["Service-Type"][7]="NAS-Prompt-User";
	$this->_AVALUE["Service-Type"][8]="Authenticate-Only";
	$this->_AVALUE["Service-Type"][9]="Callback-NAS-Prompt";
	$this->_AVALUE["Service-Type"][10]="Call-Check";
	$this->_AVALUE["Service-Type"][11]="Callback-Administrative";
	$this->_AVALUE["Service-Type"][17]="Authorize-Only";
	$this->_AVALUE["Service-Type"][18]="Framed-Management";

	$this->_AVALUE["Tunnel-Type"][1]="PPTP";
	$this->_AVALUE["Tunnel-Type"][2]="L2F";
	$this->_AVALUE["Tunnel-Type"][3]="L2TP";
	$this->_AVALUE["Tunnel-Type"][4]="ATMP";
	$this->_AVALUE["Tunnel-Type"][5]="VTP";
	$this->_AVALUE["Tunnel-Type"][6]="AH";
	$this->_AVALUE["Tunnel-Type"][7]="IP";
	$this->_AVALUE["Tunnel-Type"][8]="MIN-IP";
	$this->_AVALUE["Tunnel-Type"][9]="ESP";
	$this->_AVALUE["Tunnel-Type"][10]="GRE";
	$this->_AVALUE["Tunnel-Type"][11]="DVS";
	$this->_AVALUE["Tunnel-Type"][12]="IP-in-IP";
	$this->_AVALUE["Tunnel-Type"][13]="VLAN";

	$this->_AVALUE["Tunnel-Medium-Type"][1]="IPv4";
	$this->_AVALUE["Tunnel-Medium-Type"][2]="IPv6";
	$this->_AVALUE["Tunnel-Medium-Type"][3]="NSAP";
	$this->_AVALUE["Tunnel-Medium-Type"][4]="HDLC";
	$this->_AVALUE["Tunnel-Medium-Type"][5]="BBN-1822";
	$this->_AVALUE["Tunnel-Medium-Type"][6]="IEEE-802";
	$this->_AVALUE["Tunnel-Medium-Type"][7]="E.163";
	$this->_AVALUE["Tunnel-Medium-Type"][8]="E.164";
	$this->_AVALUE["Tunnel-Medium-Type"][9]="F.69";
	$this->_AVALUE["Tunnel-Medium-Type"][10]="X.121";
	$this->_AVALUE["Tunnel-Medium-Type"][11]="IPX";
	$this->_AVALUE["Tunnel-Medium-Type"][12]="Appletalk";
	$this->_AVALUE["Tunnel-Medium-Type"][13]="DecNet-IV";
	$this->_AVALUE["Tunnel-Medium-Type"][14]="Banyan-Vines";
	$this->_AVALUE["Tunnel-Medium-Type"][15]="E.164-NSAP";

        $this->_identifier_to_send = 0;
        $this->_user_ip_address = (isset($_SERVER['REMOTE_ADDR'])?$_SERVER['REMOTE_ADDR']:'0.0.0.0');
        
        $this->GenerateRequestAuthenticator();
        $this->SetIpRadiusServer($ip_radius_server);
        $this->SetSharedSecret($shared_secret);
        $this->SetAuthenticationPort($authentication_port);
        $this->SetAccountingPort($accounting_port);
        $this->SetCoAPort($coa_port);
        $this->SetRadiusSuffix($radius_suffix);
        $this->SetUdpTimeout($udp_timeout);
        $this->SetUsername();
        $this->SetPassword();
        $this->SetNasIpAddress();
        $this->SetNasPort();
        
        $this->ClearLastError();
        $this->ClearDataToSend();
        $this->ClearDataReceived();
    }


    function GetNextIdentifier()
    {
        $this->_identifier_to_send = (($this->_identifier_to_send + 1) % 256);
        return $this->_identifier_to_send;
    }
    

    function GenerateRequestAuthenticator()
    {
        $this->_request_authenticator = '';
        for ($ra_loop = 0; $ra_loop <= 15; $ra_loop++)
        {
            $this->_request_authenticator .= chr(rand(1, 255));
        }
    }


    function GetRequestAuthenticator()
    {
        return $this->_request_authenticator;
    }


    function GetLastError()
    {
        if (0 < $this->_last_error_code)
        {
            return $this->_last_error_message.' ('.$this->_last_error_code.')';
        }
        else
        {
            return '';
        }
    }
    
    
    function ClearDataToSend()
    {
        $this->_radius_packet_to_send = 0;
        $this->_attributes_to_send = array();
    }
    
    
    function ClearDataReceived()
    {
        $this->_radius_packet_received = 0;
        $this->_attributes_received = array();
    }
    

    function SetPacketCodeToSend($packet_code)
    {
        $this->_radius_packet_to_send = $packet_code;
    }
    
    
    function SetDebugMode($debug_mode)
    {
        $this->_debug_mode = (TRUE === $debug_mode);
    }
    
    
    function SetIpRadiusServer($ip_radius_server)
    {
        $this->_ip_radius_server = gethostbyname($ip_radius_server);
    }
    
    
    function SetSharedSecret($shared_secret)
    {
        $this->_shared_secret = $shared_secret;
    }
    
    
    function SetRadiusSuffix($radius_suffix)
    {
        $this->_radius_suffix = $radius_suffix;
    }
    
    
    function SetUsername($username = '')
    {
        $temp_username = $username;
        if (false === strpos($temp_username, '@'))
        {
            $temp_username .= $this->_radius_suffix;
        }
        
        $this->_username = $temp_username;
        $this->SetAttribute(1, $this->_username);
    }
    
    
    function SetPassword($password = '')
    {
        $this->_password = $password;
        $encrypted_password = '';
        $padded_password = $password;
        
        if (0 != (strlen($password)%16))
        {
            $padded_password .= str_repeat(chr(0),(16-strlen($password)%16));
        }
        
        $previous_result = $this->_request_authenticator;
        
        for ($full_loop = 0; $full_loop < (strlen($padded_password)/16); $full_loop++)
        {
            $xor_value = md5($this->_shared_secret.$previous_result);
            
            $previous_result = '';
            for ($xor_loop = 0; $xor_loop <= 15; $xor_loop++)
            {
                $value1 = ord(substr($padded_password, ($full_loop * 16) + $xor_loop, 1));
                $value2 = hexdec(substr($xor_value, 2*$xor_loop, 2));
                $xor_result = $value1 ^ $value2;
                $previous_result .= chr($xor_result);
            }
            $encrypted_password .= $previous_result;
        }
        
        $this->_encrypted_password = $encrypted_password;
        $this->SetAttribute(2, $this->_encrypted_password);
    }


    function SetNasIPAddress($nas_ip_address = '')
    {
        if (0 < strlen($nas_ip_address))
        {
            $this->_nas_ip_address = gethostbyname($nas_ip_address);
        }
        else
        {
            $this->_nas_ip_address = gethostbyname(isset($_SERVER['SERVER_ADDR'])?$_SERVER['SERVER_ADDR']:'0.0.0.0');
        }
        $this->SetAttribute(4, $this->_nas_ip_address);
    }
    
    
    function SetNasPort($nas_port = 0)
    {
        $this->_nas_port = intval($nas_port);
        $this->SetAttribute(5, $this->_nas_port);
    }
    
    
    function SetUdpTimeout($udp_timeout = 5)
    {
        if (intval($udp_timeout) > 0)
        {
            $this->_udp_timeout = intval($udp_timeout);
        }
    }
    
    
    function ClearLastError()
    {
        $this->_last_error_code    = 0;
        $this->_last_error_message = '';
    }
    
    
    function SetAuthenticationPort($authentication_port)
    {
        if ((intval($authentication_port) > 0) && (intval($authentication_port) < 65536))
        {
            $this->_authentication_port = intval($authentication_port);
        }
    }
    
    
    function SetAccountingPort($accounting_port)
    {
        if ((intval($accounting_port) > 0) && (intval($accounting_port) < 65536))
        {
            $this->_accounting_port = intval($accounting_port);
        }
    }
    
    function SetCoAPort($coa_port)
    {
        if ((intval($coa_port) > 0) && (intval($coa_port) < 65536))
        {
            $this->_coa_port = intval($coa_port);
        }
    }
    
    function GetReceivedPacket()
    {
        return $this->_radius_packet_received;
    }


    function GetReceivedAttributes()
    {
        return $this->_attributes_received;
    }
    

    function GetReadableReceivedAttributes()
    {
        $readable_attributes = '';
        if (isset($this->_attributes_received))
        {
            foreach($this->_attributes_received as $one_received_attribute)
            {
                $attributes_info = $this->GetAttributesInfo($one_received_attribute[0]);
                $readable_attributes .= $attributes_info[0].": ";
                if (26 == $one_received_attribute[0])
                {
                    $vendor_array = $this->DecodeVendorSpecificContent($one_received_attribute[1]);
                    foreach($vendor_array as $vendor_one)
                    {
                        $readable_attributes .= 'Vendor-Id: '.$vendor_one[0].", Vendor-type: ".$vendor_one[1].",  Attribute-specific: ".$vendor_one[2];
                    }
                }
                else
                {
                  if ( $this->_AVALUE[$attributes_info[0]][$one_received_attribute[1]] ) {
                    $readable_attributes .= $this->_AVALUE[$attributes_info[0]][$one_received_attribute[1]];
                  } else {
                    $readable_attributes .= $one_received_attribute[1];
                  }
                }
                $readable_attributes .= "\n";
            }
        }
        return $readable_attributes;
    }
    

    function GetAttribute($attribute_type)
    {
        $attribute_value = NULL;
        foreach($this->_attributes_received as $one_received_attribute)
        {
            if (intval($attribute_type) == $one_received_attribute[0])
            {
                $attribute_value = $one_received_attribute[1];
                break;
            }
        }
        return $attribute_value;
    }


    function GetRadiusPacketInfo($info_index)
    {
        if (isset($this->_radius_packet_info[intval($info_index)]))
        {
            return $this->_radius_packet_info[intval($info_index)];
        }
        else
        {
            return '';
        }
    }


    function GetAttributesInfo($info_index)
    {
        if (isset($this->_attributes_info[intval($info_index)]))
        {
            return $this->_attributes_info[intval($info_index)];
        }
        else
        {
            return array('','');
        }
    }


    function DebugInfo($debug_info)
    {
        if ($this->_debug_mode)
        {
            echo date('Y-m-d H:i:s').' DEBUG: ';
            echo $debug_info;
            echo "\n";
            flush();
        }
    }
    
    
    function SetAttribute($type, $value)
    {
        $attribute_index = -1;
        for ($attributes_loop = 0; $attributes_loop < count($this->_attributes_to_send); $attributes_loop++)
        {
            if ($type == ord(substr($this->_attributes_to_send[$attributes_loop], 0, 1)))
            {
                $attribute_index = $attributes_loop;
                break;
            }
        }

        $temp_attribute = NULL;
        
        if (isset($this->_attributes_info[$type]))
        {
            switch ($this->_attributes_info[$type][1])
            {
                case 'T': // Text, 1-253 octets containing UTF-8 encoded ISO 10646 characters (RFC 2279).
                    $temp_attribute = chr($type).chr(2+strlen($value)).$value;
                    break;
                case 'S': // String, 1-253 octets containing binary data (values 0 through 255 decimal, inclusive).
                    $temp_attribute = chr($type).chr(2+strlen($value)).$value;
                    break;
                case 'A': // Address, 32 bit value, most significant octet first.
                    $ip_array = explode(".", $value);
                    $ip_array = (count($ip_array) < 4) ? array('0', '0', '0', '0') : $ip_array;
                    $temp_attribute = chr($type).chr(6).chr($ip_array[0]).chr($ip_array[1]).chr($ip_array[2]).chr($ip_array[3]);
                    break;
                case 'I': // Integer, 32 bit unsigned value, most significant octet first.
                    $temp_attribute = chr($type).chr(6).chr(($value/(256*256*256))%256).chr(($value/(256*256))%256).chr(($value/(256))%256).chr($value%256);
                    break;
                case 'D': // Time, 32 bit unsigned value, most significant octet first -- seconds since 00:00:00 UTC, January 1, 1970. (not used in this RFC)
                    $temp_attribute = NULL;
                    break;
                default:
                    $temp_attribute = NULL;
            }
        }
                    
        if ($attribute_index > -1)
        {
            $this->_attributes_to_send[$attribute_index] = $temp_attribute;
            $additional_debug = 'Modified';
        }
        else
        {
            $this->_attributes_to_send[] = $temp_attribute;
            $additional_debug = 'Added';
        }
        $attribute_info = $this->GetAttributesInfo($type);
        $this->DebugInfo($additional_debug.' Attribute '.$type.' ('.$attribute_info[0].'), format '.$attribute_info[1].', value <em>'.$value.'</em>');
    }

    function SetVendorAttribute($vendor, $type, $case, $value)
    {
        $attribute_index = -1;
        $temp_attribute = NULL;
        $temp_attribute2 = NULL;
        
        switch ($case)
        {
                case 'T': // Text, 1-253 octets containing UTF-8 encoded ISO 10646 characters (RFC 2279).
                    $temp_attribute2 = chr($type).chr(2+strlen($value)).$value;
                    break;
                case 'S': // String, 1-253 octets containing binary data (values 0 through 255 decimal, inclusive).
                    $temp_attribute2 = chr($type).chr(2+strlen($value)).$value;
                    break;
                case 'A': // Address, 32 bit value, most significant octet first.
                    $ip_array = explode(".", $value);
                    $ip_array = (count($ip_array) < 4) ? array('0', '0', '0', '0') : $ip_array;
                    $temp_attribute2 = chr($type).chr(6).chr($ip_array[0]).chr($ip_array[1]).chr($ip_array[2]).chr($ip_array[3]);
                    break;
                case 'I': // Integer, 32 bit unsigned value, most significant octet first.
                    $temp_attribute2 = chr($type).chr(6).chr(($value/(256*256*256))%256).chr(($value/(256*256))%256).chr(($value/(256))%256).chr($value%256);
                    break;
                case 'D': // Time, 32 bit unsigned value, most significant octet first -- seconds since 00:00:00 UTC, January 1, 1970. (not used in this RFC)
                    $temp_attribute2 = NULL;
                    break;
                default:
                    $temp_attribute2 = NULL;
        }

        $temp_attribute = chr(26).chr(2+4+strlen($temp_attribute2)).pack('N',$vendor).$temp_attribute2;
        $this->_attributes_to_send[] = $temp_attribute;
        $additional_debug = 'Added';
        $attribute_info = $this->GetAttributesInfo($type);
        $this->DebugInfo($additional_debug.' Attribute '.$type.' ('.$attribute_info[0].'), format '.$attribute_info[1].', value <em>'.$value.'</em>');
    }

    function DecodeAttribute($attribute_raw_value, $attribute_format)
    {
        $attribute_value = NULL;
        
        if (isset($this->_attributes_info[$attribute_format]))
        {
            switch ($this->_attributes_info[$attribute_format][1])
            {
                case 'T': // Text, 1-253 octets containing UTF-8 encoded ISO 10646 characters (RFC 2279).
                    $attribute_value = $attribute_raw_value;
                    break;
                case 'S': // String, 1-253 octets containing binary data (values 0 through 255 decimal, inclusive).
                    $attribute_value = $attribute_raw_value;
                    break;
                case 'A': // Address, 32 bit value, most significant octet first.
                    $attribute_value = ord(substr($attribute_raw_value, 0, 1)).'.'.ord(substr($attribute_raw_value, 1, 1)).'.'.ord(substr($attribute_raw_value, 2, 1)).'.'.ord(substr($attribute_raw_value, 3, 1));
                    break;
                case 'I': // Integer, 32 bit unsigned value, most significant octet first.
                    $attribute_value = (ord(substr($attribute_raw_value, 0, 1))*256*256*256)+(ord(substr($attribute_raw_value, 1, 1))*256*256)+(ord(substr($attribute_raw_value, 2, 1))*256)+ord(substr($attribute_raw_value, 3, 1));
                    break;
                case 'D': // Time, 32 bit unsigned value, most significant octet first -- seconds since 00:00:00 UTC, January 1, 1970. (not used in this RFC)
                    $attribute_value = NULL;
                    break;
                default:
                    $attribute_value = NULL;
            }
        }
        return $attribute_value;
    }


    /*********************************************************************
     * Array returned: array(array(Vendor-Id1, Vendor type1, Attribute-Specific1), ..., array(Vendor-IdN, Vendor typeN, Attribute-SpecificN)
     *********************************************************************/
    function DecodeVendorSpecificContent($vendor_specific_raw_value)
    {
        $result = array();
        $offset_in_raw = 0;
        $vendor_id = (ord(substr($vendor_specific_raw_value, 0, 1))*256*256*256)+(ord(substr($vendor_specific_raw_value, 1, 1))*256*256)+(ord(substr($vendor_specific_raw_value, 2, 1))*256)+ord(substr($vendor_specific_raw_value, 3, 1));
        $offset_in_raw += 4;
        while ($offset_in_raw < strlen($vendor_specific_raw_value))
        {
            $vendor_type = (ord(substr($vendor_specific_raw_value, 0+$offset_in_raw, 1)));
            $vendor_length = (ord(substr($vendor_specific_raw_value, 1+$offset_in_raw, 1)));
            $attribute_specific = substr($vendor_specific_raw_value, 2+$offset_in_raw, $vendor_length);
            $result[] = array($vendor_id, $vendor_type, $attribute_specific);
            $offset_in_raw += ($vendor_length);
        }
        
        return $result;
    }


    /*
     * Function : AccessRequest
     *
     * Return TRUE if Access-Request is accepted, FALSE otherwise
     */
    function AccessRequest($username = '', $password = '', $udp_timeout = 0, $state = NULL)
    {
        $this->ClearDataReceived();
        $this->ClearLastError();
        
        $this->SetPacketCodeToSend(1); // Access-Request
        
        if (0 < strlen($username))
        {
            $this->SetUsername($username);
        }
        
        if (0 < strlen($password))
        {
            $this->SetPassword($password);
        }

        if ($state!==NULL)
        {
            $this->SetAttribute(24, $state);
        }

        if (intval($udp_timeout) > 0)
        {
            $this->SetUdpTimeout($udp_timeout);
        }

        $attributes_content = '';
        for ($attributes_loop = 0; $attributes_loop < count($this->_attributes_to_send); $attributes_loop++)
        {
            $attributes_content .= $this->_attributes_to_send[$attributes_loop];
        }

        $packet_length  = 4; // Radius packet code + Identifier + Length high + Length low
        $packet_length += strlen($this->_request_authenticator); // Request-Authenticator
        $packet_length += strlen($attributes_content); // Attributes
        
        $packet_data  = chr($this->_radius_packet_to_send);
        $packet_data .= chr($this->GetNextIdentifier());
        $packet_data .= chr(intval($packet_length/256));
        $packet_data .= chr(intval($packet_length%256));
        $packet_data .= $this->_request_authenticator;
        $packet_data .= $attributes_content;

        $_socket_to_server = socket_create(AF_INET, SOCK_DGRAM, 17); // UDP packet = 17
        
        if ($_socket_to_server === FALSE)
        {
            $this->_last_error_code    = socket_last_error();
            $this->_last_error_message = socket_strerror($this->_last_error_code);
        }
        elseif (FALSE === socket_connect($_socket_to_server, $this->_ip_radius_server, $this->_authentication_port))
        {
            $this->_last_error_code    = socket_last_error();
            $this->_last_error_message = socket_strerror($this->_last_error_code);
        }
        elseif (FALSE === socket_write($_socket_to_server, $packet_data, $packet_length))
        {
            $this->_last_error_code    = socket_last_error();
            $this->_last_error_message = socket_strerror($this->_last_error_code);
        }
        else
        {
            $this->DebugInfo('<b>Packet type '.$this->_radius_packet_to_send.' ('.$this->GetRadiusPacketInfo($this->_radius_packet_to_send).')'.' sent</b>');
            if ($this->_debug_mode)
            {
                $readable_attributes = '';
                foreach($this->_attributes_to_send as $one_attribute_to_send)
                {
                    $attribute_info = $this->GetAttributesInfo(ord(substr($one_attribute_to_send,0,1)));
                    $this->DebugInfo('Attribute '.ord(substr($one_attribute_to_send,0,1)).' ('.$attribute_info[0].'), length '.(ord(substr($one_attribute_to_send,1,1))-2).', format '.$attribute_info[1].', value <em>'.$this->DecodeAttribute(substr($one_attribute_to_send,2), ord(substr($one_attribute_to_send,0,1))).'</em>');
                }
            }
            $read_socket_array   = array($_socket_to_server);
            $write_socket_array  = NULL;
            $except_socket_array = NULL;

            $received_packet = chr(0);

            if (!(FALSE === socket_select($read_socket_array, $write_socket_array, $except_socket_array, $this->_udp_timeout)))
            {
                if (in_array($_socket_to_server, $read_socket_array))
                {
                    if (FALSE === ($received_packet = @socket_read($_socket_to_server, 1024))) // @ used, than no error is displayed if the connection is closed by the remote host
                    {
                        $received_packet = chr(0);
                        $this->_last_error_code    = socket_last_error();
                        $this->_last_error_message = socket_strerror($this->_last_error_code);
                    }
                    else
                    {
                        socket_close($_socket_to_server);
                    }
                }
            }
            else
            {
                socket_close($_socket_to_server);
            }
        }

        $this->_radius_packet_received = intval(ord(substr($received_packet, 0, 1)));
        
        $this->DebugInfo('<b>Packet type '.$this->_radius_packet_received.' ('.$this->GetRadiusPacketInfo($this->_radius_packet_received).')'.' received</b>');
        
        if ($this->_radius_packet_received > 0)
        {
            $this->_identifier_received = intval(ord(substr($received_packet, 1, 1)));
            $packet_length = (intval(ord(substr($received_packet, 2, 1))) * 256) + (intval(ord(substr($received_packet, 3, 1))));
            $this->_response_authenticator = substr($received_packet, 4, 16);
            $attributes_content = substr($received_packet, 20, ($packet_length - 4 - 16));
            while (strlen($attributes_content) > 2)
            {
                $attribute_type = intval(ord(substr($attributes_content,0,1)));
                $attribute_length = intval(ord(substr($attributes_content,1,1)));
                $attribute_raw_value = substr($attributes_content,2,$attribute_length-2);
                $attributes_content = substr($attributes_content, $attribute_length);

                $attribute_value = $this->DecodeAttribute($attribute_raw_value, $attribute_type);

                $attribute_info = $this->GetAttributesInfo($attribute_type);
                if (26 == $attribute_type)
                {
                    $vendor_array = $this->DecodeVendorSpecificContent($attribute_value);
                    foreach($vendor_array as $vendor_one)
                    {
                        $this->DebugInfo('Attribute '.$attribute_type.' ('.$attribute_info[0].'), length '.($attribute_length-2).', format '.$attribute_info[1].', Vendor-Id: '.$vendor_one[0].", Vendor-type: ".$vendor_one[1].",  Attribute-specific: ".$vendor_one[2]);
                    }
                }
                else
                {
                    $this->DebugInfo('Attribute '.$attribute_type.' ('.$attribute_info[0].'), length '.($attribute_length-2).', format '.$attribute_info[1].', value <em>'.$attribute_value.'</em>');
                }

                $this->_attributes_received[] = array($attribute_type, $attribute_value);
            }
        }
        
        return (2 == ($this->_radius_packet_received));
    }

}

?>