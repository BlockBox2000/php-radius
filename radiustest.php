<?
    require_once('b2radius.inc');

    $radius = new Radius('127.0.0.1', 'testing123'); 
    $radius->SetNasPort(0);
    $radius->SetNasIpAddress('1.2.3.4');
    $radius->SetAttribute(NAS_Identifier,'CPSwitch');

// SetVendorAttribute($vendor, $type, $case, $value);
// $case : T - Text, S - String, A - IPv4, I - Integer 32 bit unsigned value

    $radius->SetVendorAttribute(2636,50,'S',"test");
// 2636 vendor juniper, 50 type Juniper-CWA-Redirect, 'S' case String, "test"

    $radius->SetVendorAttribute(14823,2,'I',98);
// 14823 vendor aruba, 2 type Aruba-User-Vlan, 'I' case int32, 98

    if ($radius->AccessRequest('darenyeh', 'yhdgteHi')) {
        echo "Authentication accepted.\n";
    } else {
        echo "Authentication rejected.\n";
    }
    echo $radius->GetReadableReceivedAttributes();
?>
