<?php

$DB_CREDECNTIALS_FILE = "ENTER PATH FOR db.php"

// DO NOT EDIT BELOW
header("Content-Type: text/plain");
require $DB_CREDECNTIALS_FILE;

mysqli_select_db($db, "sniffler");

if ("cbm" == $_GET['value']){
    $value = "dal";
    $varname = "cbm";
}
elseif ("lpm" == $_GET['value']){
    $value = "clpm";
    $varname = "lpm";
} else {
    die("WHAAAT?");
}

$sql="SELECT UNIX_TIMESTAMP(capture_time) * 1000 AS capture_time, TRUNCATE($value / 100,2) as value FROM water_raw_data order by capture_time";
$result = mysqli_query($db, $sql);

echo "var $varname =[\n";
while($myrow=mysqli_fetch_assoc($result)){
    echo "[$myrow[capture_time],$myrow[value]],\n";
}
echo "[]]\n";

?>
