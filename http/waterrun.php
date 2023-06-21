<?php

// A simple script I wrote to allow my shelly unit to tell whenever the irrigation system runs
// This allows me to then know how much water each irrigation cycle consumed.

$DB_CREDECNTIALS_FILE = "ENTER PATH FOR db.php";

// DO NOT EDIT BELOW
require $DB_CREDECNTIALS_FILE;

mysqli_select_db($db, "sniffler");

$action = $_GET['action'];
$line = $_GET['line'];

function sanitize_num($what, $max){
	if (!is_numeric($what) || 0 > $what || $max < $what){
    		die("WHAAAT?");
	}
}
sanitize_num($action,1);
sanitize_num($line,2);

// Create an entry
if (0 == $action){
	$sql = "INSERT INTO irrigation_tracker VALUES (NULL, NOW(), NOW(), $line)";
	mysqli_query($db, $sql);
}elseif(1 == $action){
	// Get previous entry ID
	$sql = "select * from irrigation_tracker where start_time = end_time and line = 2 order by start_time desc";
	$result = mysqli_query($db, $sql);
	$myrow=mysqli_fetch_assoc($result);
	sanitize_num($myrow[id], 999999999999999999999999999);

	// Update latest entry
	$sql = "update irrigation_tracker set end_time = NOW() where id = $myrow[id]";
	mysqli_query($db, $sql);
}

?>
