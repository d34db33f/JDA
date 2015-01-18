<?php
$path=$_GET["path"];
$fp = fopen($path, "rb");
header('Content-Disposition: attachment; filename='.basename($path));
header('Content-Type: application/octet-stream');
header("Content-Length: " . filesize($path));
fpassthru($fp);