<?php
// api.php

// Make sure to put your config file full path here
require '/var/www/config.php';

header('Content-Type: application/json');

$metric = isset($_GET['metric']) ? $_GET['metric'] : 'flow'; 
$range  = isset($_GET['range']) ? $_GET['range'] : '24h';

// Helper: PHP 7 Compatible Interval
function getInterval($r) {
    switch ($r) {
        case '7d': return '7 DAY';
        case '30d': return '30 DAY';
        case '1y': return '1 YEAR';
        default: return '1 DAY';
    }
}
$interval = getInterval($range);

// ---------------------------------------------------------
// 1. ANOMALY ENGINE (IN-MEMORY CORRELATION)
// ---------------------------------------------------------
if ($metric === 'anomalies') {
    if ($range === '1y') $range = '30d'; // Limit complex analysis to 30d
    $interval = getInterval($range);

    try {
        // QUERY 1: Fetch ALL Irrigation Runs for period
        $runSql = "SELECT id, line, 
                          UNIX_TIMESTAMP(start_time) as start_ts, 
                          UNIX_TIMESTAMP(end_time) as end_ts 
                   FROM irrigation_tracker 
                   WHERE start_time >= NOW() - INTERVAL $interval
                   ORDER BY start_time ASC";
        $runs = $pdo->query($runSql)->fetchAll();

        // QUERY 2: Fetch ALL Water Data for period (Sequential Scan = Fast)
        // We fetch a bit extra (5 mins buffer) for the isolation check
        $waterSql = "SELECT UNIX_TIMESTAMP(capture_time) as ts, 
                            dal, clpm, error_codes 
                     FROM water_raw_data 
                     WHERE capture_time >= NOW() - INTERVAL $interval - INTERVAL 5 MINUTE
                     ORDER BY capture_time ASC";
        $waterData = $pdo->query($waterSql)->fetchAll();

        $plotBands = [];
        $points = [];
        $waterCount = count($waterData);
        $wIdx = 0; // Pointer to avoid rescanning array

        foreach ($runs as $run) {
            $rStart = (int)$run['start_ts'];
            $rEnd   = (int)$run['end_ts'];
            $line   = (int)$run['line'];

            // Initialize Stats
            $minDal = null; $maxDal = null;
            $maxFlow = 0; $errMask = 0;
            $preNoise = 0; $postNoise = 0;

            // 1. Advance Pointer to 5 mins BEFORE run
            $bufferStart = $rStart - 300;
            while ($wIdx < $waterCount && $waterData[$wIdx]['ts'] < $bufferStart) {
                $wIdx++;
            }

            // 2. Scan forward (without moving main pointer too far)
            $scanIdx = $wIdx;
            while ($scanIdx < $waterCount) {
                $row = $waterData[$scanIdx];
                $ts = (int)$row['ts'];

                // Stop if we went past 5 mins AFTER run
                if ($ts > $rEnd + 300) break;

                // A. Check Pre-Run Noise (Isolation)
                if ($ts >= $bufferStart && $ts < $rStart) {
                    $preNoise += (int)$row['clpm'];
                }
                // B. Check Post-Run Noise (Isolation)
                elseif ($ts > $rEnd && $ts <= $rEnd + 300) {
                    $postNoise += (int)$row['clpm'];
                }
                // C. Check Inside Run
                elseif ($ts >= $rStart && $ts <= $rEnd) {
                    $val = (int)$row['dal'];
                    if ($minDal === null || $val < $minDal) $minDal = $val;
                    if ($maxDal === null || $val > $maxDal) $maxDal = $val;
                    if ((int)$row['clpm'] > $maxFlow) $maxFlow = (int)$row['clpm'];
                    $errMask |= (int)$row['error_codes'];
                }
                $scanIdx++;
            }

            // Calculate derived stats
            $vol = ($maxDal !== null && $minDal !== null) ? ($maxDal - $minDal) * 10 : 0;
            $flow = $maxFlow / 100;
            $is_isolated = ($preNoise < 100 && $postNoise < 100);

            // LOGIC APPLICATION
            $status = 'OK'; $msg = 'Normal Run'; $color = 'rgba(74, 222, 128, 0.1)';

            if (($errMask & 256) > 0) {
                $status = 'CRITICAL'; $msg = 'Hardware Alarm (During Run)'; $color = 'rgba(255, 99, 71, 0.6)';
            } elseif (($line === 0 || $line === 1) && ($vol > 700 || $flow > 35)) {
                $status = 'LEAK'; $msg = "Excessive Usage ($vol L)"; $color = 'rgba(255, 165, 0, 0.5)';
            } elseif ($line === 2) {
                if ($flow == 0) {
                    $status = 'CLOG'; $msg = "Valve Failed / No Flow"; $color = 'rgba(128, 128, 128, 0.5)';
                } elseif ($is_isolated && ($vol > 50 || $flow > 10)) {
                    $status = 'BURST'; $msg = "Confirmed Line 2 Burst"; $color = 'rgba(255, 165, 0, 0.5)';
                    $points[] = ['x' => $rStart * 1000, 'y' => $flow, 'title' => 'Burst'];
                }
            }

            $plotBands[] = [
                'id' => 'band_' . $run['id'],
                'from' => $rStart * 1000,
                'to' => $rEnd * 1000,
                'color' => $color,
                'details' => ['line' => $line, 'status' => $status, 'msg' => $msg, 'vol' => $vol, 'flow' => $flow]
            ];
        }

        // Global Hardware Scan (using the already fetched $waterData)
        foreach ($waterData as $row) {
            if (((int)$row['error_codes'] & 256) > 0) {
                $points[] = [
                    'x' => (int)$row['ts'] * 1000,
                    'y' => (float)$row['clpm'] / 100,
                    'title' => 'HW Alarm (256)',
                    'marker' => ['fillColor' => '#ff0000', 'radius' => 6]
                ];
            }
        }

        echo json_encode(['plotBands' => $plotBands, 'points' => $points]);

    } catch (PDOException $e) {
        http_response_code(500); echo json_encode(['error' => $e->getMessage()]);
    }
    exit;
}

// ---------------------------------------------------------
// 2. STANDARD METRICS
// ---------------------------------------------------------
$columns = ['flow' => 'clpm', 'volume' => 'dal'];
$col = array_key_exists($metric, $columns) ? $columns[$metric] : 'clpm';

$group_by = ""; 
if ($range === '1y') {
    $interval = '1 YEAR';
    $group_by = "GROUP BY UNIX_TIMESTAMP(capture_time) DIV 3600";
    $timestamp_sql = "(UNIX_TIMESTAMP(capture_time) DIV 3600) * 3600 * 1000";
    $val_sql = "AVG($col)";
} else {
    $timestamp_sql = "UNIX_TIMESTAMP(capture_time) * 1000";
    $val_sql = "$col";
}

try {
    $sql = "SELECT $timestamp_sql as timestamp, TRUNCATE($val_sql / 100, 2) as value
            FROM water_raw_data 
            WHERE capture_time >= NOW() - INTERVAL $interval
            $group_by
            ORDER BY capture_time ASC";
    $stmt = $pdo->query($sql);
    $data = array_map(function($row) { return [(int)$row['timestamp'], (float)$row['value']]; }, $stmt->fetchAll());
    echo json_encode($data);
} catch (PDOException $e) {
    http_response_code(500); echo json_encode(['error' => 'DB Error']);
}
?>
