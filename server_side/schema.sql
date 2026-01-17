--
-- Table structure for table `irrigation_tracker`
--

-- DROP TABLE IF EXISTS `irrigation_tracker`;
CREATE TABLE `irrigation_tracker` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `start_time` datetime NOT NULL DEFAULT current_timestamp(),
  `end_time` datetime NOT NULL DEFAULT current_timestamp(),
  `line` tinyint(1) unsigned NOT NULL COMMENT '0-Front Garden, 1-Rear Garden, 2-Trees pots',
  PRIMARY KEY (`id`),
  KEY `start_time` (`start_time`),
  KEY `end_time` (`end_time`),
  KEY `idx_tracker_perf` (`start_time`,`end_time`,`line`)
) ENGINE=InnoDB AUTO_INCREMENT=2448 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Table structure for table `water_raw_data`
--

-- DROP TABLE IF EXISTS `water_raw_data`;
CREATE TABLE `water_raw_data` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `capture_time` datetime NOT NULL DEFAULT current_timestamp(),
  `dal` int(10) unsigned NOT NULL COMMENT 'Dekaliter (10 liters)',
  `clpm` smallint(10) unsigned NOT NULL COMMENT 'Centilitre / min',
  `error_codes` smallint(5) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `capture_time` (`capture_time`),
  KEY `idx_dashboard_perf` (`capture_time`,`clpm`,`dal`,`error_codes`)
) ENGINE=InnoDB AUTO_INCREMENT=476025 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
