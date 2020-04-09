--
-- Table structure for table `water_raw_data`
--

CREATE TABLE `water_raw_data` (
  `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `capture_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `dal` int(10) UNSIGNED NOT NULL COMMENT 'Dekaliter (10 liters)',
  `clpm` smallint(10) UNSIGNED NOT NULL COMMENT 'Centilitre / min',
  PRIMARY KEY (`id`),
  UNIQUE KEY `capture_time` (`capture_time`)
);
