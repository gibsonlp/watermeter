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


CREATE TABLE `irrigation_tracker` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `start_time` datetime NOT NULL DEFAULT current_timestamp(),
  `end_time` datetime NOT NULL DEFAULT current_timestamp(),
  `line` tinyint(1) unsigned NOT NULL COMMENT '0-Front Garden, 1-Rear Garden, 2-Tree pots',  -- Change to whatever you want or remove
  PRIMARY KEY (`id`),
  index `start_time` (`start_time`),
  index `end_time` (`end_time`)
);
