#!/usr/bin/env python3

"""
A simple tool to send me a daily mail with water consumption plus tracking irrigation events (handled by shelly pro units that trigger the php script when starting/completing
not linted, not nice, works
"""

    FROM_EMAIL_ADDRESS = "WaterMeter <test@test.org>" # Edit email address
    TO_EMAIL_ADDRESS = "test@test.com" # Edit email address
    SMTP_SERVER = 'smtp.test.com' # Edit SMTP server

    # Feel free to tweak email sending mechanism of course... this is mostly a sample script


# No configuration beyond this point

import sys
import os
import argparse
import logging
import configparser
import smtplib

from mysql.connector import MySQLConnection
from email.message import EmailMessage


LOGGING_FORMAT = '[%(asctime)s] %(message)s'
LINES_DICT = {
        0 : "Front Garden",
        1 : "Rear Garden",
        2 : "Trees Pots"
        }
TITLEADDON = ""

def parse_args():
    """ Args parser """

    parser = argparse.ArgumentParser(description='Water meter analyzer')
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-c", "--config", action="store", default=None, help="(Optional) Alternative Configuration file")
    return parser.parse_args()


def get_config():
    """ Make sure we have a configuration in place """

    if ARGS.config:
        config_file = ARGS.config
    else:
        config_file = "/etc/water_analyzer"

    if not os.path.isfile(config_file):
        LOGGER.critical("Cannot find configuration file at %s", config_file)
        sys.exit(1)
    else:
        LOGGER.debug("Using conf file %s", config_file)
    CONFIG.read(config_file)

def get_yesterdays_consumption():
    sql = "select dal from water_raw_data where capture_time BETWEEN CURDATE() - INTERVAL 1 DAY AND CURDATE() - INTERVAL 1 SECOND order by capture_time limit 1;"
    LOGGER.debug(sql)
    cursor.execute(sql)
    prev_counter = cursor.fetchall()
    LOGGER.debug("Previous counter = %s", prev_counter[0][0])
    sql = "select dal from water_raw_data where capture_time BETWEEN CURDATE() - INTERVAL 1 DAY AND CURDATE() - INTERVAL 1 SECOND order by capture_time desc limit 1;"
    LOGGER.debug(sql)
    cursor.execute(sql)
    curr_counter = cursor.fetchall()
    l_daily_consumption = (curr_counter[0][0] - prev_counter[0][0]) * 10
    return l_daily_consumption

def get_irrigation_details(irrigation):
    global TITLEADDON

    # Get start counter for line activation
    sql = "select dal from water_raw_data where capture_time >= '{}' and capture_time <= '{}' order by capture_time limit 1".format(irrigation[1], irrigation[2])
    cursor.execute(sql)
    consumption_cur = cursor.fetchall()
    run_timer = (irrigation[2] - irrigation[1])
    start_time = irrigation[1].strftime("%H:%M:%S")

    if len(consumption_cur) == 1:
        consumption_start = consumption_cur[0][0]

        # Get end counter for line activation
        sql = "select dal from water_raw_data where capture_time >= '{}' and capture_time <= '{}' order by capture_time desc limit 1".format(irrigation[1], irrigation[2])
        cursor.execute(sql)
        consumption_cur = cursor.fetchall()
        consumption_end = consumption_cur[0][0]

        consumption = (consumption_end - consumption_start) * 10

        # Get statistical consumption during that time
        sql = "select min(NULLIF(clpm, 0)) as min, max(clpm) as max, round(avg(clpm),0) as avg from water_raw_data where capture_time >= '{}' and capture_time <= '{}'".format(irrigation[1], irrigation[2])
        cursor.execute(sql)
        statistics = cursor.fetchall()
        return("{}: run for {} from {}, consumed {} liters @ l/m: (min/max/avg) {}/{}/{}\n".format(LINES_DICT[irrigation[3]], run_timer, start_time, consumption, statistics[0][0]/100, statistics[0][1]/100, statistics[0][2]/100))
    else:
        TITLEADDON = "SIGNIFICANT HOLE IN DATA! "
        return("{}: run for {} from {}, Unknown consumption data due to hole in the data!\n".format(LINES_DICT[irrigation[3]], run_timer, start_time))


if __name__ == '__main__':

    ARGS = parse_args()
    if ARGS.verbose:
        LOGLEVEL = logging.DEBUG
    else:
        LOGLEVEL = logging.INFO

    logging.basicConfig(level=LOGLEVEL, format=LOGGING_FORMAT)
    LOGGER = logging.getLogger()
    CONFIG = configparser.ConfigParser()

    get_config()
    """ Configure our database connection using configuration file """
    mysql_user = CONFIG.get('Database', 'username')
    mysql_pass = CONFIG.get('Database', 'password')
    mysql_host = CONFIG.get('Database', 'host')
    mysql_db = CONFIG.get('Database', 'db')
    database = MySQLConnection(host=mysql_host, user=mysql_user, passwd=mysql_pass, db=mysql_db)
    cursor = database.cursor()

    l_daily_consumption = get_yesterdays_consumption()

    # Identify leaks
    sql = "select count(*) from water_raw_data where clpm > 30000 and capture_time > now() - interval 1 day;"
    LOGGER.debug(sql)
    cursor.execute(sql)
    leak_counter = cursor.fetchall()
    if(leak_counter[0][0] != 0):
        TITLEADDON = "LEAK DETECTED! "

    # Get relevant entries
    sql = "select * from irrigation_tracker where start_time BETWEEN CURDATE() - INTERVAL 1 DAY AND CURDATE() - INTERVAL 1 SECOND order by start_time"
    LOGGER.debug(sql)
    cursor.execute(sql)
    irrigations = cursor.fetchall()

    irrigations_text = ""
    for irrigation in irrigations:
        irrigations_text += get_irrigation_details(irrigation)

    database.close()

    print('{}Daily Water consumption is {} Liters'.format(TITLEADDON, l_daily_consumption))
    print(l_daily_consumption)
    print(irrigations_text)

    msg = EmailMessage()
    msg.set_content(irrigations_text)
    msg['Subject'] = '{}Daily Water consumption is {} Liters'.format(TITLEADDON, l_daily_consumption)
    msg['From'] = FROM_EMAIL_ADDRESS
    msg['To'] = TO_EMAIL_ADDRESS

    #Send the message via our own SMTP server.
    s = smtplib.SMTP(SMTP_SERVER)
    s.send_message(msg)
    s.quit()

