# WebServerAccessLogParser
 Java Parser that parses web server access log file, loads the log to MySQL and checks if a given IP makes more than a certain number of requests for the given duration. 
 
 Java Parser Tool
-----------------

(1) The tool takes "startDate", "duration" and "threshold" as command line arguments. "startDate" is of "yyyy-MM-dd.HH:mm:ss" format, "duration" can take only "hourly", "daily" as inputs and "threshold" can be an integer.

(2) This is how the tool works:

    java -cp "parser.jar" com.ef.Parser --startDate=2017-01-01.13:00:00 --duration=hourly --threshold=100
	
	The tool will find any IPs that made more than 100 requests starting from 2017-01-01.13:00:00 to 2017-01-01.14:00:00 (one hour) and print them to console AND also load them to another MySQL table with comments on why it's blocked.

	java -cp "parser.jar" com.ef.Parser --startDate=2017-01-01.13:00:00 --duration=daily --threshold=250

	The tool will find any IPs that made more than 250 requests starting from 2017-01-01.13:00:00 to 2017-01-02.13:00:00 (24 hours) and print them to console AND also load them to another MySQL table with comments on why it's blocked.
 
 LOG Format
----------
Date, IP, Request, Status, User Agent (pipe delimited, open the example file in text editor)

Date Format: "yyyy-MM-dd HH:mm:ss.SSS"

The log file assumes 200 as hourly limit and 500 as daily limit, meaning:

(1) 
When you run your parser against this file with the following parameters

java -cp "parser.jar" com.ef.Parser --startDate=2017-01-01.15:00:00 --duration=hourly --threshold=200

The output will have 192.168.11.231. If you open the log file, 192.168.11.231 has 200 or more requests between 2017-01-01.15:00:00 and 2017-01-01.15:59:59

(2) 
When you run your parser against this file with the following parameters

java -cp "parser.jar" com.ef.Parser --startDate=2017-01-01.00:00:00 --duration=daily --threshold=500

The output will have  192.168.102.136. If you open the log file, 192.168.102.136 has 500 or more requests between 2017-01-01.00:00:00 and 2017-01-01.23:59:59
