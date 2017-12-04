package com.ef;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateUtils;

/*
 * 	This class parse the webserver access logs and block the ip's which matches the requirements
 */
public class Parser {

	public static final String ACCESS_FILE_ARG_KEY = "--accesslog=";
	public static final String START_DATE_ARG_KEY = "--startDate=";
	public static final String DURATION_ARG_KEY = "--duration=";
	public static final String THRESHOLD_ARG_KEY = "--threshold=";
	public static final String FORMAT = "yyyy-MM-dd HH:mm:ss";
	public static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat(
			FORMAT);
	public static final String DB_SCHEMA_URL = "jdbc:mysql://localhost:3306/accesslog";
	public static final String DB_SCHEMA_USERNAME = "root";
	public static final String DB_SCHEMA_PASSWORD = "tiger";
	public static final String HOURLY = "hourly";
	public static final String DAILY = "daily";

	public static final List<String> DURATION_VALUES = new ArrayList<String>();

	static {
		DURATION_VALUES.add(HOURLY);
		DURATION_VALUES.add(DAILY);
	}

	/*
	 * Parse the input argument
	 */
	public static String parseArgument(String argument, String argumentKey)
			throws Exception {
		String parsedValue = null;
		if ((StringUtils.startsWith(argument, argumentKey))) {
			parsedValue = StringUtils.replace(argument, argumentKey, "");
		} else {
			throw new Exception("Not able to parse argument from "
					+ argumentKey);
		}
		return parsedValue;
	}

	/*
	 * Validate start date as per the format - yyyy-MM-dd HH:mm:ss
	 */
	public static Date validateStartDate(String startDate) throws Exception {
		try {
			startDate = StringUtils.replace(startDate, ".", " ");

			Date formattedDate = DATE_FORMAT.parse(startDate);
			return formattedDate;
		} catch (Exception e) {
			throw new Exception("Incorrect date Format. Please enter like - "
					+ FORMAT);
		}

	}

	/*
	 * Validate duration based on requirement
	 */
	public static void validateDuration(String duration) throws Exception {
		if (!DURATION_VALUES.contains(duration)) {
			throw new Exception(
					"Incorrect duration value.Please enter 'hourly' or 'daily' as inputs");
		}
	}

	/*
	 * Validate threshold is valid s
	 */
	public static Integer validateThreshold(String threshold) throws Exception {
		try {
			Integer validatedThreshold = Integer.parseInt(threshold);
			return validatedThreshold;
		} catch (Exception e) {
			throw new Exception(
					"Threshold value is not an Integer. Please enter an integer value like 50 or 50.0");
		}
	}

	/*
	 * Validate access logs is valid
	 */
	public static void validateAccessLogLocation(String accessLog)
			throws Exception {
		File file = new File(accessLog);
		if (!file.isFile()) {
			throw new Exception(accessLog
					+ " is not a valid file to proceed with");
		}
	}

	/*
	 * Find the ip's which matched criteria based on inputs
	 */
	public static Map<String, String> findIps(Date validatedDate,
			String duration, Integer validatedThreshold) throws ParseException,
			SQLException {
		Map<String, String> valuesToTempTable = new HashMap<String, String>();
		Date startDate = validatedDate;
		Date endDate = null;
		if (StringUtils.equalsIgnoreCase(HOURLY, duration)) {
			endDate = DateUtils.addHours(validatedDate, 1);
		} else {
			endDate = DateUtils.addHours(validatedDate, 24);
		}
		Connection con = null;
		try {
			con = DriverManager.getConnection(DB_SCHEMA_URL,
					DB_SCHEMA_USERNAME, DB_SCHEMA_PASSWORD);
			Statement statement = con.createStatement();
			String selectIpQuery = "select ip,count(ip) as counter "
					+ "FROM accesslog.access_log where " + "date between '"
					+ DATE_FORMAT.format(startDate) + "' and '"
					+ DATE_FORMAT.format(endDate) + "' " + "group by ip "
					+ "having count(ip) >" + validatedThreshold;
			ResultSet resultSet = statement.executeQuery(selectIpQuery);
			while (resultSet.next()) {
				String resultIp = resultSet.getString("ip");
				String comment = "Ip blocked since it exceeded " + duration
						+ " limit of " + validatedThreshold;
				System.out.println(resultIp + " : " + comment);
				valuesToTempTable.put(resultIp, comment);
			}
		} finally {
			con.close();
		}

		return valuesToTempTable;

	}

	/*
	 * Add the blocked IP and comments to ip_reults table after processing
	 */
	public static void addIpstoTempTable(Map<String, String> valuesToTempTable)
			throws SQLException {
		Connection con = null;
		try {
			con = DriverManager.getConnection(DB_SCHEMA_URL,
					DB_SCHEMA_USERNAME, DB_SCHEMA_PASSWORD);
			Statement statement = con.createStatement();

			for (Map.Entry<String, String> entry : valuesToTempTable.entrySet()) {
				String insertIpQuery = "insert into ip_results(ip,comment) values ('"
						+ entry.getKey() + "' , '" + entry.getValue() + "') ";
				statement.executeUpdate(insertIpQuery);
			}
		} finally {
			con.close();
		}
	}

	/*
	 * Read the input data from log table and add it to logs table
	 */
	public static void insertLogDataToDB(String accessLog) throws Exception {
		Connection con = null;
		try {
			con = DriverManager.getConnection(DB_SCHEMA_URL,
					DB_SCHEMA_USERNAME, DB_SCHEMA_PASSWORD);
			Statement st = con.createStatement();
			FileInputStream fstream = new FileInputStream(accessLog);
			DataInputStream in = new DataInputStream(fstream);
			BufferedReader br = new BufferedReader(new InputStreamReader(in));
			String strLine;
			ArrayList<String> list = new ArrayList<String>();
			while ((strLine = br.readLine()) != null) {
				list.add(strLine);
			}
			Iterator<String> itr;
			for (itr = list.iterator(); itr.hasNext();) {
				String str = itr.next().toString();
				String[] splitSt = str.split("\\|");
				String date = "", ip = "", request = "", status = "", useragent = "";
				for (int i = 0; i < splitSt.length; i++) {
					date = splitSt[0];
					ip = splitSt[1];
					request = splitSt[2];
					status = splitSt[3];
					useragent = splitSt[4];
				}

				try {
					st.executeUpdate("insert into access_log(date,ip,request,status,useragent) values('"
							+ date
							+ "','"
							+ ip
							+ "','"
							+ request
							+ "','"
							+ status + "','" + useragent + "')");
				} catch (SQLException excp) {
					// IP and date are primary key together. If there is an IP
					// and date are already exist and we get primary key
					// violation we are ignoring that exception
					if (excp.getErrorCode() != 1062) {
						throw new Exception(excp);
					}
				}
			}
		} finally {
			con.close();
		}

	}

	public static void main(String[] args) {
		try {
			// Check the input arguments is correctly passed or not
			if (args.length != 4) {
				throw new Exception(
						"Input arguments not valid. Please enter 4 arguments");
			}
			String accessLog = parseArgument(args[0], ACCESS_FILE_ARG_KEY);
			String startDate = parseArgument(args[1], START_DATE_ARG_KEY);
			String duration = parseArgument(args[2], DURATION_ARG_KEY);
			String threshold = parseArgument(args[3], THRESHOLD_ARG_KEY);

			// validate the input arguments
			validateAccessLogLocation(accessLog);
			Date validatedDate = validateStartDate(startDate);
			validateDuration(duration);
			Integer validatedThreshold = validateThreshold(threshold);

			// add access logs to logs table
			insertLogDataToDB(accessLog);
			// Find blocked ips from the access log
			Map<String, String> blockedIpToTempTable = findIps(validatedDate,
					duration, validatedThreshold);
			// add blocked ip and comments to ipResults table
			addIpstoTempTable(blockedIpToTempTable);
			System.out.println("Process completed Successfully!!!");
		} catch (Exception e) {
			System.out.println("Error details - " + e.getMessage());
			e.printStackTrace();
		}
	}

}