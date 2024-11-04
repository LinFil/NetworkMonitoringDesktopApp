package application;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DatabaseConnection {
   public Connection connection;
   public Connection getConnection() throws SQLException {
	 // String databaseName ="monotoringapp" ;
	  String databaseUser ="root" ;
	  String databasePassword = "admin";
	  // fill with your database URL
	  String url = "jdbc:mysql:/" ;
	  
	  try {
		Class.forName("com.mysql.cj.jdbc.Driver");
		connection = DriverManager.getConnection(url, databaseUser, databasePassword);
	} catch (ClassNotFoundException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} 

	  return connection;	   
   }
}
