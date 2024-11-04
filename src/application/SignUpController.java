package application;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.stage.Stage;

public class SignUpController {
	@FXML private Label signUpLabel ;
	@FXML private Label clarificationLabel;
	@FXML private Label usernameLabel;
	@FXML private Label passwordLabel;
	//@FXML private Label succesfullSignUpLabel;
	@FXML private TextField usernameTextFeild ;
	@FXML private PasswordField passwordFeild ;
	@FXML private Label errorLabel ;
	@FXML private Button confirmButton;
	 private Stage stage;
	 private Scene scene;
	 private Parent root;
	
	
	 @FXML
	 public void signUp(ActionEvent e) throws SQLException { 
	     if(usernameTextFeild.getText().isBlank() || passwordFeild.getText().isBlank()) { 
	         errorLabel.setText("Please enter both your Username and Password"); 
	     } else { 
	         DatabaseConnection connectNow = new DatabaseConnection();
	         Connection connectDB = connectNow.getConnection();
	         
	         try {
	             Statement statement = connectDB.createStatement();
	             String username = usernameTextFeild.getText();
	             String password = passwordFeild.getText();
	             
	             // Check if username already exists in database
	             String checkUser = "SELECT COUNT(*) FROM users WHERE username='" + username + "'";
	             ResultSet rs = statement.executeQuery(checkUser);
	             rs.next();
	             int count = rs.getInt(1);
	             
	             if (count > 0) { // Username already exists
	                 errorLabel.setText("Username already exists. Please choose a different username.");
	             } else { // Username does not exist, create account
	                 String makeAccount = "INSERT INTO users (username, password) VALUES ('" + username + "', '" + password + "')";
	                 statement.executeUpdate(makeAccount);
	                 
	                 Parent root = FXMLLoader.load(getClass().getResource("SecondInterface.fxml"));
	                 stage = (Stage) ((Node) e.getSource()).getScene().getWindow();
	                 scene = new Scene(root);
	                 stage.setScene(scene);
	                 stage.show(); 
	             }
	         } catch (Exception ex) {
	             ex.printStackTrace();
	         }
	     }
	 }

		
		
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

