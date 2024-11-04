package application;

import java.io.IOException;
import java.net.URL;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javafx.application.HostServices;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Hyperlink;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.BorderPane;
import javafx.stage.Stage;

public class LoginController {

    private Stage stage;
    private Scene scene;
    private Parent root;

    @FXML
    private TextField usernameButton;

    @FXML
    private BorderPane borderPane;

    @FXML
    private PasswordField passwordPSWRDFeild;

    @FXML
    private Label errorLabel;

    @FXML
    private Label signUpLabel;

    private String username;

    @FXML
    private Hyperlink emailLink1;

    @FXML
    private Hyperlink emailLink2;

    @FXML
    private Hyperlink websiteLink;

    @FXML
    private ImageView networkImageView;

    @FXML
    private ImageView usernameImageView;

    @FXML
    private ImageView passwordImageView;
    @FXML
    private HostServices hostServices;

    public void setHostServices(HostServices hostServices) {
        this.hostServices = hostServices;
    }

    @FXML
    public void initialize() {
        Image networkImage = new Image(getClass().getResourceAsStream("/dashboard.png"));
        networkImageView.setImage(networkImage);
        Image usernameImage = new Image(getClass().getResourceAsStream("/user.png"));
        usernameImageView.setImage(usernameImage);
        Image passwordImage = new Image(getClass().getResourceAsStream("/padlock.png"));
        passwordImageView.setImage(passwordImage);
        emailLink1.setOnAction(this::handleEmailLink1Click);
        emailLink2.setOnAction(this::handleEmailLink2Click);
        websiteLink.setOnAction(this::handleWebsiteLinkClick);
    }

    @FXML
    public void logIn(ActionEvent e) throws IOException, SQLException {
    	  if (usernameButton.getText().isBlank() || passwordPSWRDFeild.getText().isBlank()) {
              errorLabel.setText("Please enter both your Username and Password");
          } else {
              DatabaseConnection connectNow = new DatabaseConnection();
              Connection connectDB = connectNow.getConnection();
              try {
                  Statement statement = connectDB.createStatement();
                  String verifyLogIn = "SELECT count(1) FROM users WHERE username = '" + usernameButton.getText()
                          + "' AND password ='" + passwordPSWRDFeild.getText() + "'";
                  ResultSet queryResult = statement.executeQuery(verifyLogIn);
                  while (queryResult.next()) {
                      if (queryResult.getInt(1) == 1) {
                      	username = usernameButton.getText();
                              Parent root = FXMLLoader.load(getClass().getResource("SecondInterface.fxml"));
                              stage = (Stage) ((Node) e.getSource()).getScene().getWindow();
                              scene = new Scene(root);
                              stage.setScene(scene);
                              stage.show();
                          }
                       else {
                          errorLabel.setText("Invalid Username Or Password. Please Try Again.");
                      }
                  }
              } catch (Exception ex) {
                  ex.printStackTrace();
              }
          }
      }
    public String getUsername() {
        return username;
    }

    @FXML
    public void signUp(ActionEvent e) throws SQLException {
        try {
            Parent root = FXMLLoader.load(getClass().getResource("signUp.fxml"));
            stage = (Stage) ((Node) e.getSource()).getScene().getWindow();
            scene = new Scene(root);
            stage.setScene(scene);
            stage.show();
        } catch (IOException ex) {
            ex.printStackTrace();
            // handle the exception here
        }
        System.out.println("Sign up clicked!"); // debug statement
    }

    @FXML
    private void handleWebsiteLinkClick(ActionEvent event) {
    	if (hostServices != null) {
            hostServices.showDocument("https://example.com");
        }
        String url = "https://www.univ-constantine2.dz/";
        hostServices.showDocument(url);
    }

    @FXML
    private void handleEmailLink1Click(ActionEvent event) {
    	if (hostServices != null) {
            hostServices.showDocument("https://example.com");
        }
        String email = "oussama.hannache@univ-constantine2.dz";
        String subject = "Hello";
        String body = "This is the email body.";
        String mailtoUri = "mailto:" + email + "?subject=" + subject + "&body=" + body;
        hostServices.showDocument(mailtoUri);
    }

    @FXML
    private void handleEmailLink2Click(ActionEvent event) {
    	if (hostServices != null) {
            hostServices.showDocument("https://example.com");
        }
        String email = "lina.filali@univ_constantine2.dz";
        String subject = "Hello";
        String body = "This is the email body.";
        String mailtoUri = "mailto:" + email + "?subject=" + subject + "&body=" + body;
        hostServices.showDocument(mailtoUri);
    }
}
