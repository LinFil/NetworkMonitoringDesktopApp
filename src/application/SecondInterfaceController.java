package application;

import java.io.IOException;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.input.MouseEvent;
import javafx.scene.text.Text;
import javafx.stage.Stage;

public class SecondInterfaceController {



@FXML
private void realTimeAnalysis(MouseEvent e) throws IOException {
    Parent root = FXMLLoader.load(getClass().getResource("LiveCapture.fxml"));
    Stage stage = (Stage)((Node)e.getSource()).getScene().getWindow();
    Scene scene = new Scene(root);
    stage.setScene(scene);
    stage.show();
}

@FXML
private void offLineAnalysis(MouseEvent e) throws IOException {
    Parent root = FXMLLoader.load(getClass().getResource("offline.fxml"));
    Stage stage = (Stage)((Node)e.getSource()).getScene().getWindow();
    Scene scene = new Scene(root);
    stage.setScene(scene);
    stage.show();
}

}
