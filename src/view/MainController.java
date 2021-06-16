package view;

import org.iftech.TrepTest.SendSampleTrap;

import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;

public class MainController {
	public SendSampleTrap mainApp;
	@FXML TextField txtBoxTrapCode;
	@FXML TextField txtBoxTargetAddress	;
	@FXML Button btnSendTrap;
	public void setMainApp(SendSampleTrap mainApp)
	{
		this.mainApp = mainApp;
	}
	@FXML private void btnSendTrapOnClicked() {
		String readString = txtBoxTrapCode.getText();
		String strTartgetAddress =txtBoxTargetAddress.getText() ;
		if(strTartgetAddress.isEmpty()  )strTartgetAddress ="0.0.0.0";
		try {
			mainApp.sendTrap(readString, strTartgetAddress);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	   //snmp.send(trap, target, null, null);                      	   
	}

}
