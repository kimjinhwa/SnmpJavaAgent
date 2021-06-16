package org.iftech.TrepTest;

import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.PDUv1;
import org.snmp4j.Snmp;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.IpAddress;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.TimeTicks;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.Variable;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.layout.BorderPane;
import javafx.stage.Stage;
import view.MainController;

public class SendSampleTrap extends Application {

    public static Snmp snmp ;
	MainController controller ;

	public  void sendTrap(String trapcode, String destination)  throws Exception
	{
		//PDU trap = new PDU();
		PDUv1 trap = new PDUv1();
		//trap.setType(PDU.TRAP);

		OID oid = new OID(trapcode);
		trap.setEnterprise(oid);
		//trap.setType( PDU.V1TRAP);
		trap.setType(PDUv1.V1TRAP);
		trap.setGenericTrap(PDUv1.COLDSTART);
		trap.setSpecificTrap(100);

		//trap.setAgentAddress(new IpAddress("192.168.0.252"));
	   //trap.add(new VariableBinding(SnmpConstants.snmpTrapOID, oid));

	   //trap.add(new VariableBinding(SnmpConstants.sysUpTime, new TimeTicks(5000))); // put your uptime here
	   //trap.add(new VariableBinding(SnmpConstants.sysDescr, new OctetString("System Description"))); 
	   
	   
	   //Add Payload
	   Variable var = new OctetString("some string");          
	   trap.add(new VariableBinding(oid, var));          
	   Address targetaddress = new UdpAddress(destination + "/162");
	   CommunityTarget<Address> target = new CommunityTarget<Address>();
	   target.setCommunity(new OctetString("public"));
	   target.setVersion(SnmpConstants.version2c);
	   target.setAddress(targetaddress);	   

	   //snmp = new Snmp(new DefaultUdpTransportMapping());
	   snmp.send(trap, target, null, null);                      	   
	}

	public static void main(String[] args) throws Exception {
		PDU trap = new PDU();
		trap.setType(PDU.TRAP);
		//OID oid = new OID("1.3.6.1.4.1.12236.1.11.0.26");
		OID oid = new OID("1.3.6.1.4.1.935.0.36");
	   trap.add(new VariableBinding(SnmpConstants.snmpTrapOID, oid));
	   trap.add(new VariableBinding(SnmpConstants.sysUpTime, new TimeTicks(5000))); // put your uptime here
	   trap.add(new VariableBinding(SnmpConstants.sysDescr, new OctetString("System Description"))); 
	   //Add Payload
	   Variable var = new OctetString("some string");          
	   trap.add(new VariableBinding(oid, var));          
	   Address targetaddress = new UdpAddress("192.168.0.252/162");
	   CommunityTarget target = new CommunityTarget();
	   target.setCommunity(new OctetString("public"));
	   target.setVersion(SnmpConstants.version2c);
	   target.setAddress(targetaddress);	   

	   snmp = new Snmp(new DefaultUdpTransportMapping());
	   //snmp.send(trap, target, null, null);                      	   
	   launch(args);
	}

	@Override
	public void start(Stage primaryStage) throws Exception {
		// TODO Auto-generated method stub
		FXMLLoader loader = new FXMLLoader();	
		loader.setLocation (SendSampleTrap.class.getResource("/view/Main.fxml"));
		BorderPane rootLayout;
		rootLayout = (BorderPane) loader.load();
		Scene scene = new Scene(rootLayout);
		primaryStage.setScene(scene);
		primaryStage.show();

		MainController controller = loader.getController();
		controller.setMainApp(this);

	}
}
