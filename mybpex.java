package bpex;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.ScanCheck;

public class mybpex implements BurpExtension {
    public MontoyaApi myapi;

    @Override
    public void initialize(MontoyaApi api) {

        myapi=api;

        //JPanel myUI = new JPanel();
        //myapi.userInterface().registerSuiteTab("TestTAB",myUI);

        myapi.extension().setName("敏感信息扫描插件");
        Logging logging = myapi.logging();
        boolean isBapp=myapi.extension().isBapp();
        if(isBapp){
            logging.logToOutput("app from Burp!!!!!!");
        }else{
            logging.logToOutput("app from zy!!!!!!!!!");
        }

        String version= myapi.burpSuite().version().edition().name();

        //logging.logToOutput("plugin version is "+SensitiveInfoCheckV2.version);
        logging.logToOutput("version is V0.2");
        //SensitiveInfoCheck mySICheck=new SensitiveInfoCheck();
        //SensitiveInfoCheckV2 mySICheck=new SensitiveInfoCheckV2();
        //myapi.scanner().registerScanCheck(mySICheck);
        ScanCheck myScancheck1=new findMail();
        ScanCheck myScancheck2=new findPhone();
        ScanCheck myScancheck3=new findPrivateIp();
        ScanCheck myScancheck4=new findName();
        ScanCheck active_myScancheck1=new active_scan_swagger(myapi);
        ScanCheck active_myScancheck2=new active_scan_actuator(myapi);

        myapi.scanner().registerScanCheck(myScancheck1);
        myapi.scanner().registerScanCheck(myScancheck2);
        myapi.scanner().registerScanCheck(myScancheck3);
        myapi.scanner().registerScanCheck(myScancheck4);
        myapi.scanner().registerScanCheck(active_myScancheck1);
        myapi.scanner().registerScanCheck(active_myScancheck2);


        // write a message to our output stream
        logging.logToOutput("Hello output.");

        // write a message to our error stream
        logging.logToError("Hello error.");

/*        // write a message to the Burp alerts tab
        logging.raiseInfoEvent("Hello info event.");
        logging.raiseDebugEvent("Hello debug event.");
        logging.raiseErrorEvent("Hello error event.");
        logging.raiseCriticalEvent("Hello critical event.");*/

        // throw an exception that will appear in our error stream
    }
}