package bpex;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;

public class active_scan_actuator implements ScanCheck {

    private final MontoyaApi api;

    active_scan_actuator(MontoyaApi api)
    {
        this.api = api;
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint){



        HttpRequest req=baseRequestResponse.request();
        String atype=auditInsertionPoint.baseValue();
        String aname=auditInsertionPoint.name();
        String a="baseValue:"+atype+"name:"+aname;



        String req_url=req.url();
        try{
            URL url=new URL(req_url);


            String str_url="";
            if(url.getPort()==-1){
                str_url=url.getProtocol()+"://"+url.getHost()+"/actuator";}
            else{
                str_url=url.getProtocol()+"://"+url.getHost()+":"+url.getPort()+"/actuator";
            }
            HttpRequest swagger_req=HttpRequest.httpRequestFromUrl(str_url);


            HttpRequestResponse swaggerRequestResponse = api.http().sendRequest(swagger_req, HttpMode.HTTP_1);
            short code=swaggerRequestResponse.response().statusCode();


            List<AuditIssue> auditIssueList = code!=200 ? emptyList() : singletonList(
                    AuditIssue.auditIssue("Sensitive information found:actuator!",
                            str_url,
                            req.url(),
                            req.url(),
                            AuditIssueSeverity.HIGH,
                            AuditIssueConfidence.CERTAIN,
                            a,
                            null,
                            AuditIssueSeverity.MEDIUM,
                            swaggerRequestResponse));

            return AuditResult.auditResult(auditIssueList);
        }
        catch (MalformedURLException e){
            return  null;
        }

    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse var1){
        List<AuditIssue> auditIssueList =  emptyList();
        return AuditResult.auditResult(auditIssueList);}

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue var1, AuditIssue var2){
        return null;
    }
}
