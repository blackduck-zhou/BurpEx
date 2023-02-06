package bpex;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.List;

import static java.util.Collections.emptyList;

//扫描越权漏洞
public class active_scan_NoAuth implements ScanCheck {

    private final MontoyaApi api;

    active_scan_swagger(MontoyaApi api)
    {
        this.api = api;
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint){




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
}
