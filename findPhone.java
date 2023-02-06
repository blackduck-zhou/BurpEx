package bpex;

import burp.api.montoya.core.Marker;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;

public class findPhone implements ScanCheck {

    @Override
    public AuditResult activeAudit(HttpRequestResponse var1, AuditInsertionPoint var2){
        return null;
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse var1){
        String p="\\D(13|15|17|18)\\d{9}\\D";
        Pattern pattern_All=Pattern.compile(p);
        String background="Sensitive information found: mobile number!";
        HttpRequest req= var1.request();
        HttpResponse res= var1.response();
        String res_Body=res.toString();
        Matcher m=pattern_All.matcher(res_Body);
        List<Marker> marker_list=new ArrayList<Marker>();
        while(m.find()){
            int m_start=m.start();
            int m_end=m.end();
            Range range_a=Range.range(m_start,m_end);
            Marker maker_a= Marker.marker(range_a);
            marker_list.add(maker_a);
        }
        List<AuditIssue> auditIssueList = marker_list.isEmpty() ? emptyList() : singletonList(
                AuditIssue.auditIssue("Sensitive information found:mobile number!",
                        "Sensitive information found:mobile number!",
                        req.url(),
                        req.url(),
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.CERTAIN,
                        null,
                        null,
                        AuditIssueSeverity.MEDIUM,
                        var1.withResponseMarkers(marker_list)));

        return AuditResult.auditResult(auditIssueList);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue var1, AuditIssue var2){
        return null;
    }
}

