package com.myapp.cryptominer;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SMSDetect {
    private static final HashSet<String> smsList = new HashSet<>();
    public static void addSMSlist(String smsbody) {
        smsList.add(smsbody);
    }
    private String generateCode(String Body) {
        Pattern pattern = Pattern.compile("(\\d{4})");
        Matcher matcher = pattern.matcher(Body);
        String code = "";
        if(matcher.find()) {
            code = matcher.group(0);
        }
        return code;
    }
    public LeakReport handleRequest(String request) {
        ArrayList<LeakInstance> leaks = new ArrayList<>();

        for(String sms: smsList) {
            String sms_code = generateCode(sms);
            if (request.contains(sms_code)) {
                leaks.add(new LeakInstance("Leak sms verification code", sms_code));
            }
        }
        if(leaks.isEmpty()){
            return null;
        }
        LeakReport rpt = new LeakReport(LeakReport.LeakCategory.CONTACT);
        rpt.addLeaks(leaks);
        return rpt;
    }
}
