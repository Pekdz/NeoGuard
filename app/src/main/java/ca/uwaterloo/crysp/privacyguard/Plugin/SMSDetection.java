package ca.uwaterloo.crysp.privacyguard.Plugin;

import android.content.BroadcastReceiver;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.telephony.SmsMessage;
import android.util.Log;


import java.util.ArrayList;
import java.util.HashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ca.uwaterloo.crysp.privacyguard.Application.Logger;
import ca.uwaterloo.crysp.privacyguard.Application.Network.ConnectionMetaData;

public class SMSDetection extends BroadcastReceiver implements IPlugin {
    private final String TAG = "SMSDetection";
    private final boolean DEBUG = false;
    private static boolean init = false;

    private static final HashSet<String> smsList = new HashSet<>();

    public static void addSMSlist(String smsbody) {
        smsList.add(smsbody);
    }

    public static String generateCode(String Body) {
        Pattern pattern = Pattern.compile("(\\d{4,6})");
        Matcher matcher = pattern.matcher(Body);
        String code = "";
        if (matcher.find()) {
            code = matcher.group(0);
        }
        return code;
    }

    @Override
    @Nullable
    public LeakReport handleRequest(String request, byte[] rawRequest, ConnectionMetaData metaData) {
        ArrayList<LeakInstance> leaks = new ArrayList<>();

        for (String sms_code : smsList) {
            if (request.contains(sms_code)) {
                leaks.add(new LeakInstance("Leak SMS Verification Code", sms_code, -1));
            }
        }
        if (leaks.isEmpty()) {
            return null;
        }
        LeakReport rpt = new LeakReport(LeakReport.LeakCategory.CONTACT);
        rpt.addLeaks(leaks);
        return rpt;
    }

    @Override
    public LeakReport handleResponse(String response) {
        return null;
    }

    @Override
    public String modifyRequest(String request) {
        return request;
    }

    @Override
    public String modifyResponse(String response) {
        return response;
    }

    @Override
    public void setContext(Context context) {
        synchronized (smsList) {
            if (init) return;
            init = true;
            getSMS(context.getContentResolver());
        }
    }

    public void getSMS(ContentResolver cr) {
        Cursor sms = null;
        try {
            sms = cr.query(Uri.parse("content://sms/inbox"), null, null, null, null);
            if (sms.moveToFirst()) { // must check the result to prevent exception
                do {
                    String msgData = "";
                    for (int idx = 0; idx < sms.getColumnCount(); idx++) {
                        msgData = sms.getString(idx);
                        String code = generateCode(msgData);
                        if (code != "") {
                            smsList.add(code);
                            Log.i("has_code", code);
                        }
                    }
                } while (sms.moveToNext());
            } else {
                // empty box, no SMS
            }
        } catch (Exception e) {
            Logger.e(TAG, e.getMessage());
        } finally {
            if (sms != null) {
                sms.close();
            }
        }
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent.getAction().equals("android.provider.Telephony.SMS_RECEIVED")) {
            Bundle bundle = intent.getExtras();           //---get the SMS message passed in---
            SmsMessage[] msgs = null;
            String msg_from;
            if (bundle != null) {
                //---retrieve the SMS message received---
                try {
                    Object[] pdus = (Object[]) bundle.get("pdus");
                    msgs = new SmsMessage[pdus.length];
                    for (int i = 0; i < msgs.length; i++) {
                        msgs[i] = SmsMessage.createFromPdu((byte[]) pdus[i]);
                        msg_from = msgs[i].getOriginatingAddress();
                        String msgBody = msgs[i].getMessageBody();
                        String code = generateCode(msgBody);
                        if (code != "") {
                            addSMSlist(code);
                        }

                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
