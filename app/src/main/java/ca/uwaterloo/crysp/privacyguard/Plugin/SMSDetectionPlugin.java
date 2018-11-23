package ca.uwaterloo.crysp.privacyguard.Plugin;

import android.Manifest;
import android.content.BroadcastReceiver;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v4.app.ActivityCompat;
import android.support.v4.content.ContextCompat;
import android.telephony.SmsMessage;
import android.util.Log;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ca.uwaterloo.crysp.privacyguard.Application.Database.DatabaseHandler;
import ca.uwaterloo.crysp.privacyguard.Application.Logger;
import ca.uwaterloo.crysp.privacyguard.Application.Network.ConnectionMetaData;


public class SMSDetectionPlugin extends BroadcastReceiver implements IPlugin {
    private final String TAG = "SMSDetectionPlugin";
    private final boolean DEBUG = true;
    private static boolean init = false;
    private static DatabaseHandler db;
    private static final HashSet<String> smsList = new HashSet<>();

    @Override
    @Nullable
    public LeakReport handleRequest(String request, byte[] rawRequest, ConnectionMetaData metaData) {
        try {
            ArrayList<LeakInstance> leaks = new ArrayList<>();

            long refPacketId = -1;
            for (String sms_code : smsList) {
                if (request.contains(sms_code)) {
                    if (refPacketId == -1 && metaData.currentPacket != null) {
                        refPacketId = db.addPacketRecord(metaData.currentPacket).dbId;
                    }
                    leaks.add(new LeakInstance("Leak Verification Code", sms_code, refPacketId));
                    if (DEBUG)
                        Logger.i(TAG, "SMS Leak => " + sms_code);
                }
            }
            if (leaks.isEmpty()) {
                return null;
            }
            LeakReport rpt = new LeakReport(LeakReport.LeakCategory.SMS);
            rpt.addLeaks(leaks);
            return rpt;
        } catch (Exception e) {
            return null;
        }
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
            db = DatabaseHandler.getInstance(context);
            init = true;
            getSMS(context.getContentResolver());
        }
    }

    public void getSMS(ContentResolver cr) {
        Cursor sms = null;
        try {
            sms = cr.query(Uri.parse("content://sms/inbox"),
                    null, null, null, null);
            int totalSMS = sms.getCount();
            if (sms.moveToFirst()) { // must check the result to prevent exception
                do {
                    String msgData = "";
                    for(int idx=0;idx<sms.getColumnCount();idx++)
                    {
                        String name = sms.getColumnName(idx);
                        String sub_body = sms.getString(idx);
                        if(name.contains("body")) {
                            msgData = sub_body;
                        }
                    }
                    String code = extractCode(msgData);
                    if (code != null) {
                        smsList.add(code);
                    }
                } while (sms.moveToNext());
            }
        } catch (Exception e) {
            Logger.e(TAG, e.getMessage());
        } finally {
            if (sms != null) {
                sms.close();
            }
        }
    }

    public static String extractCode(String Body) {
        if (!Body.contains("Code"))
            return null;

        Pattern pattern = Pattern.compile("(\\d{4,6})");
        Matcher matcher = pattern.matcher(Body);
        String code = null;
        if (matcher.find()) {
            code = matcher.group(0);
        }
        return code;
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent.getAction().equals("android.provider.Telephony.SMS_RECEIVED")) {
            //---get the SMS message passed in---
            Bundle bundle = intent.getExtras();
            SmsMessage[] msgs = null;
            if (bundle != null) {
                //---retrieve the SMS message received---
                try {
                    Object[] pdus = (Object[]) bundle.get("pdus");
                    msgs = new SmsMessage[pdus.length];
                    for (int i = 0; i < msgs.length; i++) {
                        msgs[i] = SmsMessage.createFromPdu((byte[]) pdus[i]);
                        String msgBody = msgs[i].getMessageBody();
                        String code = extractCode(msgBody);
                        if (code != null) {
                            smsList.add(code);
                        }

                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
