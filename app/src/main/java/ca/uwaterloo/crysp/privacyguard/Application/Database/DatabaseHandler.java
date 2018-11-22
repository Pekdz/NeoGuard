package ca.uwaterloo.crysp.privacyguard.Application.Database;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.util.Patterns;

import ca.uwaterloo.crysp.privacyguard.Application.Logger;
import ca.uwaterloo.crysp.privacyguard.Plugin.CryptominerInstance;
import ca.uwaterloo.crysp.privacyguard.Plugin.DomainInstance;
import ca.uwaterloo.crysp.privacyguard.Plugin.LeakInstance;
import ca.uwaterloo.crysp.privacyguard.Plugin.LeakReport;

import ca.uwaterloo.crysp.privacyguard.Plugin.TrafficReport;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Scanner;

import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;

/**
 * Created by MAK on 03/11/2015.
 */
public class DatabaseHandler extends SQLiteOpenHelper {
    private static final int DATABASE_VERSION = 1;
    private static final String DATABASE_NAME = "dataLeaksManager";
    private static SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss", Locale.CANADA);
    private SQLiteDatabase mDB;
    public static final String LEAK_ID_KEY = "leak_id_key";
    private static final boolean DEBUG = false;

    private static DatabaseHandler sInstance = null;

    private Context applicationContext = null;

    //The singleton pattern is used here because multiple threads could potentially be writing to the database.
    //Because of this pattern, only one DataBaseHandler is created for the application lifecycle.
    //As a result, do not call .close() on a DatabaseHandler instance.
    public static synchronized DatabaseHandler getInstance(Context context) {
        // Use the application context, which will ensure that you
        // don't accidentally leak an Activity's context.
        // See this article for more information: http://bit.ly/6LRzfx
        if (sInstance == null) {
            sInstance = new DatabaseHandler(context.getApplicationContext());
        }
        return sInstance;
    }

    private DatabaseHandler(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
        applicationContext = context;
        mDB = getReadableDatabase();
    }

    public String[] getTables() {
        return new String[]{TABLE_DATA_LEAKS, TABLE_LEAK_SUMMARY, TABLE_APP_STATUS_EVENTS,
                TABLE_TRAFFIC_SUMMARY, TABLE_CRYPTO_ALERT, TABLE_DOMAIN_ALERT, TABLE_PACKET};
    }

    public static SimpleDateFormat getDateFormat() {
        return DATE_FORMAT;
    }

    // Creating Tables
    @Override
    public void onCreate(SQLiteDatabase db) {
        //create table data_leaks
        db.execSQL(CREATE_DATA_LEAKS_TABLE);
        db.execSQL(CREATE_LEAK_SUMMARY_TABLE);
        db.execSQL(CREATE_APP_STATUS_TABLE);
        // w3kim@uwaterloo.ca
        db.execSQL(CREATE_TRAFFIC_TABLE);
        db.execSQL(CREATE_PACKET_TABLE);
        db.execSQL(CREATE_DOMAIN_TABLE);
        db.execSQL(CREATE_CRYPTO_TABLE);
    }

    // Upgrading database
    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        // Drop older table if existed
        db.execSQL("DROP TABLE IF EXISTS " + TABLE_DATA_LEAKS);
        db.execSQL("DROP TABLE IF EXISTS " + TABLE_LEAK_SUMMARY);
        db.execSQL("DROP TABLE IF EXISTS " + TABLE_APP_STATUS_EVENTS);
        // w3kim@uwaterloo.ca
        db.execSQL("DROP TABLE IF EXISTS " + TABLE_TRAFFIC_SUMMARY);
        db.execSQL("DROP TABLE IF EXISTS " + TABLE_PACKET);
        db.execSQL("DROP TABLE IF EXISTS " + TABLE_DOMAIN_ALERT);
        db.execSQL("DROP TABLE IF EXISTS " + TABLE_CRYPTO_ALERT);
        // Create tables again
        onCreate(db);
    }

    // DataLeaks table name
    private static final String TABLE_LEAK_SUMMARY = "leak_summary";

    // DataLeaks Table Columns names
    private static final String KEY_ID = "_id";
    private static final String KEY_NAME = "app_name";
    private static final String KEY_PACKAGE = "package_name";
    private static final String KEY_CATEGORY = "category";
    private static final String KEY_TYPE = "type";
    private static final String KEY_CONTENT = "content";
    private static final String KEY_TIME_STAMP = "time_stamp";
    private static final String KEY_HOSTNAME = "host_name";
    private static final String KEY_REFPACKET_ID = "ref_pkt_id";

    public static final int FOREGROUND_STATUS = 1;
    public static final int BACKGROUND_STATUS = 0;
    public static final int UNSPECIFIED_STATUS = -1;

    //Note: foreground status is either 1 for foreground, 0 for background, or -1 if not specified.
    private static final String KEY_FOREGROUND_STATUS = "foreground_status";

    // App status events table name
    private static final String TABLE_APP_STATUS_EVENTS = "app_status_events";
    // App status events Table Columns names
    private static final String CREATE_APP_STATUS_TABLE = "CREATE TABLE " + TABLE_APP_STATUS_EVENTS + "("
            + KEY_ID + " INTEGER PRIMARY KEY AUTOINCREMENT,"
            + KEY_PACKAGE + " TEXT,"
            + KEY_TIME_STAMP + " INTEGER,"
            + KEY_FOREGROUND_STATUS + " INTEGER,"
            + KEY_HOSTNAME + " TEXT)";

    private static final String TAG = DatabaseHandler.class.getSimpleName();

    // Packet record table
    private static final String TABLE_PACKET = "packets";
    private static final String KEY_PACKET_ID = "_id";
    private static final String KEY_PACKET_DOMAIN = "domain";
    private static final String KEY_PACKET_IP = "ip";
    private static final String KEY_PACKET_PORT = "port";
    private static final String KEY_PACKET_TYPE = "type";
    private static final String KEY_PACKET_PATH = "path";
    private static final String KEY_PACKET_QUERY = "querys";
    private static final String KEY_PACKET_FRAGMENT = "fragments";
    private static final String KEY_PACKET_PAYLOAD = "payload";
    private static final String KEY_PACKET_TIME = "time";

    private static final String CREATE_PACKET_TABLE = "CREATE TABLE " + TABLE_PACKET + "("
            + KEY_PACKET_ID + " INTEGER PRIMARY KEY AUTOINCREMENT,"
            + KEY_PACKET_DOMAIN + " TEXT,"
            + KEY_PACKET_IP + " TEXT,"
            + KEY_PACKET_PORT + " INTEGER,"
            + KEY_PACKET_TYPE + " TEXT,"
            + KEY_PACKET_PATH + " TEXT,"
            + KEY_PACKET_QUERY + " TEXT,"
            + KEY_PACKET_FRAGMENT + " TEXT,"
            + KEY_PACKET_PAYLOAD + " TEXT,"
            + KEY_PACKET_TIME + " TEXT )";


    // Data leak table
    private static final String TABLE_DATA_LEAKS = "data_leaks";
    private static final String KEY_FREQUENCY = "frequency";
    private static final String KEY_IGNORE = "ignore";
    private static final String CREATE_DATA_LEAKS_TABLE = "CREATE TABLE " + TABLE_DATA_LEAKS + "("
            + KEY_ID + " INTEGER PRIMARY KEY AUTOINCREMENT,"
            + KEY_PACKAGE + " TEXT,"
            + KEY_NAME + " TEXT,"
            + KEY_CATEGORY + " TEXT,"
            + KEY_TYPE + " TEXT,"
            + KEY_CONTENT + " TEXT,"
            + KEY_TIME_STAMP + " TEXT,"
            + KEY_FOREGROUND_STATUS + " INTEGER,"
            + KEY_HOSTNAME + " TEXT)";
    private static final String CREATE_LEAK_SUMMARY_TABLE = "CREATE TABLE " + TABLE_LEAK_SUMMARY + "("
            + KEY_ID + " INTEGER PRIMARY KEY AUTOINCREMENT,"
            + KEY_PACKAGE + " TEXT,"
            + KEY_NAME + " TEXT,"
            + KEY_CATEGORY + " TEXT,"
            + KEY_FREQUENCY + " INTEGER,"
            + KEY_IGNORE + " INTEGER)";

    // Suspicious domain alert table
    private static final String TABLE_DOMAIN_ALERT = "domain_alerts";
    private static final String KEY_DOMAIN_DOMAIN = "domain";
    private static final String KEY_DOMAIN_ISDGA = "isdga";
    private static final String KEY_DOMAIN_SCORE = "score";
    private static final String CREATE_DOMAIN_TABLE = "CREATE TABLE " + TABLE_DOMAIN_ALERT + "("
            + KEY_ID + " INTEGER PRIMARY KEY AUTOINCREMENT,"
            + KEY_PACKAGE + " TEXT,"
            + KEY_NAME + " TEXT,"
            + KEY_REFPACKET_ID + " INTEGER,"
            + KEY_DOMAIN_DOMAIN + " TEXT,"
            + KEY_DOMAIN_ISDGA + " TEXT,"
            + KEY_TIME_STAMP + " TEXT,"
            + KEY_DOMAIN_SCORE + " TEXT)";

    // Cyptominer alert table
    private static final String TABLE_CRYPTO_ALERT = "crypto_alerts";
    private static final String KEY_CRYPTO_DOMAIN = "domain";
    private static final String KEY_CRYPTO_DOMAINISPOOL = "ispool";
    private static final String KEY_CRYPTO_SIGNATURE = "signature";
    private static final String CREATE_CRYPTO_TABLE = "CREATE TABLE " + TABLE_CRYPTO_ALERT + "("
            + KEY_ID + " INTEGER PRIMARY KEY AUTOINCREMENT,"
            + KEY_PACKAGE + " TEXT,"
            + KEY_NAME + " TEXT,"
            + KEY_REFPACKET_ID + " INTEGER,"
            + KEY_CRYPTO_DOMAIN + " TEXT,"
            + KEY_CRYPTO_SIGNATURE + " TEXT,"
            + KEY_TIME_STAMP + " TEXT,"
            + KEY_CRYPTO_DOMAINISPOOL + " TEXT)";

    // Traffic summary table
    private static final String TABLE_TRAFFIC_SUMMARY = "traffic_summary";
    private static final String KEY_TRAFFIC_ID = "_id";
    private static final String KEY_TRAFFIC_APP_NAME = "app_name";
    private static final String KEY_TRAFFIC_DEST_ADDR = "dest_addr";
    private static final String KEY_TRAFFIC_ENCRYPTION = "encryption";
    private static final String KEY_TRAFFIC_SIZE = "data_size";
    private static final String KEY_TRAFFIC_DIRECTION_OUT = "direction_out";

    private static final String CREATE_TRAFFIC_TABLE = "CREATE TABLE " + TABLE_TRAFFIC_SUMMARY + "("
            + KEY_TRAFFIC_ID + " INTEGER PRIMARY KEY AUTOINCREMENT,"
            + KEY_TRAFFIC_APP_NAME + " TEXT,"
            + KEY_TRAFFIC_DEST_ADDR + " TEXT,"
            + KEY_TRAFFIC_ENCRYPTION + " INTEGER,"
            + KEY_TRAFFIC_SIZE + " INTEGER,"
            + KEY_TRAFFIC_DIRECTION_OUT + " INTEGER )";

    /**
     * All CRUD(Create, Read, Update, Delete) Operations
     */

    public void addtraffic(TrafficReport traffic){
        int encryption;
        if (traffic.metaData.encrypted){
            encryption = 1;
        } else{
            encryption = 0;
        }
        int outgoing= 0;
        String destIP = traffic.metaData.srcIP;
        if(traffic.metaData.outgoing){
            outgoing = 1;
            destIP = traffic.metaData.destIP;
        }
        Cursor cursor = mDB.query(TABLE_TRAFFIC_SUMMARY,
                new String[]{KEY_TRAFFIC_ID, KEY_TRAFFIC_SIZE},
                KEY_TRAFFIC_APP_NAME + "=? AND " + KEY_TRAFFIC_DEST_ADDR + "=? AND "
                        + KEY_TRAFFIC_ENCRYPTION + "=? AND " + KEY_TRAFFIC_DIRECTION_OUT + "=?",
                new String[]{traffic.metaData.appName, destIP, Integer.toString(encryption), Integer.toString(outgoing)}, null, null, null, null);

        if (cursor != null) {
            if (!cursor.moveToFirst()) { // this package(app) has no leak of this category previously
                ContentValues values = new ContentValues();
                values.put(KEY_TRAFFIC_APP_NAME, traffic.metaData.appName);
                values.put(KEY_TRAFFIC_DEST_ADDR, destIP);
                values.put(KEY_TRAFFIC_ENCRYPTION, encryption);
                values.put(KEY_TRAFFIC_SIZE, traffic.size);
                values.put(KEY_TRAFFIC_DIRECTION_OUT, outgoing);
                mDB.insert(TABLE_TRAFFIC_SUMMARY, null, values);
                cursor = mDB.query(TABLE_TRAFFIC_SUMMARY,
                        new String[]{KEY_TRAFFIC_ID, KEY_TRAFFIC_SIZE},
                        KEY_TRAFFIC_APP_NAME + "=? AND " + KEY_TRAFFIC_DEST_ADDR + "=? AND "
                                + KEY_TRAFFIC_ENCRYPTION + "=? AND " + KEY_TRAFFIC_DIRECTION_OUT + "=?",
                        new String[]{traffic.metaData.appName, destIP, Integer.toString(encryption)}, null, null, null, null);
            }
            if (!cursor.moveToFirst()) {
                if (DEBUG) Logger.i("DatabaseHandler", "fail to create summary table");
                cursor.close();
                return;
            }

            int Id = cursor.getInt(0);
            int size = cursor.getInt(1);

            cursor.close();

            // Need to update frequency in summary table accordingly
            // Which row to update, based on the package and category
            ContentValues values = new ContentValues();
            values.put(KEY_TRAFFIC_SIZE, size + traffic.size);

            String selection = KEY_TRAFFIC_ID + " =?";
            String[] selectionArgs = {String.valueOf(Id)};

            int count = mDB.update(
                    TABLE_TRAFFIC_SUMMARY,
                    values,
                    selection,
                    selectionArgs);

            if (DEBUG) Logger.d(TAG, "Testing: update appname: "+ traffic.metaData.appName + " to: " + destIP + " : " + (size + traffic.size)) ;

            if (count == 0) {
                if (DEBUG) Logger.i("DatabaseHandler", "fail to update summary table");
            }
        }
    }

    public List<Traffic> getTraffics(String appName, boolean encrypted, boolean outgoing) {
        List<Traffic> traffics = new ArrayList<>();
        Cursor cursor = mDB.query(TABLE_TRAFFIC_SUMMARY, new String[]{KEY_TRAFFIC_DEST_ADDR, KEY_TRAFFIC_SIZE},
                KEY_TRAFFIC_APP_NAME + "=? AND " + KEY_TRAFFIC_ENCRYPTION + "=? AND " + KEY_TRAFFIC_DIRECTION_OUT + "=? ",
                new String[]{appName, encrypted ? "1" : "0", outgoing ? "1" : "0"}, null, null, null);
        if (cursor != null) {
            if (cursor.moveToFirst()) {
                do {
                    Traffic traffic = new Traffic(appName, cursor.getString(0), encrypted, cursor.getInt(1), outgoing) ;
                    traffics.add(traffic);
                } while (cursor.moveToNext());
            }
            cursor.close();
        }
        // return contact list
        return traffics;
    }

    public List<Traffic> getTraffics(boolean encrypted, boolean outgoing) {
        List<Traffic> traffics = new ArrayList<>();
        Cursor cursor = mDB.query(TABLE_TRAFFIC_SUMMARY, new String[]{KEY_TRAFFIC_APP_NAME, KEY_TRAFFIC_DEST_ADDR, KEY_TRAFFIC_SIZE},
                KEY_TRAFFIC_ENCRYPTION + "=? AND " + KEY_TRAFFIC_DIRECTION_OUT + "=? ",
                new String[]{encrypted ? "1" : "0", outgoing ? "1" : "0"}, null, null, null);
        if (cursor != null) {
            if (cursor.moveToFirst()) {
                do {
                    Traffic traffic = new Traffic(cursor.getString(0), cursor.getString(1), encrypted, cursor.getInt(2), outgoing);
                    traffics.add(traffic);
                } while (cursor.moveToNext());
            }
            cursor.close();
        }
        // return contact list
        return traffics;
    }

    public PacketRecord addPacketRecord(PacketRecord record) {
        ContentValues values = new ContentValues();
        values.put(KEY_PACKET_DOMAIN, record.domain);
        values.put(KEY_PACKET_IP, record.destIp);
        values.put(KEY_PACKET_PORT, record.destPort);
        values.put(KEY_PACKET_TYPE, record.type);
        values.put(KEY_PACKET_PATH, record.path);
        values.put(KEY_PACKET_QUERY, record.query);
        values.put(KEY_PACKET_FRAGMENT, record.fragment);
        values.put(KEY_PACKET_PAYLOAD, record.payload);
        values.put(KEY_PACKET_TIME, record.time);

        record.dbId = mDB.insert(TABLE_PACKET, null, values);
        return record;
    }

    public PacketRecord getPacketRecord(long packetId) {
        PacketRecord record = null;
        Cursor cursor = mDB.query(TABLE_PACKET, new String[]{KEY_PACKET_DOMAIN, KEY_PACKET_IP,
                        KEY_PACKET_PORT, KEY_PACKET_TYPE, KEY_PACKET_PATH, KEY_PACKET_QUERY, KEY_PACKET_FRAGMENT, KEY_PACKET_PAYLOAD, KEY_PACKET_TIME},
                KEY_ID + "=? ",
                new String[]{Long.toString(packetId)}, null, null, null);
        if (cursor != null) {
            if (cursor.moveToFirst()) {
                record = new PacketRecord(cursor.getString(0), cursor.getString(1),
                        cursor.getInt(2), cursor.getString(3), cursor.getString(4),
                        cursor.getString(5), cursor.getString(6), cursor.getString(3));
            }
            cursor.close();
        }
        return record;
    }

    public void deletePackage(String packageName) {
        mDB.delete(TABLE_DATA_LEAKS, KEY_PACKAGE + "=?", new String[] {packageName});
        mDB.delete(TABLE_LEAK_SUMMARY, KEY_PACKAGE + "=?", new String[] {packageName});
        mDB.delete(TABLE_APP_STATUS_EVENTS, KEY_PACKAGE + "=?", new String[] {packageName});
        mDB.delete(TABLE_PACKET, KEY_PACKAGE + "=?", new String[] {packageName});
        mDB.delete(TABLE_DOMAIN_ALERT, KEY_PACKAGE + "=?", new String[] {packageName});
        mDB.delete(TABLE_CRYPTO_ALERT, KEY_PACKAGE + "=?", new String[] {packageName});
    }

    // Adding new data leak
    private void addDataLeak(String packageName, String appName, String category, String type, String content, String hostName) {
        ContentValues values = new ContentValues();
        values.put(KEY_PACKAGE, packageName); // App Name
        values.put(KEY_NAME, appName); // App Name
        values.put(KEY_CATEGORY, category);
        values.put(KEY_TYPE, type); // Leak type
        values.put(KEY_CONTENT, content);
        values.put(KEY_TIME_STAMP, DATE_FORMAT.format(new Date())); // Leak time stamp
        values.put(KEY_FOREGROUND_STATUS, UNSPECIFIED_STATUS); // Leak foreground status
        values.put(KEY_HOSTNAME, hostName);

        // Inserting Row
        final long id = mDB.insert(TABLE_DATA_LEAKS, null, values);

        // A bug occurred when the update task ran so quickly after the app left the foreground
        // that the most recent status event was not yet available in the api. Hence, the leak was
        // incorrectly classified as foreground. To fix this, run the update task after 10 seconds
        // to ensure that the most recent status event is available.
        new Timer().schedule(new TimerTask() {
            @Override
            public void run() {
                new UpdateLeakForegroundStatus(applicationContext).execute(id);
            }
        }, TimeUnit.SECONDS.toMillis(10));
    }

    private void addDomainAlert(String packageName, String appName, String domain, boolean isDGA,
                                double score, long refPacketId, String time) {
        ContentValues values = new ContentValues();
        values.put(KEY_PACKAGE, packageName);
        values.put(KEY_NAME, appName);
        values.put(KEY_DOMAIN_DOMAIN, domain);
        String isDGAstr = isDGA ? "Yes" : "No";
        values.put(KEY_DOMAIN_ISDGA, isDGAstr);
        values.put(KEY_DOMAIN_SCORE, Double.toString(score));
        values.put(KEY_TIME_STAMP, time);
        values.put(KEY_REFPACKET_ID, refPacketId);

        mDB.insert(TABLE_DOMAIN_ALERT, null, values);
    }

    private void addCryptoAlert(String packageName, String appName, String domain, boolean isPool,
                                String signature, long refPacketId, String time) {
        ContentValues values = new ContentValues();
        values.put(KEY_PACKAGE, packageName);
        values.put(KEY_NAME, appName);
        values.put(KEY_CRYPTO_DOMAIN, domain);
        String isPoolStr = isPool ? "Yes" : "No";
        values.put(KEY_CRYPTO_DOMAINISPOOL, isPoolStr);
        values.put(KEY_CRYPTO_SIGNATURE, signature);
        values.put(KEY_REFPACKET_ID, refPacketId);
        values.put(KEY_TIME_STAMP, time);

        mDB.insert(TABLE_CRYPTO_ALERT, null, values);
    }

    public void addAppStatusEvent(String packageName, long timeStamp, int foreground) {
        if (foreground != 0 && foreground != 1) throw new RuntimeException("Must be 0 or 1");

        ContentValues values = new ContentValues();
        values.put(KEY_PACKAGE, packageName);
        values.put(KEY_TIME_STAMP, timeStamp);
        values.put(KEY_FOREGROUND_STATUS, foreground);

        // Inserting Row
        mDB.insert(TABLE_APP_STATUS_EVENTS, null, values);
    }

    private void addLeakSummary(LeakReport rpt) {
        ContentValues values = new ContentValues();
        values.put(KEY_PACKAGE, rpt.metaData.packageName);
        values.put(KEY_NAME, rpt.metaData.appName);
        values.put(KEY_CATEGORY, rpt.category.name());
        values.put(KEY_FREQUENCY, 0);
        values.put(KEY_IGNORE, 0);
        mDB.insert(TABLE_LEAK_SUMMARY, null, values);
    }

    public List<AppSummary> getAllApps() {
        List<AppSummary> apps = new ArrayList<>();
        Cursor cursor = mDB.query(TABLE_LEAK_SUMMARY, new String[]{KEY_PACKAGE, KEY_NAME, "SUM(" + KEY_FREQUENCY + ")", "MIN(" + KEY_IGNORE + ")"}, null, null, KEY_PACKAGE + ", " + KEY_NAME, null, null);
        if (cursor != null) {
            if (cursor.moveToFirst()) {
                do {
                    AppSummary app = new AppSummary(cursor.getString(0), cursor.getString(1), cursor.getInt(2), cursor.getInt(3));
                    apps.add(app);
                } while (cursor.moveToNext());

            }
            cursor.close();
        }
        return apps;
    }

    public List<AppStatusEvent> getAppStatusEvents() {
        List<AppStatusEvent> appStatusEvents = new ArrayList<>();
        Cursor cursor = mDB.query(TABLE_APP_STATUS_EVENTS, new String[]{KEY_PACKAGE, KEY_TIME_STAMP, KEY_FOREGROUND_STATUS}, null, null, null, null, null);
        if (cursor != null) {
            if (cursor.moveToFirst()) {
                do {
                    AppStatusEvent appStatusEvent = new AppStatusEvent(cursor.getString(0), cursor.getLong(1), cursor.getInt(2));
                    appStatusEvents.add(appStatusEvent);
                } while (cursor.moveToNext());

            }
            cursor.close();
        }
        return appStatusEvents;
    }

    public List<AppStatusEvent> getAppStatusEvents(String packageName) {
        List<AppStatusEvent> appStatusEvents = new ArrayList<>();
        Cursor cursor = mDB.query(TABLE_APP_STATUS_EVENTS, new String[]{KEY_PACKAGE, KEY_TIME_STAMP, KEY_FOREGROUND_STATUS}, KEY_PACKAGE + "=?", new String[]{packageName}, null, null, null);
        if (cursor != null) {
            if (cursor.moveToFirst()) {
                do {
                    AppStatusEvent appStatusEvent = new AppStatusEvent(cursor.getString(0), cursor.getLong(1), cursor.getInt(2));
                    appStatusEvents.add(appStatusEvent);
                } while (cursor.moveToNext());

            }
            cursor.close();
        }
        return appStatusEvents;
    }

    public List<CategorySummary> getAppDetail(String packageName) {
        List<CategorySummary> categories = new ArrayList<>();
        Cursor cursor = mDB.query(TABLE_LEAK_SUMMARY, new String[]{KEY_ID, KEY_CATEGORY, KEY_FREQUENCY, KEY_IGNORE}, KEY_PACKAGE + "=?", new String[]{packageName}, null, null, null);
        if (cursor != null) {
            if (cursor.moveToFirst()) {
                do {
                    int notifyId = cursor.getInt(0);
                    String category = cursor.getString(1);
                    int count = cursor.getInt(2);
                    int ignore = cursor.getInt(3);
                    categories.add(new CategorySummary(notifyId, category, count, ignore));
                } while (cursor.moveToNext());
            }
            cursor.close();
        }

        return categories;
    }

    public DataLeak getLeakById(long id) {
        Cursor cursor = mDB.query(TABLE_DATA_LEAKS, new String[]{KEY_PACKAGE, KEY_NAME, KEY_CATEGORY, KEY_TYPE, KEY_CONTENT, KEY_TIME_STAMP, KEY_FOREGROUND_STATUS, KEY_HOSTNAME}, KEY_ID + "=?", new String[]{String.valueOf(id)}, null, null, null);
        if (cursor != null) {
            if (cursor.moveToFirst()) {
                DataLeak leak = new DataLeak(cursor.getString(0), cursor.getString(1), cursor.getString(2), cursor.getString(3), cursor.getString(4), cursor.getString(5), cursor.getInt(6), cursor.getString(7));
                cursor.close();
                return leak;
            }
            cursor.close();
        }
        return null;
    }


    public List<DataLeak> getAppLeaks(String packageName, String category) {
        List<DataLeak> leakList = new ArrayList<>();
        Cursor cursor = mDB.query(TABLE_DATA_LEAKS, new String[]{KEY_PACKAGE, KEY_NAME, KEY_TYPE, KEY_CONTENT, KEY_TIME_STAMP, KEY_FOREGROUND_STATUS, KEY_HOSTNAME}, KEY_PACKAGE + "=? AND " + KEY_CATEGORY + "=?", new String[]{packageName, category}, null, null, null);
        if (cursor != null) {
            if (cursor.moveToFirst()) {
                do {
                    DataLeak leak = new DataLeak(cursor.getString(0), cursor.getString(1), category, cursor.getString(2), cursor.getString(3), cursor.getString(4), cursor.getInt(5), cursor.getString(6));
                    leakList.add(leak);
                } while (cursor.moveToNext());
            }
            cursor.close();
        }
        // return contact list
        return leakList;
    }

    public List<DataLeak> getAppLeaks(String category) {
        List<DataLeak> leakList = new ArrayList<>();
        Cursor cursor = mDB.query(TABLE_DATA_LEAKS, new String[]{KEY_PACKAGE, KEY_NAME, KEY_TYPE, KEY_CONTENT, KEY_TIME_STAMP, KEY_FOREGROUND_STATUS, KEY_HOSTNAME}, KEY_CATEGORY + "=?", new String[]{category}, null, null, null);
        if (cursor != null) {
            if (cursor.moveToFirst()) {
                do {
                    DataLeak leak = new DataLeak(cursor.getString(0), cursor.getString(1), category, cursor.getString(2), cursor.getString(3), cursor.getString(4), cursor.getInt(5), cursor.getString(6));
                    leakList.add(leak);
                } while (cursor.moveToNext());
            }
            cursor.close();
        }
        // return contact list
        return leakList;
    }

    public List<DomainAlert> getAppDomainAlerts(String packageName) {
        List<DomainAlert> domainAlerts = new ArrayList<>();
        Cursor cursor = mDB.query(TABLE_DOMAIN_ALERT, new String[]{KEY_PACKAGE, KEY_NAME, KEY_DOMAIN_DOMAIN, KEY_DOMAIN_ISDGA, KEY_DOMAIN_SCORE, KEY_TIME_STAMP, KEY_REFPACKET_ID},
                KEY_PACKAGE + "=?", new String[]{packageName},
                null, null, null);
        if (cursor != null) {
            if (cursor.moveToFirst()) {
                do {
                    DomainAlert alert = new DomainAlert(cursor.getString(0), cursor.getString(1), "DOMAIN", cursor.getString(2), cursor.getString(3), cursor.getString(4), cursor.getString(5), cursor.getLong(6));
                    domainAlerts.add(alert);
                } while (cursor.moveToNext());
            }
            cursor.close();
        }
        return domainAlerts;
    }

    public List<CryptominerAlert> getAppCryptoAlerts(String packageName) {
        List<CryptominerAlert> cryptoAlerts = new ArrayList<>();
        Cursor cursor = mDB.query(TABLE_CRYPTO_ALERT, new String[]{KEY_PACKAGE, KEY_NAME, KEY_CRYPTO_DOMAIN, KEY_CRYPTO_DOMAINISPOOL, KEY_CRYPTO_SIGNATURE, KEY_TIME_STAMP, KEY_REFPACKET_ID},
                KEY_PACKAGE + "=?", new String[]{packageName},
                null, null, null);
        if (cursor != null) {
            if (cursor.moveToFirst()) {
                do {
                    CryptominerAlert alert = new CryptominerAlert(cursor.getString(0), cursor.getString(1), "DOMAIN", cursor.getString(2), cursor.getString(3), cursor.getString(4), cursor.getString(5), cursor.getLong(6));
                    cryptoAlerts.add(alert);
                } while (cursor.moveToNext());
            }
            cursor.close();
        }
        return cryptoAlerts;
    }

    private boolean isHttpMethod(String s) {
        return s.equals("GET")
                || s.equals("POST")
                || s.equals("PUT")
                || s.equals("HEAD")
                || s.equals("CONNECT")
                || s.equals("DELETE")
                || s.equals("OPTIONS");
    }

    /**
     * Update leak summary table, frequency.
     * Add leaks into dataleak table.
     * */
    public int findNotificationId(LeakReport rpt) {
        Cursor cursor = mDB.query(TABLE_LEAK_SUMMARY,
                new String[]{KEY_ID, KEY_FREQUENCY, KEY_IGNORE},
                KEY_PACKAGE + "=? AND " + KEY_CATEGORY + "=?",
                new String[]{rpt.metaData.packageName, rpt.category.name()}, null, null, null, null);

        if (cursor != null) {
            if (!cursor.moveToFirst()) { // this package(app) has no leak of this category previously
                addLeakSummary(rpt);
                cursor = mDB.query(TABLE_LEAK_SUMMARY,
                        new String[]{KEY_ID, KEY_FREQUENCY, KEY_IGNORE},
                        KEY_PACKAGE + "=? AND " + KEY_CATEGORY + "=?",
                        new String[]{rpt.metaData.packageName, rpt.category.name()}, null, null, null, null);
            }
            if (!cursor.moveToFirst()) {
                if (DEBUG) Logger.i("DatabaseHandler", "fail to create summary table");
                cursor.close();
                return -1;
            }

            int notifyId = cursor.getInt(0);
            int frequency = cursor.getInt(1);
            int ignore = cursor.getInt(2);

            cursor.close();

            if (rpt.category == LeakReport.LeakCategory.DOMAIN) {
                for (LeakInstance li : rpt.leaks) {
                    DomainInstance inst = (DomainInstance) li;
                    addDomainAlert(rpt.metaData.packageName, rpt.metaData.appName, inst.content,
                            inst.isDGA, inst.reputationScore, inst.refPacketId, inst.time);
                }
            } else if (rpt.category == LeakReport.LeakCategory.CRYPTOMINER) {
                for (LeakInstance li : rpt.leaks) {
                    CryptominerInstance inst = (CryptominerInstance) li;
                    addCryptoAlert(rpt.metaData.packageName, rpt.metaData.appName, inst.content,
                            inst.isPoolDomain, inst.signatureName, inst.refPacketId, inst.time);
                }
            } else {
                for (LeakInstance li : rpt.leaks) {
                    addDataLeak(rpt.metaData.packageName, rpt.metaData.appName, rpt.category.name(), li.type, li.content, rpt.metaData.destHostName);
                }
            }

            // Need to update frequency in summary table accordingly
            // Which row to update, based on the package and category
            ContentValues values = new ContentValues();
            values.put(KEY_FREQUENCY, frequency + rpt.leaks.size());

            String selection = KEY_ID + " =?";
            String[] selectionArgs = {String.valueOf(notifyId)};

            int count = mDB.update(
                    TABLE_LEAK_SUMMARY,
                    values,
                    selection,
                    selectionArgs);

            if (count == 0) {
                Logger.i("DatabaseHandler", "fail to update summary table");
            }
            return ignore == 1 ? -1 : notifyId;
        }
        return -1;
    }


    public int findNotificationCounter(int id, String category) {
        Cursor cursor = mDB.query(TABLE_LEAK_SUMMARY,
                new String[]{KEY_ID, KEY_FREQUENCY},
                KEY_ID + "=? AND " + KEY_CATEGORY + "=?",
                new String[]{String.valueOf(id), category}, null, null, null, null);

        if (cursor != null) {
            if (cursor.moveToFirst()) {
                int frequency = cursor.getInt(1);
                cursor.close();
                return frequency;
            }
            cursor.close();
        }

        return -1;
    }

    public void setDataLeakStatus(long id, int status) {
        if (status != BACKGROUND_STATUS && status != FOREGROUND_STATUS) throw new RuntimeException("Invalid status value.");
        ContentValues values = new ContentValues();
        values.put(KEY_FOREGROUND_STATUS, status);

        String selection = KEY_ID + " =?";
        String[] selectionArgs = {String.valueOf(id)};

        int count = mDB.update(
                TABLE_DATA_LEAKS,
                values,
                selection,
                selectionArgs);

        if (count == 0) {
            if (DEBUG) Logger.i("DatabaseHandler", "fail to set status for id: " + id);
        }
    }

    public void setIgnoreApp(String packageName, boolean ignore) {
        ContentValues values = new ContentValues();
        values.put(KEY_IGNORE, ignore ? 1 : 0);

        String selection = KEY_PACKAGE + " =?";
        String[] selectionArgs = {packageName};

        int count = mDB.update(
                TABLE_LEAK_SUMMARY,
                values,
                selection,
                selectionArgs);

        if (count == 0) {
            if (DEBUG) Logger.i("DatabaseHandler", "fail to set ignore for " + packageName);
        }
    }

    public void setIgnoreAppCategory(int notifyId, boolean ignore) {
        ContentValues values = new ContentValues();
        values.put(KEY_IGNORE, ignore ? 1 : 0);

        String selection = KEY_ID + " =?";
        String[] selectionArgs = {String.valueOf(notifyId)};
        int count = mDB.update(
                TABLE_LEAK_SUMMARY,
                values,
                selection,
                selectionArgs);
        if (count == 0) {
            if (DEBUG) Logger.i("DatabaseHandler", "fail to set ignore for " + notifyId);
        }
    }

}
