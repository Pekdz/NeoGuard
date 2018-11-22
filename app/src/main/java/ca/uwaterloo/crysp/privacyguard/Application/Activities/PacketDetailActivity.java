package ca.uwaterloo.crysp.privacyguard.Application.Activities;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
import android.widget.TextView;

import ca.uwaterloo.crysp.privacyguard.Application.Database.DatabaseHandler;
import ca.uwaterloo.crysp.privacyguard.Application.Database.PacketRecord;
import ca.uwaterloo.crysp.privacyguard.Application.PrivacyGuard;
import ca.uwaterloo.crysp.privacyguard.R;

public class PacketDetailActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        TextView tvDomain, tvIP, tvType, tvTimestamp, tvPath, tvFragment, tvQuery, tvPayload;

        StringBuilder sb = new StringBuilder();
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_packet_detail);
        DatabaseHandler db = DatabaseHandler.getInstance(this);

        // get value from intent
        Intent intent = getIntent();
        long id = intent.getLongExtra(PrivacyGuard.EXTRA_REF_PACKETID, -1);
        if (id == -1) {
            return;
        }

        PacketRecord record = db.getPacketRecord(id);
        // Logger.d("PacketDetail: ", record.toString());
        tvDomain = findViewById(R.id.tvDomain);
        tvIP = findViewById(R.id.tvIP);
        tvType = findViewById(R.id.tvType);
        tvTimestamp = findViewById(R.id.tvTimeStamp);
        tvPath = findViewById(R.id.tvPath);
        tvPath.setMovementMethod(new ScrollingMovementMethod());
        tvFragment = findViewById(R.id.tvFragment);

        tvQuery = findViewById(R.id.tvQuery);
        tvQuery.setMovementMethod(new ScrollingMovementMethod());

        tvPayload = findViewById(R.id.tvPayload);
        tvPayload.setMovementMethod(new ScrollingMovementMethod());
        if (record.domain != null) {
            tvDomain.setText(record.domain);
        }
        sb.append(record.destIp);
        sb.append(":");
        sb.append(record.destPort);
        if (sb != null) {
            tvIP.setText(sb);
        }
        if (record.type != null) {
            tvType.setText(record.type);
        }
        if (record.time != null) {
            tvTimestamp.setText(record.time);
        }
        if (record.path != null) {
            tvPath.setText(record.path);
        }
        if (record.fragment != null) {
            tvFragment.setText(record.fragment);
        }
        else{
            tvFragment.setText("No Fragment");
        }
        if (record.query != null) {
            tvQuery.setText(record.query);
        }
        else{
            tvQuery.setText("No Query");
        }
        if ((record.payload != null)&&(!record.payload.equals(""))) {
            tvPayload.setText(record.payload);
        }
        else{
            tvPayload.setText(" No Content");
        }


    }
}
