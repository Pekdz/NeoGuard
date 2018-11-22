package ca.uwaterloo.crysp.privacyguard.Application.Activities;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.widget.EditText;
import android.widget.TextView;

import ca.uwaterloo.crysp.privacyguard.Application.Database.DatabaseHandler;
import ca.uwaterloo.crysp.privacyguard.Application.Database.PacketRecord;
import ca.uwaterloo.crysp.privacyguard.Application.Logger;
import ca.uwaterloo.crysp.privacyguard.Application.PrivacyGuard;
import ca.uwaterloo.crysp.privacyguard.R;

public class PacketDetailActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        TextView tvDomain, tvType, tvTimestamp, tvPath, tvFragment;
        EditText etQuery, etPayload;
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
        tvType = findViewById(R.id.tvType);
        tvTimestamp = findViewById(R.id.tvTimeStamp);
        tvPath = findViewById(R.id.tvPath);
        tvFragment = findViewById(R.id.tvFragment);

        etQuery = findViewById(R.id.etQuery);
        etPayload = findViewById(R.id.etPayload);
        if (record.domain != null) {
            setTitle(record.domain);
        }
        sb.append(record.destIp);
        sb.append(":");
        sb.append(record.destPort);
        if (sb != null) {
            tvDomain.setText(sb);
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
        if (record.query != null) {
            etQuery.setText(record.query);
        }
        if (record.payload != null) {
            etPayload.setText(record.payload);
        }


    }
}
