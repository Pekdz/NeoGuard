package ca.uwaterloo.crysp.privacyguard.Application.Activities;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.TextView;

import java.util.List;

import ca.uwaterloo.crysp.privacyguard.Application.Database.CryptominerAlert;
import ca.uwaterloo.crysp.privacyguard.Application.Database.DomainAlert;
import ca.uwaterloo.crysp.privacyguard.R;

public class DetailCryptoListViewAdapter extends BaseAdapter {
    private final Context context;
    private List<CryptominerAlert> list;

    public DetailCryptoListViewAdapter(Context context, List<CryptominerAlert> list) {
        super();
        this.context = context;
        this.list = list;

    }

    public void updateData(List<CryptominerAlert> list) {
        this.list = list;
        this.notifyDataSetChanged();
    }

    @Override
    public int getCount() {
        return list.size();
    }

    @Override
    public Object getItem(int position) {
        return list.get(position);
    }

    @Override
    public long getItemId(int position) {
        return position;
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        DetailCryptoListViewAdapter.ViewHolder holder;
        if (convertView == null) {
            LayoutInflater inflater = (LayoutInflater) context
                    .getSystemService(Context.LAYOUT_INFLATER_SERVICE);
            convertView = inflater.inflate(R.layout.listview_detail_crypto, null);

            holder = new DetailCryptoListViewAdapter.ViewHolder();
            holder.domain = (TextView) convertView.findViewById(R.id.detail_domain);
            holder.ispool = (TextView) convertView.findViewById(R.id.detail_ispool);
            holder.signature = (TextView) convertView.findViewById(R.id.detail_signature);
            holder.time = (TextView) convertView.findViewById(R.id.detail_time);

            convertView.setTag(holder);
        } else {
            holder = (DetailCryptoListViewAdapter.ViewHolder) convertView.getTag();
        }

        CryptominerAlert alert = list.get(position);
        holder.domain.setText(alert.getDomain());
        holder.time.setText(alert.getTimestamp());
        holder.ispool.setText(alert.getIsPoolDomain());
        holder.signature.setText(alert.getSignatureName());
        return convertView;
    }

    public static class ViewHolder {
        public TextView domain;
        public TextView ispool;
        public TextView signature;
        public TextView time;
    }
}
