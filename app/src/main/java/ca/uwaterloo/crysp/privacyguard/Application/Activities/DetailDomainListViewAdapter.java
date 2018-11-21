package ca.uwaterloo.crysp.privacyguard.Application.Activities;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.TextView;

import java.util.List;

import ca.uwaterloo.crysp.privacyguard.Application.Database.DomainAlert;
import ca.uwaterloo.crysp.privacyguard.R;

public class DetailDomainListViewAdapter extends BaseAdapter {
    private final Context context;
    private List<DomainAlert> list;

    public DetailDomainListViewAdapter(Context context, List<DomainAlert> list) {
        super();
        this.context = context;
        this.list = list;

    }

    public void updateData(List<DomainAlert> list) {
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
        DetailDomainListViewAdapter.ViewHolder holder;
        if (convertView == null) {
            LayoutInflater inflater = (LayoutInflater) context
                    .getSystemService(Context.LAYOUT_INFLATER_SERVICE);
            convertView = inflater.inflate(R.layout.listview_detail_domain, null);

            holder = new DetailDomainListViewAdapter.ViewHolder();
            holder.domain = (TextView) convertView.findViewById(R.id.detail_domain);
            holder.isdga = (TextView) convertView.findViewById(R.id.detail_isdga);
            holder.score = (TextView) convertView.findViewById(R.id.detail_score);
            holder.time = (TextView) convertView.findViewById(R.id.detail_time);

            convertView.setTag(holder);
        } else {
            holder = (DetailDomainListViewAdapter.ViewHolder) convertView.getTag();
        }

        DomainAlert alert = list.get(position);
        holder.domain.setText(alert.getDomain());
        holder.time.setText(alert.getTimestamp());
        holder.isdga.setText(alert.isDGA());
        holder.score.setText(alert.getReputationScore());
        return convertView;
    }

    public static class ViewHolder {
        public TextView domain;
        public TextView isdga;
        public TextView score;
        public TextView time;
    }
}
