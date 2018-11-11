package ca.uwaterloo.crysp.privacyguard.Application.Activities;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.TextView;

import java.util.List;

import ca.uwaterloo.crysp.privacyguard.Application.Database.DataLeak;
import ca.uwaterloo.crysp.privacyguard.Application.Database.URLTrace;
import ca.uwaterloo.crysp.privacyguard.R;

/**
 * Created by justinhu on 16-03-13.
 */
public class DetailUrlListViewAdapter extends BaseAdapter {
    private final Context context;
    private List<URLTrace> list;

    public DetailUrlListViewAdapter(Context context, List<URLTrace> list) {
        super();
        this.context = context;
        this.list = list;

    }

    public void updateData(List<URLTrace> list) {
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
        ViewHolder holder;
        if (convertView == null) {
            LayoutInflater inflater = (LayoutInflater) context
                    .getSystemService(Context.LAYOUT_INFLATER_SERVICE);
            convertView = inflater.inflate(R.layout.listview_detail_url, null);
            holder = new ViewHolder();

            holder.resource = (TextView) convertView.findViewById(R.id.detail_url);
            holder.time = (TextView) convertView.findViewById(R.id.detail_time);
            holder.host = (TextView) convertView.findViewById(R.id.detail_host);

            convertView.setTag(holder);
        } else {
            holder = (ViewHolder) convertView.getTag();
        }

        URLTrace url = list.get(position);
        holder.resource.setText(url.getRes());
        holder.time.setText(url.getTimestamp());
        holder.host.setText(url.getHost());
        return convertView;
    }

    public static class ViewHolder {
        public TextView host;
        public TextView resource;
        public TextView time;
    }
}
