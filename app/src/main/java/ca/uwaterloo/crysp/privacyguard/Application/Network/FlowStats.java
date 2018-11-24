package ca.uwaterloo.crysp.privacyguard.Application.Network;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import ca.uwaterloo.crysp.privacyguard.Application.Logger;

public class FlowStats {
    private static final String TAG = FlowStats.class.getSimpleName();
    private long startTime;
    private ArrayList<Double> fwdPktList;
    private ArrayList<Double> backPktList;

    private double duration; // ms

    private double totalNum;
    private double fwdPktNum;
    private double backPktNum;

    private double totalLen; // byte
    private double backTotalLen;
    private double fwdTotalLen;

    private double pktMaxLen;
    private double pktMinLen;
    private double fwdPktMaxLen;
    private double fwdPktMinLen;
    private double backPktMaxLen;
    private double backPktMinLen;

    private double pktLenMean;
    private double pktLenStd;
    private double pktLenVar;
    private double pktLenMid;

    public FlowStats() {
        startTime = System.currentTimeMillis();
        fwdPktList = new ArrayList<>();
        backPktList = new ArrayList<>();

        totalNum = 0;
        fwdPktNum = 0;
        backPktNum = 0;
        totalLen = 0;
        backTotalLen = 0;
        pktMaxLen = 0;
        pktMinLen = 0;
        fwdTotalLen = 0;
        fwdPktMaxLen = 0;
        fwdPktMinLen = 0;
        backPktMaxLen = 0;
        backPktMinLen = 0;
        pktLenMean = 0;
        pktLenStd = 0;
        pktLenVar = 0;
        pktLenMid = 0;
    }

    public void addFwdPkt(double pktLen) {
        fwdPktList.add(pktLen);
    }

    public void addBackPkt(double pktLen) {
        backPktList.add(pktLen);
    }

    public List<Double> calculate() {
        duration = System.currentTimeMillis() - startTime;

        Collections.sort(backPktList);
        Collections.sort(fwdPktList);

        fwdPktNum = fwdPktList.size();
        backPktNum = backPktList.size();
        totalNum = fwdPktNum + backPktNum;

        if (totalNum == 0) {
            return null;
        }

        fwdPktMaxLen = fwdPktNum > 0 ? fwdPktList.get((int)fwdPktNum - 1) : 0;
        fwdPktMinLen = fwdPktNum > 0  ? fwdPktList.get(0) : 0;
        backPktMaxLen = backPktNum > 0 ? backPktList.get((int)backPktNum - 1) : 0;
        backPktMinLen = backPktNum > 0 ? backPktList.get(0) : 0;
        if (fwdPktNum == 0) {
            pktMaxLen = backPktMaxLen;
            pktMinLen = backPktMinLen;
        } else if (backPktNum == 0) {
            pktMaxLen = fwdPktMaxLen;
            pktMinLen = fwdPktMinLen;
        } else  {
            pktMaxLen = fwdPktMaxLen >= backPktMaxLen ? fwdPktMaxLen : backPktMaxLen;
            pktMinLen = fwdPktMinLen <= backPktMinLen ? fwdPktMinLen : backPktMinLen;
        }

        fwdTotalLen = sum(fwdPktList);
        backTotalLen = sum(backPktList);
        totalLen = fwdTotalLen + backTotalLen;

        List<Double> pktList = merged(fwdPktList, backPktList);
        pktLenMean = totalLen / totalNum;
        pktLenVar = getVariance(pktLenMean, pktList);
        pktLenStd = (float) Math.sqrt(pktLenVar);
        pktLenMid = getMedian(pktList);

        // Logger.d(TAG, this.toString());
        /*
          'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
          'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
          'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Fwd Packet Length Max',
          'Fwd Packet Length Min', 'Min Packet Length', 'Max Packet Length',
          'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance'
         */
        ArrayList<Double> paramList = new ArrayList<>();
        paramList.add(duration);
        paramList.add(fwdPktNum);
        paramList.add(backPktNum);
        paramList.add(fwdTotalLen);
        paramList.add(backTotalLen);
        paramList.add(backPktMaxLen);
        paramList.add(backPktMinLen);
        paramList.add(fwdPktMaxLen);
        paramList.add(fwdPktMinLen);
        paramList.add(pktMinLen);
        paramList.add(pktMaxLen);
        paramList.add(pktLenMean);
        paramList.add(pktLenStd);
        paramList.add(pktLenVar);
        return paramList;
    }

    @Override
    public String toString() {
        return "FlowStats{" +
                "duration=" + duration +
                ", totalNum=" + totalNum +
                ", fwdPktNum=" + fwdPktNum +
                ", backPktNum=" + backPktNum +
                ", totalLen=" + totalLen +
                ", backTotalLen=" + backTotalLen +
                ", fwdTotalLen=" + fwdTotalLen +
                ", pktMaxLen=" + pktMaxLen +
                ", pktMinLen=" + pktMinLen +
                ", fwdPktMaxLen=" + fwdPktMaxLen +
                ", fwdPktMinLen=" + fwdPktMinLen +
                ", backPktMaxLen=" + backPktMaxLen +
                ", backPktMinLen=" + backPktMinLen +
                ", pktLenMean=" + pktLenMean +
                ", pktLenStd=" + pktLenStd +
                ", pktLenVar=" + pktLenVar +
                ", pktLenMid=" + pktLenMid +
                '}';
    }

    private double sum(List<Double> list) {
        double sum = 0;
        for (double i : list)
            sum = sum + i;
        return sum;
    }

    private static List<Double> merged(List<Double> left, List<Double> right) {
        if (left.isEmpty())
            return right;
        else if (right.isEmpty())
            return left;

        int leftIndex = 0;
        int rightIndex = 0;
        List<Double> merged = new ArrayList<>();

        while (leftIndex < left.size() && rightIndex < right.size()) {
            if (left.get(leftIndex) < right.get(rightIndex)) {
                merged.add(left.get(leftIndex++));
            } else {
                merged.add(right.get(rightIndex++));
            }
        }
        merged.addAll(left.subList(leftIndex, left.size()));
        merged.addAll(right.subList(rightIndex, right.size()));
        return merged;
    }

    private double getVariance(double mean, List<Double> list) {
        double temp = 0;
        for(double a : list)
            temp += (a-mean)*(a-mean);
        return temp/(list.size() - 1);
    }


    private double getMedian(List<Double> list) {
        if (list.size() % 2 == 0)
            return (list.get((list.size() / 2) - 1) + list.get(list.size() / 2)) / 2.0;
        return list.get(list.size() / 2);
    }
}
