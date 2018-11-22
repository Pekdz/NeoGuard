package ca.uwaterloo.crysp.privacyguard.Application.Network;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import ca.uwaterloo.crysp.privacyguard.Application.Logger;

public class FlowStats {
    private static final String TAG = FlowStats.class.getSimpleName();
    private long startTime;
    private ArrayList<Integer> fwdPktList;
    private ArrayList<Integer> backPktList;

    long duration; // ms

    int totalNum;
    int fwdPktNum;
    int backPktNum;

    int totalLen; // byte
    int backTotalLen;
    int fwdTotalLen;

    int fwdPktMaxLen;
    int fwdPktMinLen;
    int backPktMaxLen;
    int backPktMinLen;

    float pktLenMean;
    float pktLenStd;
    float pktLenVar;
    float pktLenMid;

    public FlowStats() {
        startTime = System.currentTimeMillis();
        fwdPktList = new ArrayList<>();
        backPktList = new ArrayList<>();

        totalNum = 0;
        fwdPktNum = 0;
        backPktNum = 0;
        totalLen = 0;
        backTotalLen = 0;
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

    public void addFwdPkt(int pktLen) {
        fwdPktList.add(pktLen);
    }

    public void addBackPkt(int pktLen) {
        backPktList.add(pktLen);
    }

    public void calculate() {
        duration = System.currentTimeMillis() - startTime;

        Collections.sort(backPktList);
        Collections.sort(fwdPktList);

        fwdPktNum = fwdPktList.size();
        backPktNum = backPktList.size();
        totalNum = fwdPktNum + backPktNum;

        if (totalNum == 0) {
            return;
        }

        fwdPktMaxLen = fwdPktNum > 0 ? fwdPktList.get(fwdPktNum - 1) : 0;
        fwdPktMinLen = fwdPktNum > 0  ? fwdPktList.get(0) : 0;
        backPktMaxLen = backPktNum > 0 ? backPktList.get(backPktNum - 1) : 0;
        backPktMinLen = backPktNum > 0 ? backPktList.get(0) : 0;

        fwdTotalLen = sum(fwdPktList);
        backTotalLen = sum(backPktList);
        totalLen = fwdTotalLen + backTotalLen;

        List<Integer> pktList = merged(fwdPktList, backPktList);
        pktLenMean = totalLen / totalNum;
        pktLenVar = getVariance(pktLenMean, pktList);
        pktLenStd = (float) Math.sqrt(pktLenVar);
        pktLenMid = getMedian(pktList);

        Logger.d(TAG, this.toString());
    }

    @Override
    public String toString() {
        return "FlowStats {" +
                "duration=" + duration +
                ", totalNum=" + totalNum +
                ", fwdPktNum=" + fwdPktNum +
                ", backPktNum=" + backPktNum +
                ", totalLen=" + totalLen +
                ", backTotalLen=" + backTotalLen +
                ", fwdTotalLen=" + fwdTotalLen +
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

    private int sum(List<Integer> list) {
        int sum = 0;
        for (int i : list)
            sum = sum + i;
        return sum;
    }

    private static List<Integer> merged(List<Integer> left, List<Integer> right) {
        int leftIndex = 0;
        int rightIndex = 0;
        List<Integer> merged = new ArrayList<>();

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

    private float getVariance(float mean, List<Integer> list) {
        float temp = 0;
        for(float a : list)
            temp += (a-mean)*(a-mean);
        return temp/(list.size() - 1);
    }


    private float getMedian(List<Integer> list) {
        if (list.size() % 2 == 0)
            return (float) ((list.get((list.size() / 2) - 1) + list.get(list.size() / 2)) / 2.0);
        return list.get(list.size() / 2);
    }
}
