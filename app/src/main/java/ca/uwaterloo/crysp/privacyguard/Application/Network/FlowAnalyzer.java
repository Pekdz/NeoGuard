package ca.uwaterloo.crysp.privacyguard.Application.Network;

import java.util.List;

import org.ejml.simple.SimpleMatrix;

public class FlowAnalyzer {
    private static int D = 10;  // hidden unit count
    private static int M = 15;  // feature and bias count
    private static double[][] meanTmp = {{0, 15445394.2831, 9.71666009084, 10.867425135, 547.382239223, 17297.9665632, 932.70809605, 41.1206915745, 215.178012943, 18.8895722149,
                                          128, 1017.11313299, 181.752887768, 316.252957767, 534072.612594}};
    private static double[][] subTmp = {{1, 119988082, 8670, 2651, 12490948.0, 3762632.0, 1460.0, 1418.0, 1460.0, 1460.0, 1, 1460, 1260.56085106,
            799.674933958, 639480.0}};

    private static double[][] alphaTmp = new double[][]
            {{-3.532, -0.008, -0.290, 0.734, 0.073, -0.837, -8.222, -11.090, -2.860, -3.078, -5.162, -8.716, -7.069, -11.586, 0.751},
                    {7.634, 22.031, 0.377, 0.940, -0.677, -0.539, 8.345, -1.813, 0.492, 1.897, -5.853, 3.876, 1.821, 4.007, 2.270},
                    {3.322, 26.627, 0.728, -0.198, -0.323, -0.725, 10.570, 0.018, 6.127, 4.154, -3.309, 6.066, 4.170, 5.767, -0.064},
                    {-1.876, 1.418, 0.168, -0.287, -0.508, 0.491, -1.656, 2.308, 0.647, 1.371, 4.211, -0.977, -0.623, -1.058, -1.893},
                    {-1.451, 12.517, 0.146, -0.760, 0.095, 0.648, -2.281, 0.715, 4.973, -0.967, 5.287, 5.078, 4.225, 1.427, -3.594},
                    {5.626, 7.458, 0.670, -0.632, 0.541, -0.238, 5.298, -1.990, 1.604, 0.132, -4.095, 2.084, 0.242, 1.412, 1.388},
                    {-2.481, 0.104, 0.390, -0.468, -0.317, -0.770, -0.297, 0.067, 0.536, -0.428, 0.793, -0.595, 1.223, -0.742, 0.858},
                    {5.555, 10.148, -0.167, 0.531, -1.242, 0.346, -7.027, 14.467, -0.134, 8.412, 15.884, 1.816, 13.110, 8.348, -2.420},
                    {1.332, -0.229, -0.312, 1.473, -0.991, 1.064, -2.837, 13.223, 19.965, 9.458, 17.927, 10.899, 4.343, -10.739, -10.702},
                    {0.804, 9.015, 0.232, 0.021, 0.202, -0.070, -2.749, 9.547, -0.894, -0.556, 8.434, 2.372, 5.931, 3.446, -2.220}};
    private static double[][] betaTmp = new double[][]
            {{-0.512, -3.628, -7.004, -7.587, 0.242, 2.463, -4.822, 0.190, 6.506, 15.270, 1.314},
                    {0.512, 4.499, 6.723, 8.437, 0.096, -2.798, 4.007, 0.509, -7.164, -15.491, -1.744}};

    private static SimpleMatrix alpha = new SimpleMatrix(alphaTmp);
    private static SimpleMatrix beta = new SimpleMatrix(betaTmp);
    private static SimpleMatrix mean = new SimpleMatrix(meanTmp);
    private static SimpleMatrix sub = new SimpleMatrix(subTmp);
    private static FlowAnalyzer instance;

    private FlowAnalyzer() {
    }

    public static FlowAnalyzer getInstance() {
        if (instance == null) {
            instance = new FlowAnalyzer();
        }
        return instance;
    }

    private static SimpleMatrix sigmoid(SimpleMatrix values) {
        for (int i = 0; i < values.numRows() * values.numCols(); i++) {
            values.set(i, 1 / (1 + Math.exp(-values.get(i))));
        }
        return values;
    }

    private static SimpleMatrix getA(SimpleMatrix X) {
        return alpha.mult(X.transpose());
    }

    private static SimpleMatrix getB(SimpleMatrix Z, int K) {
        SimpleMatrix tmp = new SimpleMatrix(D + 1, 1);
        tmp.set(0, 1);
        for (int i = 1; i < D + 1; i++) {
            tmp.set(i, Z.get(i - 1));
        }
        return beta.mult(tmp);
    }

    private static SimpleMatrix Normalize(SimpleMatrix values) {
        for (int i = 0; i < values.numRows() * values.numCols(); i++) {
            values.set(i, (values.get(i) - mean.get(i)) / sub.get(i));
        }
        return values;
    }

    // The API used with adding bias and transferred to matrix
    private static int MakeSingleTag(SimpleMatrix X) {
        SimpleMatrix n_X = Normalize(X);
        SimpleMatrix A = getA(n_X);
        SimpleMatrix Z = sigmoid(A);
        SimpleMatrix B = getB(Z, 2);
        if (B.get(0) > B.get(1)) {
            return 0;
        }
        return 1;
    }
	
	/* The API used without adding bias(Input is the raw network flow)
	 * Input order =>
	  'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
	  'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
	  'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Fwd Packet Length Max',
	  'Fwd Packet Length Min', 'Min Packet Length', 'Max Packet Length',
	  'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance'
	 */

    public boolean isBadFlow(List<Double> X) {
        try {
            double[][] matrixX = new double[1][X.size() + 1];
            matrixX[0][0] = 1.0;
            for (int i = 1; i < X.size() + 1; i++) {
                matrixX[0][i] = X.get(i - 1);
            }
            SimpleMatrix n_X = Normalize(new SimpleMatrix(matrixX));
            SimpleMatrix A = getA(n_X);
            SimpleMatrix Z = sigmoid(A);
            SimpleMatrix B = getB(Z, 2);
            return B.get(0) <= B.get(1);
        } catch(Exception e) {
            return true;
        }

    }

    /*public static void main(String[] args) {

        // normal flow test
//    	double[] X = new double[] {564975.0, 12.0, 11.0, 1193.0, 4650.0, 1418.0, 0.0, 916.0, 
//    			                   0.0, 0.0, 1418.0, 243.45833333333337, 440.2825159378688, 
//    			                   193848.69384057968};

        // malicious flow test
        double[] X = new double[]{40.0, 2.0, 0.0, 42.0, 0.0, 0.0, 0.0, 42.0, 0.0, 0.0,
                42.0, 28.0, 24.248711305964278, 588.0};

        ArrayList<Double> input = new ArrayList<Double>();
        for (double i : X) {
            input.add(i);
        }
        int tag = FlowAnalyzer.isBadFlow(input);
        if (tag == 0) {
            System.out.println("normal flow");
        } else {
            System.out.println("malicious flow");
        }
    }*/
}
