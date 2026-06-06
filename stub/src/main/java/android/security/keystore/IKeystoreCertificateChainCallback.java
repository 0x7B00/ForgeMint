package android.security.keystore;

import android.os.IBinder;

public interface IKeystoreCertificateChainCallback {
    abstract class Stub extends android.os.Binder implements IKeystoreCertificateChainCallback {
        public static IKeystoreCertificateChainCallback asInterface(IBinder binder) {
            return null;
        }
    }
}
