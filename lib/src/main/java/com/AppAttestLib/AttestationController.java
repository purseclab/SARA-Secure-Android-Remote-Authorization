package com.AppAttestLib;
import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.security.ConfirmationCallback;
import android.security.ConfirmationPrompt;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;

import com.AppAttestLib.BioConfirmMain;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

public class AttestationController {


    protected KeyPair ConfirmKP;
    protected KeyPair BioKP;


    public String registerBioConfirm(Context mainContext, String initParams){
        try {
            KeyGenParameterSpec.Builder KGPS = new KeyGenParameterSpec.Builder(mainContext.getString(mainContext.getApplicationInfo().labelRes)+"confFun", KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY);
            KeyGenParameterSpec.Builder BioKGPS = new KeyGenParameterSpec.Builder(mainContext.getString(mainContext.getApplicationInfo().labelRes)+"bioFun", KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY);
            byte[] challenge = initParams.getBytes();
            KGPS.setAttestationChallenge(challenge);
            KGPS.setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512);
            if (mainContext.getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE) && Build.VERSION.SDK_INT >= 28) {
                KGPS.setIsStrongBoxBacked(true);
            };
            KeyguardManager KgM = (KeyguardManager) mainContext.getSystemService(Context.KEYGUARD_SERVICE);
            if (KgM.isDeviceSecure()) {
                KGPS.setUserAuthenticationRequired(true);
            }
            if (Build.VERSION.SDK_INT >= 28) {
                KGPS.setUserConfirmationRequired(true);
            }
            KGPS.setUserAuthenticationValidityDurationSeconds(300);
            if (Build.VERSION.SDK_INT >= 28) {
                KGPS.setUnlockedDeviceRequired(true);
            }
            KGPS.setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS);
            KeyGenParameterSpec kgps = KGPS.build();
            KeyPairGenerator KPG = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
            KPG.initialize(kgps);
            ConfirmKP = KPG.generateKeyPair();
            BioKGPS.setAttestationChallenge(challenge);
            BioKGPS.setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512);
            if (mainContext.getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE) && Build.VERSION.SDK_INT >= 28) {
                BioKGPS.setIsStrongBoxBacked(true);
            }
            BioKGPS.setUserAuthenticationRequired(true);
            BioKGPS.setUserAuthenticationValidityDurationSeconds(-1);
            if (Build.VERSION.SDK_INT >= 28) {
                BioKGPS.setUnlockedDeviceRequired(true);
            }
            BioKGPS.setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS);
            KeyGenParameterSpec biokgps = BioKGPS.build();
            KeyPairGenerator BioKPG = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
            BioKPG.initialize(biokgps);
            BioKP = BioKPG.generateKeyPair();
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            Certificate[] cc = ks.getCertificateChain(mainContext.getString(mainContext.getApplicationInfo().labelRes)+"confFun");
            int length = cc.length;
            StringBuilder ccString = new StringBuilder();
            for (int i=0;i<length;i++)
            {
                if(i>0)
                {
                    ccString.append("<==>");
                }
                X509Certificate xCert;
                xCert = (X509Certificate) cc[length-i-1];
                String cString;
                if(Build.VERSION.SDK_INT >= 26) {
                    cString = Base64.getEncoder().encodeToString(xCert.getEncoded());
                } else {
                    cString = android.util.Base64.encodeToString(xCert.getEncoded(),android.util.Base64.NO_WRAP);
                }
                ccString.append(cString);

            }
            ccString.append("<|==|>");
            cc = ks.getCertificateChain(mainContext.getString(mainContext.getApplicationInfo().labelRes)+"bioFun");
            length = cc.length;
            for (int i=0;i<length;i++)
            {
                if(i>0)
                {
                    ccString.append("<==>");
                }
                X509Certificate xCert;
                xCert = (X509Certificate) cc[length-i-1];
                String cString;
                if(Build.VERSION.SDK_INT >= 26) {
                    cString = Base64.getEncoder().encodeToString(xCert.getEncoded());
                } else {
                    cString = android.util.Base64.encodeToString(xCert.getEncoded(),android.util.Base64.NO_WRAP);
                }
                ccString.append(cString);

            }
            return ccString.toString();
        } catch (Exception e){
            e.printStackTrace();
            return "ERROR IN REGISTRATION";
        }
    }




}
