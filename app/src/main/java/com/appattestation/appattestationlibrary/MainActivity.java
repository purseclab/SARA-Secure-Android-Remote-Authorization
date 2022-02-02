    package com.appattestation.appattestationlibrary;

import androidx.fragment.app.FragmentActivity;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

import com.AppAttestLib.AttestationController;
import com.AppAttestLib.BioConfirmMain;

import java.net.CookieHandler;
import java.net.CookieManager;

public class MainActivity extends FragmentActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        AttestationController myAC=new AttestationController();
        String certificateChainString = myAC.registerBioConfirm(this,"LGDTIR6TN4ZH1V4K");
        //certificateChainString to be sent to server

        Intent callAttestation = new Intent(this, BioConfirmMain.class);
        callAttestation.putExtra("authParams","QWERTPLEASE CONFIRM: Sending $500 to Bashir");
        this.startActivityForResult(callAttestation,2);
    }



    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (requestCode == 2) {
            if(resultCode == Activity.RESULT_OK){

                String signatures=data.getStringExtra("Signature");
                //signatures to be sent to server
            }
            
        }
    } 

}
