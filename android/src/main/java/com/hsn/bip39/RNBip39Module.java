
package com.hsn.bip39;

import android.util.Log;


import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.WritableArray;
import com.hsn.bip39.key.Chain;
import com.hsn.bip39.key.Key;

import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.MnemonicCode;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

public class RNBip39Module extends ReactContextBaseJavaModule {

    public static final String MNEMONIC_WORD_LIST_FILE = "english.txt";
    private final ReactApplicationContext reactContext;

    public RNBip39Module(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;
    }

    @Override
    public String getName() {
        return "RNBip39";
    }

    @ReactMethod
    public void GenAddressAndMnemonic(String chainName, Integer wordSize, Callback successCallback, Callback failCallback) {
        if (chainName == null || chainName.equals("") || !chainName.equals(Chain.HSN_MAIN.getChain())) {
            Log.w("GenAccount: ", "chainName is invalid");
            failCallback.invoke("GetWordList: " + "chainName is invalid");
            return;
        }
        if (wordSize == 12 || wordSize == 24) {
            byte[] entropy = Key.getEntropy(wordSize);
            WritableArray writableArray = Arguments.createArray();
            try {
                List<String> mnemonic = Key.getRandomMnemonic(new MnemonicCode(reactContext.getAssets().open(MNEMONIC_WORD_LIST_FILE), null), entropy);
                for (String str : mnemonic) {
                    writableArray.pushString(str);
                }
//                writableArray.pushArray(new MnemonicArray(Key.getRandomMnemonic(new MnemonicCode(reactContext.getAssets().open(MNEMONIC_WORD_LIST_FILE), null), entropy)));
                successCallback.invoke(Key.getDpAddressFromEntropy(chainName, entropy), writableArray);
//                successCallback.invoke(Key.getDpAddressFromEntropy(chainName, entropy));
            } catch (Exception e) {
                Log.w("GetWordList: ", e.getMessage());
                failCallback.invoke("GetWordList: " + e.getMessage());
            }
        } else {
            Log.w("GenAAM: ", "word size is invalid");
            failCallback.invoke("GenAAM: " + "word size is invalid");
        }
    }

    @ReactMethod
    public void GenAccount(ReadableArray mnemonicArray, String chainName, Integer path, Callback successCallback, Callback failCallback) {
        if (mnemonicArray == null || mnemonicArray.size() == 0) {
            Log.w("GenAccount: ", "mnemonic is null or size equal zero");
            failCallback.invoke("GetWordList: " + "mnemonic is null or size equal zero");
            return;
        }
        if (chainName == null || chainName.equals("") || !chainName.equals(Chain.HSN_MAIN.getChain())) {
            Log.w("GenAccount: ", "chainName is invalid");
            failCallback.invoke("GetWordList: " + "chainName is invalid");
            return;
        }
        if (path != 0) {
            Log.w("GenAccount: ", "current version path always equal zero");
            failCallback.invoke("GetWordList: " + "current version path always equal zero");
            return;
        }
        ArrayList<String> mnemonic = new ArrayList<>();
        for (int i = 0; i < mnemonicArray.size(); i++)
            mnemonic.add(mnemonicArray.getString(i));
        byte[] entropy = Key.toEntropy(mnemonic);
        if (entropy == null) {
            Log.w("GenAccount: ", "mnemonic is invalid");
            failCallback.invoke("GenAccount: " + "mnemonic is invalid");
            return;
        }
        DeterministicKey key = Key.getKeyWithPathfromEntropy(chainName, Key.byteArrayToHexString(entropy), path);
        successCallback.invoke(Key.getDpAddressFromEntropy(chainName, entropy), Key.byteArrayToHexString(key.getPubKey()));
    }

    @ReactMethod
    public void RestoreAccount(ReadableArray mnemonicArray, String chainName, Integer path, Callback successCallback, Callback failCallback) {
        if (mnemonicArray == null || mnemonicArray.size() == 0) {
            Log.w("RestoreAccount: ", "mnemonic is null or size equal zero");
            failCallback.invoke("RestoreAccount: " + "mnemonic is null or size equal zero");
            return;
        }
        if (chainName == null || chainName.equals("") || !chainName.equals(Chain.HSN_MAIN.getChain())) {
            Log.w("RestoreAccount: ", "chainName is invalid");
            failCallback.invoke("RestoreAccount: " + "chainName is invalid");
            return;
        }
        if (path != 0) {
            Log.w("RestoreAccount: ", "current version path always equal zero");
            failCallback.invoke("RestoreAccount: " + "current version path always equal zero");
            return;
        }
        ArrayList<String> mnemonic = new ArrayList<>();
        for (int i = 0; i < mnemonicArray.size(); i++)
            mnemonic.add(mnemonicArray.getString(i));
        byte[] entropy = Key.toEntropy(mnemonic);
        if (entropy == null) {
            Log.w("RestoreAccount: ", "mnemonic is invalid");
            failCallback.invoke("RestoreAccount: " + "mnemonic is invalid");
            return;
        }
        DeterministicKey key = Key.getKeyWithPathfromEntropy(chainName, Key.byteArrayToHexString(entropy), path);
        successCallback.invoke(Key.getDpAddressFromEntropy(chainName, entropy), Key.byteArrayToHexString(key.getPubKey()));
    }

    @ReactMethod
    public void Sign(ReadableArray mnemonicArray, String chainName, Integer path, String txJson, Callback successCallback, Callback failCallback) {
        if (mnemonicArray == null || mnemonicArray.size() == 0) {
            Log.w("Sign: ", "mnemonic is null or size equal to zero");
            failCallback.invoke("Sign: " + "mnemonic is null or size equal to zero");
            return;
        }
        if (chainName == null || chainName.equals("") || !chainName.equals(Chain.HSN_MAIN.getChain())) {
            Log.w("Sign: ", "chainName is invalid");
            failCallback.invoke("Sign: " + "chainName is invalid");
            return;
        }
        if (path != 0) {
            Log.w("Sign: ", "current version path always equal zero");
            failCallback.invoke("Sign: " + "current version path always equal zero");
            return;
        }
        if (txJson == null || txJson.equals("")) {
            Log.w("Sign: ", "txJson is null or equal to \"\"");
            failCallback.invoke("Sign: " + "txJson is null or equal to \"\"");
            return;
        }
        ArrayList<String> mnemonic = new ArrayList<>();
        for (int i = 0; i < mnemonicArray.size(); i++)
            mnemonic.add(mnemonicArray.getString(i));
        byte[] entropy = Key.toEntropy(mnemonic);
        if (entropy == null) {
            Log.w("RestoreAccount: ", "mnemonic is invalid");
            failCallback.invoke("RestoreAccount: " + "mnemonic is invalid");
            return;
        }
        DeterministicKey key = Key.getKeyWithPathfromEntropy(chainName, Key.byteArrayToHexString(entropy), path);
        String signedTxJson = Key.getSignature(key, txJson.getBytes(Charset.forName("UTF-8")));
        successCallback.invoke(signedTxJson);
    }

}