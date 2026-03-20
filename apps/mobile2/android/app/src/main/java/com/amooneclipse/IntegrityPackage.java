package com.amooneclipse;

import androidx.annotation.NonNull;

import com.facebook.react.ReactPackage;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.uimanager.ViewManager;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * IntegrityPackage
 *
 * Standard {@link ReactPackage} registration for {@link IntegrityModule}.
 *
 * Register this package in your MainApplication.java / MainApplication.kt:
 *
 * <pre>
 *   // Java
 *   @Override
 *   protected List<ReactPackage> getPackages() {
 *       List<ReactPackage> packages = new PackageList(this).getPackages();
 *       packages.add(new IntegrityPackage());
 *       return packages;
 *   }
 *
 *   // Kotlin
 *   override fun getPackages(): List<ReactPackage> =
 *       PackageList(this).packages.apply {
 *           add(IntegrityPackage())
 *       }
 * </pre>
 */
public class IntegrityPackage implements ReactPackage {

    /**
     * Creates the list of native modules to register with the React Native
     * bridge.  We only expose {@link IntegrityModule}.
     */
    @NonNull
    @Override
    public List<NativeModule> createNativeModules(@NonNull ReactApplicationContext reactContext) {
        List<NativeModule> modules = new ArrayList<>();
        modules.add(new IntegrityModule(reactContext));
        return modules;
    }

    /**
     * No custom view managers are provided by this package.
     */
    @NonNull
    @Override
    public List<ViewManager> createViewManagers(@NonNull ReactApplicationContext reactContext) {
        return Collections.emptyList();
    }
}
