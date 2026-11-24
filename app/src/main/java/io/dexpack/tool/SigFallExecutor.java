package io.dexpack.tool;

final class SigFallExecutor {
    interface Listener {
        void onApplied(SigFallConfig config);
        void onError(String message);
    }

    private SigFallExecutor() { }

    static void apply(ProtectionApp app, SigFallConfig config, Listener listener) {
        try {
            validate(config);
        } catch (Exception error) {
            listener.onError(message(error));
            return;
        }
        if (app.busy) {
            listener.onError("Wait for the current operation to finish.");
            return;
        }
        app.busy = true;
        app.processing = true;
        app.hasExecution = true;
        app.failed = false;
        app.saved = null;
        app.percent = 0;
        app.status = "Applying SigFall…";
        app.beginExecution("sigfall --mode " + modeName(config.mode) + " --version " + config.version);
        app.worker.execute(() -> {
            try {
                step(app, "basics-to-sign", String.valueOf(config.basicsToSign), 5, () -> applyBasicsToSign(config));
                step(app, "mode", modeName(config.mode), 12, () -> applyMode(config));
                step(app, "version", config.version, 20, () -> applyVersion(config));
                step(app, "file-redirection", config.fileRedirection, 28, () -> applyFileRedirection(config));
                step(app, "resource-redirection", String.valueOf(config.resourceRedirection), 36, () -> applyResourceRedirection(config));
                step(app, "apk-path", String.valueOf(config.replaceApkPath), 44, () -> applyApkPathReplacement(config));
                step(app, "app-class", String.valueOf(config.replaceAppClassName), 52, () -> applyAppClassNameReplacement(config));
                step(app, "java-hook-framework", String.valueOf(config.javaHookFramework), 60, () -> applyJavaHookFramework(config));
                step(app, "maps-hiding", String.valueOf(config.mapsHiding), 68, () -> applyMapsHiding(config));
                step(app, "dex-obfuscation", String.valueOf(config.dexObfuscation), 76, () -> applyDexObfuscation(config));
                step(app, "data-reuse", String.valueOf(config.dataReuseOptimization), 84, () -> applyDataReuseOptimization(config));
                step(app, "debuggable", String.valueOf(config.debuggable), 90, () -> applyDebuggable(config));
                step(app, "data-folder", config.dataFolderName, 95, () -> applyDataFolderName(config));
                step(app, "library-name", config.libraryName, 98, () -> applyDynamicLibraryName(config));
                app.step("done", 100);
                app.main.post(() -> {
                    app.busy = false;
                    app.processing = false;
                    app.percent = 100;
                    app.status = "SigFall configuration applied";
                    app.log("configuration saved");
                    app.notifyState();
                    listener.onApplied(config);
                });
            } catch (Exception error) {
                String text = message(error);
                app.main.post(() -> {
                    app.busy = false;
                    app.processing = false;
                    app.failed = true;
                    app.status = text;
                    app.logError(text);
                    app.notifyState();
                    listener.onError(text);
                });
            }
        });
    }

    private static void step(ProtectionApp app, String name, String detail, int progress, Runnable action) {
        app.step(name + "=" + detail, progress);
        action.run();
    }

    private static String modeName(int mode) {
        if (mode == SigFallConfig.MODE_STRENGTH) return "strength";
        if (mode == SigFallConfig.MODE_HIGH_STABILITY) return "high-stability";
        return "automatic";
    }

    private static void validate(SigFallConfig config) {
        if (config.dataFolderName == null || config.dataFolderName.trim().isEmpty()) {
            throw new IllegalArgumentException("Enter a custom data folder name.");
        }
        if (config.libraryName == null || config.libraryName.trim().isEmpty()) {
            throw new IllegalArgumentException("Enter a custom de-check library name.");
        }
        config.dataFolderName = config.dataFolderName.trim();
        config.libraryName = config.libraryName.trim();
    }

    private static void applyBasicsToSign(SigFallConfig config) {
        // Hook: apply the "The basics go to sign" option to the signing/protection pipeline.
    }

    private static void applyMode(SigFallConfig config) {
        // Hook: map automatic, Strength, and High stability modes to protection profiles.
    }

    private static void applyVersion(SigFallConfig config) {
        // Hook: select the requested SigFall version payload.
    }

    private static void applyFileRedirection(SigFallConfig config) {
        // Hook: configure file redirection using config.fileRedirection.
    }

    private static void applyResourceRedirection(SigFallConfig config) {
        // Hook: enable resource redirection when config.resourceRedirection is true.
    }

    private static void applyApkPathReplacement(SigFallConfig config) {
        // Hook: replace APK path lookups when config.replaceApkPath is true.
    }

    private static void applyAppClassNameReplacement(SigFallConfig config) {
        // Hook: replace the application class name when config.replaceAppClassName is true.
    }

    private static void applyJavaHookFramework(SigFallConfig config) {
        // Hook: install or enable the Java Hook framework when config.javaHookFramework is true.
    }

    private static void applyMapsHiding(SigFallConfig config) {
        // Hook: hide protected mappings when config.mapsHiding is true.
    }

    private static void applyDexObfuscation(SigFallConfig config) {
        // Hook: apply DEX obfuscation when config.dexObfuscation is true.
    }

    private static void applyDataReuseOptimization(SigFallConfig config) {
        // Hook: enable data reuse optimization when config.dataReuseOptimization is true.
    }

    private static void applyDebuggable(SigFallConfig config) {
        // Hook: preserve or force the debuggable flag when config.debuggable is true.
    }

    private static void applyDataFolderName(SigFallConfig config) {
        // Hook: use config.dataFolderName as the custom data folder.
    }

    private static void applyDynamicLibraryName(SigFallConfig config) {
        // Hook: use config.libraryName as the de-check dynamic library template.
    }

    private static String message(Throwable error) {
        return error.getMessage() == null || error.getMessage().isEmpty()
                ? error.getClass().getSimpleName()
                : error.getMessage();
    }
}
