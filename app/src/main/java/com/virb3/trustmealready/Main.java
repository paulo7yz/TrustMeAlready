package com.virb3.trustmealready;

import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import static de.robv.android.xposed.XposedHelpers.*;

public class Main implements IXposedHookZygoteInit {

    private static final String SSL_CLASS_NAME = "com.android.org.conscrypt.TrustManagerImpl";
    private static final String SSL_METHOD_NAME = "checkTrustedRecursive";
    private static final Class<?> SSL_RETURN_TYPE = List.class;
    private static final Class<?> SSL_RETURN_PARAM_TYPE = X509Certificate.class;

    @Override
    public void initZygote(StartupParam startupParam) throws Throwable {
        XposedBridge.log("TrustMeAlready loading...");
        int hookedMethods = 0;

        // Hook original TrustManagerImpl
        hookedMethods += hookTrustManagerImpl();

        // Hook OkHttp CertificatePinner
        hookedMethods += hookOkHttpCertificatePinner();

        // Hook TrustKit
        hookedMethods += hookTrustKit();

        // Hook Flutter SSL pinning
        hookedMethods += hookFlutterSslPinning();

        // Hook WebView SSL errors
        hookedMethods += hookWebViewSslErrors();

        // Hook dynamic SSL verification methods
        hookedMethods += hookDynamicSslVerification();

        // Hook Network Security Config (Android 7+)
        hookedMethods += hookNetworkSecurityConfig();

        // Hook Appmattus Certificate Transparency (CT) implementations
        hookedMethods += hookAppmattusCertificateTransparency();

        // Hook raw custom-pinned requests
        hookedMethods += hookRawCustomPinnedRequests();

        XposedBridge.log(String.format(Locale.ENGLISH, "TrustMeAlready loaded! Hooked %d methods", hookedMethods));
    }

    private int hookTrustManagerImpl() {
        int hooked = 0;
        try {
            Class<?> clazz = findClass(SSL_CLASS_NAME, null);
            for (Method method : clazz.getDeclaredMethods()) {
                if (!checkSSLMethod(method)) {
                    continue;
                }

                List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                params.add(new XC_MethodReplacement() {
                    @Override
                    protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                        return new ArrayList<X509Certificate>();
                    }
                });

                XposedBridge.log("Hooking TrustManagerImpl method: " + method.toString());
                findAndHookMethod(SSL_CLASS_NAME, null, SSL_METHOD_NAME, params.toArray());
                hooked++;
            }
        } catch (Exception e) {
            XposedBridge.log("[-] Error hooking TrustManagerImpl: " + e);
        }
        return hooked;
    }

    private int hookOkHttpCertificatePinner() {
        int hooked = 0;
        try {
            Class<?> certPinnerClass = findClass("okhttp3.CertificatePinner", null);
            for (Method method : certPinnerClass.getDeclaredMethods()) {
                if (method.getName().equals("check")) {
                    List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                    params.add(new XC_MethodReplacement() {
                        @Override
                        protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                            XposedBridge.log("[+] Bypassing OkHttp CertificatePinner check");
                            return null; // Ignora a verificação
                        }
                    });
                    XposedBridge.log("Hooking OkHttp method: " + method.toString());
                    findAndHookMethod(certPinnerClass, "check", params.toArray());
                    hooked++;
                }
            }
        } catch (Exception e) {
            XposedBridge.log("[-] OkHttp CertificatePinner not found: " + e);
        }
        return hooked;
    }

    private int hookTrustKit() {
        int hooked = 0;
        try {
            Class<?> trustKitClass = findClass("com.datatheorem.android.trustkit.TrustKit", null);
            Method initialize = trustKitClass.getMethod("initializeWithNetworkSecurityConfiguration", android.content.Context.class);
            XposedBridge.hookMethod(initialize, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    XposedBridge.log("[+] Bypassing TrustKit initialization");
                    param.setResult(null);
                }
            });
            hooked++;
        } catch (Exception e) {
            XposedBridge.log("[-] TrustKit not found: " + e);
        }
        return hooked;
    }

    private int hookFlutterSslPinning() {
        int hooked = 0;
        try {
            Class<?> flutterClass = findClass("io.flutter.plugin.common.MethodChannel$IncomingMethodCallHandler", null);
            XposedBridge.hookAllMethods(flutterClass, "onMethodCall", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    String method = (String) param.args[0];
                    if (method.equals("check")) {
                        XposedBridge.log("[+] Bypassing Flutter SSL pinning check");
                        param.setResult(true);
                    }
                }
            });
            hooked++;
        } catch (Exception e) {
            XposedBridge.log("[-] Flutter SSL pinning not found: " + e);
        }
        return hooked;
    }

    private int hookWebViewSslErrors() {
        int hooked = 0;
        try {
            Class<?> webViewClient = findClass("android.webkit.WebViewClient", null);
            Method onReceivedSslError = webViewClient.getMethod("onReceivedSslError", android.webkit.WebView.class, android.webkit.SslErrorHandler.class, android.net.http.SslError.class);
            XposedBridge.hookMethod(onReceivedSslError, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    XposedBridge.log("[+] Bypassing WebView SSL error");
                    Object handler = param.args[1]; // SslErrorHandler
                    handler.getClass().getMethod("proceed").invoke(handler);
                    param.setResult(null);
                }
            });
            XposedBridge.log("Hooking WebView method: " + onReceivedSslError.toString());
            hooked++;
        } catch (Exception e) {
            XposedBridge.log("[-] WebViewClient onReceivedSslError not found: " + e);
        }
        return hooked;
    }

    private int hookDynamicSslVerification() {
        int hooked = 0;
        try {
            Class<?> exceptionClass = findClass("javax.net.ssl.SSLPeerUnverifiedException", null);
            hookAllConstructors(exceptionClass, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Throwable ex = (Throwable) param.thisObject;
                    StackTraceElement[] stack = ex.getStackTrace();
                    if (stack.length > 1) {
                        String className = stack[1].getClassName();
                        String methodName = stack[1].getMethodName();
                        XposedBridge.log("[!] SSLPeerUnverifiedException from: " + className + "." + methodName);
                        try {
                            Class<?> clazz = findClass(className, null);
                            for (Method m : clazz.getDeclaredMethods()) {
                                if (m.getName().equals(methodName)) {
                                    XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(null));
                                    XposedBridge.log("[+] Dynamically hooked: " + className + "." + methodName);
                                }
                            }
                        } catch (Exception e) {
                            XposedBridge.log("[-] Failed to hook dynamically: " + e);
                        }
                    }
                }
            });
            hooked++;
        } catch (Exception e) {
            XposedBridge.log("[-] SSLPeerUnverifiedException hook failed: " + e);
        }
        return hooked;
    }

    private int hookNetworkSecurityConfig() {
        int hooked = 0;
        try {
            Class<?> trustManagerImpl = findClass("com.android.org.conscrypt.TrustManagerImpl", null);
            Method verifyChain = trustManagerImpl.getMethod("verifyChain", List.class, List.class, String.class, boolean.class, byte[].class, byte[].class);
            XposedBridge.hookMethod(verifyChain, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    XposedBridge.log("[+] Bypassing Network Security Config");
                    param.setResult(param.args[0]); // Retorna a cadeia não verificada
                }
            });
            hooked++;
        } catch (Exception e) {
            XposedBridge.log("[-] Network Security Config hook failed: " + e);
        }
        return hooked;
    }

    private int hookAppmattusCertificateTransparency() {
        int hooked = 0;
        try {
            // Hook Appmattus CT TrustManager
            Class<?> ctTrustManager = findClass("com.appmattus.certificatetransparency.TrustManager", null);
            if (ctTrustManager != null) {
                XposedBridge.hookAllMethods(ctTrustManager, "checkServerTrusted", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        XposedBridge.log("[+] Bypassing Appmattus CT TrustManager checkServerTrusted");
                        param.setResult(null); // Ignora verificação de CT
                    }
                });
                hooked++;
            }

            // Hook Appmattus CT Interceptor (OkHttp)
            Class<?> ctInterceptor = findClass("com.appmattus.certificatetransparency.CTInterceptor", null);
            if (ctInterceptor != null) {
                XposedBridge.hookAllMethods(ctInterceptor, "intercept", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        XposedBridge.log("[+] Bypassing Appmattus CTInterceptor for OkHttp");
                        param.setResult(param.args[0]); // Retorna a resposta sem verificar CT
                    }
                });
                hooked++;
            }

            // Hook Appmattus CT for WebView (shouldInterceptRequest)
            Class<?> webView = findClass("android.webkit.WebView", null);
            if (webView != null) {
                Class<?> webViewClient = findClass("android.webkit.WebViewClient", null);
                XposedBridge.hookAllMethods(webViewClient, "shouldInterceptRequest", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        XposedBridge.log("[+] Bypassing Appmattus CT in WebView shouldInterceptRequest");
                        param.setResult(null); // Ignora verificação de CT
                    }
                });
                hooked++;
            }

            // Hook Appmattus CT Java Security Provider
            Class<?> ctProvider = findClass("com.appmattus.certificatetransparency.CTProvider", null);
            if (ctProvider != null) {
                XposedBridge.hookAllMethods(ctProvider, "installCertificateTransparencyProvider", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        XposedBridge.log("[+] Bypassing Appmattus CT Java Security Provider installation");
                        param.setResult(null); // Impede a instalação do provedor
                    }
                });
                hooked++;
            }

        } catch (Exception e) {
            XposedBridge.log("[-] Error hooking Appmattus Certificate Transparency: " + e);
        }
        return hooked;
    }

    private int hookRawCustomPinnedRequests() {
        int hooked = 0;
        try {
            // Hook generic X509TrustManager for custom pinning
            Class<?> x509TrustManager = findClass("javax.net.ssl.X509TrustManager", null);
            XposedBridge.hookAllMethods(x509TrustManager, "checkServerTrusted", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    XposedBridge.log("[+] Bypassing generic X509TrustManager checkServerTrusted for custom pinning");
                    param.setResult(null); // Ignora verificação
                }
            });
            hooked++;

            // Hook SSLContext initialization to bypass custom TrustManagers
            Class<?> sslContext = findClass("javax.net.ssl.SSLContext", null);
            XposedBridge.hookAllMethods(sslContext, "init", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    XposedBridge.log("[+] Bypassing SSLContext init for custom TrustManagers");
                    param.args[1] = null; // Define TrustManagers como nulo
                }
            });
            hooked++;

        } catch (Exception e) {
            XposedBridge.log("[-] Error hooking raw custom-pinned requests: " + e);
        }
        return hooked;
    }

    private boolean checkSSLMethod(Method method) {
        if (!method.getName().equals(SSL_METHOD_NAME)) {
            return false;
        }
        if (!SSL_RETURN_TYPE.isAssignableFrom(method.getReturnType())) {
            return false;
        }
        Type returnType = method.getGenericReturnType();
        if (!(returnType instanceof ParameterizedType)) {
            return false;
        }
        Type[] args = ((ParameterizedType) returnType).getActualTypeArguments();
        return args.length == 1 && args[0].equals(SSL_RETURN_PARAM_TYPE);
    }
                        }
