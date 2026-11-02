<%@ page import="java.io.*" contentType="text/plain; charset=UTF-8" %>
<%
  // World-readable file *outside* the content root, labeled so DAC succeeds and
  // SELinux must deny. Do not use /etc/shadow — mode 000 fails DAC first, so
  // there is no AVC for a sceptic to see.
  String path = System.getenv("APP_A_FORBIDDEN_PATH");
  if (path == null || path.isEmpty()) {
      path = "/var/lib/selinux-pac-demo/out-of-scope.txt";
  }
  File f = new File(path);
  try (FileInputStream in = new FileInputStream(f)) {
      out.println("UNEXPECTED_READ " + f);
  } catch (Exception e) {
      out.println("DENIED " + e.getClass().getSimpleName() + " " + e.getMessage());
  }
%>
