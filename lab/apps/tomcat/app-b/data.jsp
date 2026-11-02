<%@ page import="java.io.*" contentType="text/plain; charset=UTF-8" %>
<%
  // secret.dat sits in the inherited docBase (/opt/appdata) with a wrong label.
  File f = new File(application.getRealPath("/secret.dat"));
  if (f == null) {
      f = new File("/opt/appdata/secret.dat");
  }
  try (FileInputStream in = new FileInputStream(f)) {
      byte[] buf = new byte[64];
      int n = in.read(buf);
      out.println("READ " + n);
  } catch (Exception e) {
      out.println("DENIED " + e.getClass().getSimpleName() + " " + e.getMessage());
  }
%>
