<%@ page import="java.net.*,java.io.*" contentType="text/plain; charset=UTF-8" %>
<%
  String url = System.getenv("APP_B_GATEWAY_URL");
  if (url == null || url.isEmpty()) {
      url = "http://127.0.0.1:8091/health";
  }
  try {
      HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
      c.setConnectTimeout(2000);
      c.setReadTimeout(2000);
      int code = c.getResponseCode();
      out.println("GATEWAY " + code);
  } catch (Exception e) {
      out.println("DENIED " + e.getClass().getSimpleName() + " " + e.getMessage());
  }
%>
