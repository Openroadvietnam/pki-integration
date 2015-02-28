<%@page import="java.sql.ResultSet"%>
<%@page import="java.sql.PreparedStatement"%>
<%@page import="java.sql.Connection"%>
<%@page import="org.apache.commons.codec.binary.Hex"%>
<%@page import="java.io.InputStream"%>
<%@page import="javax.crypto.Cipher"%>
<%@page import="java.security.cert.X509Certificate"%>
<%@page import="java.security.cert.CertificateFactory"%>
<%@page import="java.io.ByteArrayInputStream"%>
<%@page import="sun.misc.BASE64Decoder"%>
<%@page import="java.util.Random"%>
<%@page import="com.google.gson.JsonObject"%>
<%@page import="com.google.gson.Gson"%>
<%@page import="org.springframework.jdbc.core.simple.SimpleJdbcTemplate"%>
<%@page import="org.support.ApplicationContextProvider"%>
<%@page import="org.apache.commons.dbcp.BasicDataSource"%>
<%@page import="org.springframework.context.ApplicationContext"%>
<%!
public String generateRandomString(int length) {
	String tmp = "";
	Random random = new Random();
	for (int i=0; i<length; i++){
		int loai = (int)(random.nextFloat()*3);
		switch (loai) {
		case 0:
			tmp += (char)('0'+(int)(random.nextFloat()*9));
			break;
		case 1:
			tmp += (char)('a'+(int)(random.nextFloat()*26));
			break;
		case 2:
			tmp += (char)('A'+(int)(random.nextFloat()*26));
			break;	
		default:
			break;
		}
	}
	return tmp;
}
public static String encrypt(String text, String certificate) {
	 try {
		
		byte b[] = new BASE64Decoder().decodeBuffer(certificate);
		InputStream _in = new ByteArrayInputStream(b);
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		X509Certificate cert = (X509Certificate) certFactory.generateCertificate(_in);
		
		Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, cert.getPublicKey());
		byte[] original = text.getBytes();
		byte[] cipherData = cipher.doFinal(original);
		return Hex.encodeHexString(cipherData);
       }
       catch (Exception e) {
           System.out.println(e.toString());
       }
	 return "";
 }
%>
<%
	response.setContentType("application/json");
	JsonObject jsonObject = new JsonObject();

	ApplicationContext context = new ApplicationContextProvider().getApplicationContext();
	BasicDataSource dataSource = context.getBean("dataSource",BasicDataSource.class);
	String base64Certificate = request.getParameter("base64Encode");
	Connection jdbc = dataSource.getConnection();

	/* String updateSQL = "UPDATE tbl_users SET certificate = ? WHERE username = 'trongdd'";
	PreparedStatement pre2Stt = jdbc.prepareStatement(updateSQL);
	pre2Stt.setString(1, base64Certificate);
	pre2Stt.execute(); */
	
	PreparedStatement preparedStt = jdbc.prepareStatement("SELECT username FROM tbl_users WHERE certificate = ?");
	preparedStt.setString(1, base64Certificate);
	ResultSet rs = preparedStt.executeQuery();
	if (rs.next()){
		String username = rs.getString("username");
		String challangeString = generateRandomString(256);
		jsonObject.addProperty("status", 1);
		jsonObject.addProperty("username", username);
		jsonObject.addProperty("challange", encrypt(challangeString, base64Certificate));
		rs.close();
		preparedStt.close();
		
		String updateSQL = "UPDATE tbl_users SET response_token = ? WHERE username = ?";
		PreparedStatement pre2Stt = jdbc.prepareStatement(updateSQL);
		pre2Stt.setString(1, challangeString);
		pre2Stt.setString(2, username);
		pre2Stt.execute();
		pre2Stt.close(); 
	} else {
		jsonObject.addProperty("status", -1);
	}
	jdbc.close();
	out.print(jsonObject.toString()); 
%>