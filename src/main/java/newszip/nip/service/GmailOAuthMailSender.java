package newszip.nip.service;

import jakarta.mail.Authenticator;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

// Gmail SMTP + OAuth2 (XOAUTH2)로 HTML 메일 전송
@Component
public class GmailOAuthMailSender {

    private static final Logger log = LoggerFactory.getLogger(GmailOAuthMailSender.class);

    @Value("${gmail.smtp.username:}")
    private String username; // Gmail 주소

    @Value("${mail.from:no-reply@newszip.app}")
    private String from;

    @Value("${gmail.smtp.host:smtp.gmail.com}")
    private String host;

    @Value("${gmail.smtp.port:587}")
    private int port;

    private final GmailOAuthTokenProvider tokenProvider;

    public GmailOAuthMailSender(GmailOAuthTokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    public void send(String to, String subject, String htmlBody) {
        if (username == null || username.isBlank()) {
            throw new IllegalStateException("gmail.smtp.username 설정이 필요합니다.");
        }
        String accessToken = tokenProvider.getAccessToken();
        try {
            Properties props = new Properties();
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.host", host);
            props.put("mail.smtp.port", String.valueOf(port));
            props.put("mail.smtp.auth.mechanisms", "XOAUTH2");

            Session session = Session.getInstance(props, new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(username, accessToken);
                }
            });

            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress(from));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to));
            message.setSubject(subject, StandardCharsets.UTF_8.name());
            message.setContent(htmlBody, "text/html; charset=UTF-8");

            Transport transport = session.getTransport("smtp");
            transport.connect(host, port, username, accessToken);
            transport.sendMessage(message, message.getAllRecipients());
            transport.close();
        } catch (MessagingException e) {
            log.error("이메일 전송 실패: {}", e.getMessage(), e);
            throw new IllegalStateException("이메일 전송에 실패했습니다.", e);
        }
    }
}
