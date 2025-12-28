package newszip.nip.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

// Gmail OAuth SMTP를 사용해 HTML 인증메일 전송
@Service
public class EmailService {

    private final GmailOAuthMailSender gmailOAuthMailSender;

    @Value("${verification.email.subject:[NIP] 이메일 인증 코드}")
    private String subject;

    public EmailService(GmailOAuthMailSender gmailOAuthMailSender) {
        this.gmailOAuthMailSender = gmailOAuthMailSender;
    }

    public void sendVerificationCode(String to, String code, long ttlMinutes) {
        String html = buildHtml(code, ttlMinutes);
        gmailOAuthMailSender.send(to, subject, html);
    }

    private String buildHtml(String code, long ttlMinutes) {
        String logoUrl = "https://raw.githubusercontent.com/SEOMOONJEONG/korit_07_Nuzip_Front/main/src/pages/Nuzip_logo2.png";
        return """
                <div style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 30px;">
                  <div style="max-width: 600px; margin: 0 auto; background-color: #f8f9fa; border-radius: 8px; overflow: hidden;">
                    <div style="background-color: #E8F0FE; padding: 28px 20px; text-align: center;">
                      <img src="%s" alt="Nuzip Logo" style="height: 52px; width: auto; display: inline-block;">
                    </div>
                    <div style="padding: 40px 30px; color: #111111; text-align: center; background-color: #ffffff;">
                      <h2 style="margin-top: 10px; font-size: 22px; font-weight: bold;">확인 코드</h2>
                      <div style="color: #000000; padding: 18px 0; margin: 20px auto; width: 200px; font-size: 26px; font-weight: bold; border-radius: 8px; letter-spacing: 6px;">
                        %s
                      </div>
                      <p style="font-size: 13px; margin-top: -5px; opacity: 0.7; color: #868e96;">(이 코드는 전송 %d분 후에 만료됩니다.)</p>
                      <hr style="margin: 35px 0; border: 0; border-top: 1px solid #d0d4d8;" />
                      <p style="font-size: 14px; line-height: 1.6; text-align: left; color: #868e96;">
                        뉴스집은 절대 사용자의 인증코드, 신용카드 또는 은행 계좌 번호를 묻거나 확인하라는 이메일을 보내지 않습니다.
                        계정 정보를 업데이트하라는 링크가 포함된 의심스러운 이메일을 수신한 경우 링크를 클릭하지 말고 해당 이메일을 신고해 주세요.
                      </p>
                    </div>
                  </div>
                </div>
                """.formatted(logoUrl, code, ttlMinutes);
    }
}

