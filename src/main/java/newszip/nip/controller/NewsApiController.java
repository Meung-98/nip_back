package newszip.nip.controller;


import com.fasterxml.jackson.databind.ObjectMapper;
import newszip.nip.dto.NewsResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/news")
public class NewsApiController {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${NAVER_CLIENT_ID:}")
    private String clientId;

    @Value("${NAVER_CLIENT_SECRET:}")
    private String clientSecret;

    // 카테고리별 뉴스 조회
    @GetMapping
    public ResponseEntity<NewsResponse> getNewsByCategory(
            @RequestParam(required = false, defaultValue = "8") Integer display,
            @RequestParam String category
    ) {
        if (clientId == null || clientId.isEmpty() || clientSecret == null || clientSecret.isEmpty()) {
            throw new RuntimeException("네이버 클라이언트 ID 또는 시크릿이 설정되지 않았습니다.");
        }

        String searchKeyword = category;   // 카테고리명을 검색어로 사용
        if (searchKeyword == null || searchKeyword.isEmpty()) {
            throw new RuntimeException("카테고리가 비어 있습니다.");
        }

        String encodeQuery;
        try {
            encodeQuery = URLEncoder.encode(searchKeyword, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("검색어 인코딩 실패", e);
        }

        // display는 최대 100까지 가능
        int displayCount = Math.min(Math.max(display, 1), 100);
        String apiURL = "https://openapi.naver.com/v1/search/news?query=" + encodeQuery + "&display=" + displayCount + "&sort=date";

        Map<String, String> requestHeaders = new HashMap<>();
        requestHeaders.put("X-Naver-Client-Id", clientId);
        requestHeaders.put("X-Naver-Client-Secret", clientSecret);

        try {
            String responseBody = get(apiURL, requestHeaders);
            NewsResponse newsResponse = objectMapper.readValue(responseBody, NewsResponse.class);

            // 네이버 API 에러 응답 확인
            if (newsResponse.getErrorMessage() != null && !newsResponse.getErrorMessage().isEmpty()) {
                String errorMsg = newsResponse.getErrorMessage();
                // 인증 오류인 경우 더 친절한 메시지 제공
                if (errorMsg.contains("Authentication failed") || errorMsg.contains("Scopes are Empty")) {
                    throw new RuntimeException("네이버 뉴스 검색 API가 활성화되지 않았습니다. 네이버 개발자 센터에서 '검색' API 서비스를 활성화해주세요.");
                }
                throw new RuntimeException("네이버 뉴스 API 오류: " + errorMsg);
            }

            // 응답이 비어있거나 items가 null인 경우
            if (newsResponse.getItems() == null || newsResponse.getItems().isEmpty()) {
                // 빈 응답인 경우 빈 리스트 반환 (에러가 아님)
                return ResponseEntity.ok(newsResponse);
            }

            return ResponseEntity.ok(newsResponse);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("뉴스 조회 실패: " + e.getMessage(), e);
        }
    }

    private static String get(String apiUrl, Map<String, String> requestHeaders){
        HttpURLConnection con = connect(apiUrl);
        try {
            con.setRequestMethod("GET");
            for(Map.Entry<String, String> header :requestHeaders.entrySet()) {
                con.setRequestProperty(header.getKey(), header.getValue());
            }
            int responseCode = con.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) { // 정상 호출
                return readBody(con.getInputStream());
            } else { // 오류 발생
                return readBody(con.getErrorStream());
            }
        } catch (IOException e) {
            throw new RuntimeException("API 요청과 응답 실패", e);
        } finally {
            con.disconnect();
        }
    }

    private static HttpURLConnection connect(String apiUrl){
        try {
            URL url = new URL(apiUrl);
            return (HttpURLConnection)url.openConnection();
        } catch (MalformedURLException e) {
            throw new RuntimeException("API URL이 잘못되었습니다. : " + apiUrl, e);
        } catch (IOException e) {
            throw new RuntimeException("연결이 실패했습니다. : " + apiUrl, e);
        }
    }

    private static String readBody(InputStream body){
        InputStreamReader streamReader = new InputStreamReader(body);
        try (BufferedReader lineReader = new BufferedReader(streamReader)) {
            StringBuilder responseBody = new StringBuilder();
            String line;
            while ((line = lineReader.readLine()) != null) {
                responseBody.append(line);
            }
            return responseBody.toString();
        } catch (IOException e) {
            throw new RuntimeException("API 응답을 읽는 데 실패했습니다.", e);
        }
    }
}