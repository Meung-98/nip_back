package newszip.nip.service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import lombok.extern.slf4j.Slf4j;
import newszip.nip.dto.GeminiApiResponse;
import newszip.nip.dto.GeminiSummaryRequest;
import newszip.nip.dto.GeminiSummaryResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;

@Service
@Slf4j
public class GeminiSummaryService {

    private static final int MAX_PROMPT_TEXT_LENGTH = 4000;
    private static final String DEFAULT_MODEL = "gemini-1.5-flash"; // v1에서 지원되는 모델명

    @Value("${GEMINI_API_KEY:}")
    private String apiKey;

    @Value("${GEMINI_MODEL:" + DEFAULT_MODEL + "}")
    private String geminiModel;

    private final RestTemplate restTemplate = new RestTemplate();

    public GeminiSummaryResponse summarize(GeminiSummaryRequest request) {
        if (apiKey == null || apiKey.isBlank()) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Gemini API 키가 설정되지 않았습니다.");
        }

        String prompt = buildPrompt(request);
        String summaryText = callGemini(prompt);

        return GeminiSummaryResponse.builder()
                .summary(summaryText)
                .build();
    }

    private String buildPrompt(GeminiSummaryRequest request) {
        StringBuilder sb = new StringBuilder();
        sb.append("다음 뉴스 기사를 한국어로 2~3문장으로 요약해줘. ")
                .append("불릿 없이 자연스러운 문장으로 작성하고, 사실 위주로 정리해줘. ")
                .append("과도한 추측이나 의견은 넣지 말아줘.\n");

        if (request.getTitle() != null && !request.getTitle().isBlank()) {
            sb.append("제목: ").append(request.getTitle().trim()).append("\n");
        }
        if (request.getDescription() != null && !request.getDescription().isBlank()) {
            sb.append("설명: ").append(request.getDescription().trim()).append("\n");
        }
        if (request.getUrl() != null && !request.getUrl().isBlank()) {
            sb.append("기사 URL: ").append(request.getUrl()).append("\n");
        }
        sb.append("위 정보로 2~3문장 한국어 요약을 작성해줘.");

        return sb.toString();
    }

    private String callGemini(String prompt) {
        String model = (geminiModel == null || geminiModel.isBlank()) ? DEFAULT_MODEL : geminiModel.trim();
        try {
            // 1차: v1beta
            return callGeminiWithEndpoint(prompt, model, "v1beta");
        } catch (RestClientResponseException ex) {
            // 404 시 v1으로 재시도
            if (ex.getStatusCode() == HttpStatus.NOT_FOUND) {
                try {
                    log.warn("Gemini 모델 404(v1beta) 발생, v1로 재시도: {}", model);
                    return callGeminiWithEndpoint(prompt, model, "v1");
                } catch (RestClientResponseException inner) {
                    log.error("Gemini API 오류(v1 재시도): status={}, body={}", inner.getStatusCode(), inner.getResponseBodyAsString());
                    throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Gemini 요약 요청이 실패했습니다.", inner);
                }
            }
            log.error("Gemini API 오류: status={}, body={}", ex.getStatusCode(), ex.getResponseBodyAsString());
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Gemini 요약 요청이 실패했습니다.", ex);
        } catch (Exception ex) {
            log.error("Gemini 요약 요청 중 예외 발생", ex);
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Gemini 요약 요청 중 오류가 발생했습니다.", ex);
        }
    }

    // 엔드포인트(v1beta/v1) 선택 호출
    private String callGeminiWithEndpoint(String prompt, String model, String apiVersion) {
        String url = "https://generativelanguage.googleapis.com/" + apiVersion + "/models/" + model + ":generateContent?key=" + apiKey;
        Map<String, Object> body = new HashMap<>();
        body.put("contents", List.of(Map.of("parts", List.of(Map.of("text", prompt)))));

        try {
            ResponseEntity<GeminiApiResponse> response = restTemplate.postForEntity(url, body, GeminiApiResponse.class);
            GeminiApiResponse apiResponse = response.getBody();

            if (apiResponse == null || apiResponse.getCandidates() == null || apiResponse.getCandidates().isEmpty()) {
                throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Gemini 응답이 비어 있습니다.");
            }

            String text = apiResponse.getCandidates().stream()
                    .filter(candidate -> candidate.getContent() != null && candidate.getContent().getParts() != null)
                    .findFirst()
                    .flatMap(candidate -> candidate.getContent().getParts().stream()
                            .map(GeminiApiResponse.Part::getText)
                            .filter(t -> t != null && !t.isBlank())
                            .findFirst())
                    .orElse("");

            if (text.isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Gemini 요약 결과를 찾을 수 없습니다.");
            }

            return text.trim();
        } catch (RestClientResponseException ex) {
            log.error("Gemini API 오류({}): status={}, body={}", apiVersion, ex.getStatusCode(), ex.getResponseBodyAsString());
            throw ex;
        } catch (Exception ex) {
            log.error("Gemini 요약 요청 중 예외 발생({})", apiVersion, ex);
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Gemini 요약 요청 중 오류가 발생했습니다.", ex);
        }
    }
}

