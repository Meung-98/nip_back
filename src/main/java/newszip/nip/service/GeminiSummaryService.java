package newszip.nip.service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
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

    private static final String DEFAULT_MODEL = "gemini-1.5-flash-latest"; // API 기본 권장 모델

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
        String configured = (geminiModel == null || geminiModel.isBlank()) ? DEFAULT_MODEL : geminiModel.trim();

        // 시도할 모델 후보 리스트 (중복 제거를 위해 LinkedHashSet 사용)
        LinkedHashSet<String> modelCandidates = new LinkedHashSet<>();
        modelCandidates.add(configured);
        if (configured.endsWith("-latest")) {
            modelCandidates.add(configured.replace("-latest", "")); // latest 실패 시 기본명으로
        } else {
            modelCandidates.add(configured + "-latest"); // latest 버전도 시도
        }
        modelCandidates.add("gemini-1.5-flash"); // 안정적인 기본 모델 추가

        List<String> apiVersions = List.of("v1beta", "v1");

        List<String> errorMessages = new ArrayList<>();

        for (String model : modelCandidates) {
            for (String apiVersion : apiVersions) {
                try {
                    return callGeminiWithEndpoint(prompt, model, apiVersion);
                } catch (RestClientResponseException ex) {
                    String msg = String.format("모델 시도 실패 (%s/%s): status=%s, body=%s", apiVersion, model, ex.getStatusCode(), ex.getResponseBodyAsString());
                    errorMessages.add(msg);
                    log.warn(msg);
                    // 404면 다른 버전/모델로 이어서 시도, 그 외는 즉시 중단
                    if (ex.getStatusCode() != HttpStatus.NOT_FOUND) {
                        throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Gemini 요약 요청이 실패했습니다.", ex);
                    }
                } catch (Exception ex) {
                    String msg = String.format("모델 시도 중 예외 (%s/%s): %s", apiVersion, model, ex.getMessage());
                    errorMessages.add(msg);
                    log.warn(msg, ex);
                }
            }
        }

        // 모든 시도가 실패한 경우
        log.error("Gemini 모든 모델 시도가 실패했습니다. 시도 내역: {}", String.join(" | ", errorMessages));
        throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Gemini 요약 요청이 실패했습니다.");
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

