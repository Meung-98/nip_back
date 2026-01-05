package newszip.nip.controller;

import lombok.RequiredArgsConstructor;
import newszip.nip.dto.GeminiSummaryRequest;
import newszip.nip.dto.GeminiSummaryResponse;
import newszip.nip.service.GeminiSummaryService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/ai")
@RequiredArgsConstructor
public class GeminiController {

    private final GeminiSummaryService geminiSummaryService;

    @PostMapping("/summary")
    public ResponseEntity<GeminiSummaryResponse> summarize(@RequestBody GeminiSummaryRequest request) {
        boolean hasBody = request != null && (
                (request.getUrl() != null && !request.getUrl().isBlank()) ||
                        (request.getTitle() != null && !request.getTitle().isBlank()) ||
                        (request.getDescription() != null && !request.getDescription().isBlank())
        );

        if (!hasBody) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "요약할 정보가 없습니다.");
        }

        GeminiSummaryResponse response = geminiSummaryService.summarize(request);
        return ResponseEntity.ok(response);
    }
}

