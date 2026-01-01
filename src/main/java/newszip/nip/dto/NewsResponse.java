package newszip.nip.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class NewsResponse {

    @JsonProperty("lastBuildDate")
    private String lastBuildDate;

    private Integer total;
    private Integer start;
    private Integer display;

    @JsonProperty("errorMessage")
    private String errorMessage;

    private List<NewsItem> items;

    @Getter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class NewsItem {
        private String title;
        private String originallink;
        private String link;
        private String description;
        private String image;  // 뉴스 이미지 URL

        @JsonProperty("pubDate")
        private String pubDate;
    }
}

