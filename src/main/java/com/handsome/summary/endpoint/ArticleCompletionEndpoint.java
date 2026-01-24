package com.handsome.summary.endpoint;

import com.handsome.summary.service.ArticleCompletionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/apis/api.plugin.ai-copilot/v1alpha1")
@RequiredArgsConstructor
@Tag(name = "Article Completion", description = "文章续写接口")
public class ArticleCompletionEndpoint {

    private final ArticleCompletionService articleCompletionService;

    @PostMapping("/completion")
    @Operation(summary = "文章续写")
    public Mono<String> completeText(@RequestBody CompletionRequest request) {
        return articleCompletionService.completeText(request.getContext());
    }

    @Data
    public static class CompletionRequest {
        private String context;
    }
}
