package com.handsome.summary.service.impl;

import com.handsome.summary.service.AiConfigService;
import com.handsome.summary.service.AiServiceUtils;
import com.handsome.summary.service.ArticleCompletionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
@Slf4j
public class ArticleCompletionServiceImpl implements ArticleCompletionService {

    private final AiConfigService aiConfigService;

    // Default system prompt for completion
    private static final String DEFAULT_COMPLETION_SYSTEM_PROMPT = "你是一个专业的写作补全助手。你的任务是根据用户提供的文本片段，**直接续写**后续内容。\n" +
            "要求：\n" +
            "1. 续写内容必须紧密承接上文的语境、风格、语气和逻辑。\n" +
            "2. 严禁输出标题、章节头（如 '## 标题'）、引言、摘要或任何解释性文字，除非上文明确在列大纲。\n" +
            "3. 严禁重复上文的最后一句话。\n" +
            "4. 直接输出续写的内容，不要加任何前缀（如 '续写：'）。\n" +
            "5. 如果上文是中文，请用中文续写。";

    @Override
    public Mono<String> completeText(String context) {
        log.info("Received text completion request. Context length: {}", context != null ? context.length() : 0);

        if (context == null || context.trim().isEmpty()) {
            return Mono.error(new IllegalArgumentException("Context cannot be empty"));
        }

        // We use "completion" as the function identifier for AI config
        return Mono.zip(
                aiConfigService.getAiConfigForFunction("completion"),
                aiConfigService.getAiServiceForFunction("completion"))
                .flatMap(tuple -> {
                    var aiConfig = tuple.getT1();
                    var aiService = tuple.getT2();

                    String systemPrompt = aiConfig.getSystemPrompt();
                    if (systemPrompt == null || systemPrompt.isEmpty()) {
                        systemPrompt = DEFAULT_COMPLETION_SYSTEM_PROMPT;
                    }

                    // Construct the prompt.
                    // For completion, providing the context clearly is key.
                    String prompt = systemPrompt + "\n\n【待续写的上文】\n" + context + "\n\n【续写开始】";

                    // Create compatible config
                    var compatibleConfig = aiConfigService.createCompatibleBasicConfig(aiConfig);

                    return Mono.fromCallable(() -> aiService.chatCompletionRaw(prompt, compatibleConfig));
                })
                .map(AiServiceUtils::extractContentFromResponse)
                .doOnSuccess(result -> log.info("Text completion generated. Length: {}",
                        result != null ? result.length() : 0))
                .doOnError(e -> log.error("Error generating text completion", e));
    }
}
