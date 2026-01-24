package com.handsome.summary.service;

import reactor.core.publisher.Mono;

/**
 * Article Completion Service Interface
 * Provides functionality for AI-assisted text completion (continue writing).
 */
public interface ArticleCompletionService {

    /**
     * Generate completion text based on the provided context.
     *
     * @param context The preceding text context.
     * @return A Mono emitting the generated completion text.
     */
    Mono<String> completeText(String context);
}
