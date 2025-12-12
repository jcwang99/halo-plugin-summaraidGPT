package com.handsome.summary.service.impl;

import static run.halo.app.extension.MetadataUtil.nullSafeAnnotations;
import static run.halo.app.extension.index.query.QueryFactory.and;
import static run.halo.app.extension.index.query.QueryFactory.equal;
import static run.halo.app.extension.index.query.QueryFactory.isNotNull;


import com.handsome.summary.extension.Summary;
import com.handsome.summary.service.AiConfigService;
import com.handsome.summary.service.AiServiceUtils;
import com.handsome.summary.service.ArticleSummaryService;
import com.handsome.summary.service.SettingConfigGetter;
import com.handsome.summary.utils.ContentHashUtils;
import com.handsome.summary.utils.EncryptionUtils;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import run.halo.app.content.PostContentService;
import run.halo.app.core.extension.content.Post;
import run.halo.app.extension.ListOptions;
import run.halo.app.extension.Metadata;
import run.halo.app.extension.ReactiveExtensionClient;
import run.halo.app.extension.router.selector.FieldSelector;
import reactor.core.scheduler.Schedulers;

/**
 * 文章摘要服务实现类
 * 负责文章摘要的生成、存储和更新，支持多种AI服务提供商。
 * @author handsome
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ArticleSummaryServiceImpl implements ArticleSummaryService {

    // 依赖注入
    private final AiConfigService aiConfigService;
    private final PostContentService postContentService;
    private final ReactiveExtensionClient client;
    private final EncryptionUtils encryptionUtils;
    private final SettingConfigGetter settingConfigGetter;

    // 常量定义
    public static final String AI_SUMMARY_UPDATED = "summary.lik.cc/ai-summary-updated";
    public static final String ENABLE_BLACK_LIST = "summary.xhhao.com/enable-black-list";
    public static final String UPDATE_SUMMARY = "summary.xhhao.com/update-summary";
    public static final String DEFAULT_AI_SYSTEM_PROMPT = "你是专业摘要助手，请为以下文章生成简明摘要：";
    public static final String DEFAULT_SUMMARY_ERROR_MESSAGE = "文章摘要生成异常：";

    // 进度状态变量
    private final java.util.concurrent.atomic.AtomicInteger total = new java.util.concurrent.atomic.AtomicInteger();
    private final java.util.concurrent.atomic.AtomicInteger finished = new java.util.concurrent.atomic.AtomicInteger();

    /**
     * 获取指定文章的AI摘要
     * <p>
     * 实现内容哈希缓存机制：如果文章内容哈希相同，直接返回缓存的摘要，避免重复生成。
     * </p>
     * 
     * @param post 文章对象
     * @return 摘要内容
     */
    @Override
    public Mono<String> getSummary(Post post) {
        String postMetadataName = post.getMetadata().getName();
        
        // 先获取文章内容，计算哈希值
        return postContentService.getReleaseContent(postMetadataName)
            .flatMap(contentWrapper -> {
                String content = contentWrapper.getRaw();
                String currentHash = ContentHashUtils.generateHash(content);
                
                if (currentHash == null) {
                    log.warn("无法生成内容哈希，文章: {}", postMetadataName);
                    // 如果哈希生成失败，继续正常流程
                    return generateNewSummary(post);
                }
                
                // 检查缓存：查找相同文章名称和内容哈希的摘要
                return findSummaryByPostName(postMetadataName)
                    .filter(summary -> {
                        String cachedHash = summary.getSummarySpec().getContentHash();
                        return ContentHashUtils.isHashEqual(currentHash, cachedHash);
                    })
                    .next()
                    .flatMap(cachedSummary -> {
                        // 找到缓存，尝试解密并返回
                        String storedSummary = cachedSummary.getSummarySpec().getPostSummary();
                        
                        // 检查是否加密：如果格式是 iv:authTag:encryptedText（包含两个冒号），则认为是加密的
                        String decryptedSummary = null;
                        if (storedSummary != null && storedSummary.split(":").length == 3) {
                            // 可能是加密数据，尝试解密
                            decryptedSummary = encryptionUtils.decrypt(storedSummary);
                        }
                        
                        if (decryptedSummary != null) {
                            log.info("使用缓存的摘要（已解密），文章: {}, 哈希: {}", postMetadataName, currentHash);
                            return Mono.just(decryptedSummary);
                        } else if (storedSummary != null) {
                            // 解密失败或未加密，使用原始值
                            log.info("使用缓存的摘要（未加密），文章: {}, 哈希: {}", postMetadataName, currentHash);
                            return Mono.just(storedSummary);
                        } else {
                            log.warn("缓存摘要为空，将重新生成，文章: {}", postMetadataName);
                            // 摘要为空，重新生成
                            return generateNewSummary(post, currentHash);
                        }
                    })
                    .switchIfEmpty(Mono.defer(() -> {
                        // 没有缓存或内容已变化，生成新摘要
                        log.info("未找到缓存或内容已变化，生成新摘要，文章: {}", postMetadataName);
                        return generateNewSummary(post, currentHash);
                    }));
            })
            .onErrorResume(this::handleSummaryGenerationError);
    }
    
    /**
     * 生成新摘要（内部方法，不包含缓存检查）
     */
    private Mono<String> generateNewSummary(Post post) {
        return generateNewSummary(post, null);
    }
    
    /**
     * 生成新摘要（内部方法，不包含缓存检查）
     * 
     * @param post 文章对象
     * @param contentHash 内容哈希值，如果为 null 则自动计算
     * @return 摘要内容
     */
    private Mono<String> generateNewSummary(Post post, String contentHash) {
        return Mono.zip(
                aiConfigService.getAiConfigForFunction("summary"),
                aiConfigService.getAiServiceForFunction("summary")
        )
        .flatMap(tuple -> generateSummaryWithAiConfig(post, tuple.getT1(), tuple.getT2()))
        .map(AiServiceUtils::extractContentFromResponse)
        .flatMap(summary -> {
            // 检查是否是错误信息，如果是则不保存到数据库
            if (AiServiceUtils.isErrorMessage(summary)) {
                return Mono.error(new RuntimeException(summary));
            }
            // 如果 contentHash 为 null，重新计算
            String hash = contentHash;
            if (hash == null) {
                return postContentService.getReleaseContent(post.getMetadata().getName())
                    .map(contentWrapper -> ContentHashUtils.generateHash(contentWrapper.getRaw()))
                    .flatMap(calculatedHash -> {
                        if (calculatedHash == null) {
                            log.warn("无法生成内容哈希，文章: {}", post.getMetadata().getName());
                        }
                        return saveSummaryToDatabase(summary, post, calculatedHash).thenReturn(summary);
                    });
            } else {
                return saveSummaryToDatabase(summary, post, hash).thenReturn(summary);
            }
        });
    }

    /**
     * 根据文章名称查询摘要
     * @param postMetadataName 文章元数据名称
     * @return 摘要列表
     */
    @Override
    public Flux<Summary> findSummaryByPostName(String postMetadataName) {
        var listOptions = new ListOptions();
        listOptions.setFieldSelector(FieldSelector.of(
            and(equal("summarySpec.postMetadataName", postMetadataName),
                isNotNull("summarySpec.postSummary"))
        ));
        return client.listAll(Summary.class, listOptions, Sort.unsorted());
    }

    /**
     * 更新文章内容并返回摘要信息
     * @param postMetadataName 文章元数据名称
     * @return 更新结果
     */
    @Override
    public Mono<Map<String, Object>> updatePostContentWithSummary(String postMetadataName) {
        return findSummaryByPostName(postMetadataName)
            .hasElements()
            .flatMap(hasElements -> {
                if (!hasElements) {
                    log.info("未找到摘要数据，文章: {}", postMetadataName);
                    return Mono.just(buildResponse(false, "未找到摘要内容", "未找到摘要内容", false));
                }
                return processUpdateRequest(postMetadataName);
            })
            .onErrorResume(e -> handleUpdateError(e, postMetadataName));
    }

    @Override
    public Mono<Void> syncAllSummariesAsync() {
        total.set(0);
        finished.set(0);
        return client.listAll(Post.class, new ListOptions(), Sort.unsorted())
            .doOnNext(post -> total.incrementAndGet())
            .filter(post -> {
                var annotations = nullSafeAnnotations(post);
                var newPostNotified = annotations.getOrDefault(AI_SUMMARY_UPDATED, "false");
                return Objects.equals(newPostNotified, "false");
            })
            .flatMap(post -> {
                log.info("开始摘要同步，文章: {}", post.getMetadata().getName());
                return getSummary(post)
                    .doOnSuccess(s -> finished.incrementAndGet())
                    .onErrorResume(e -> {
                        log.error("摘要同步失败，文章: {}，错误: {}", post.getMetadata().getName(), e.getMessage());
                        finished.incrementAndGet();
                        return Mono.empty();
                    });
            }, 3) // 并发数
            .subscribeOn(Schedulers.boundedElastic()) // 在后台线程池执行
            .then();
    }

    @Override
    public Mono<Map<String, Integer>> getSyncProgress() {
        Map<String, Integer> progress = new HashMap<>();
        progress.put("total", total.get());
        progress.put("finished", finished.get());
        return Mono.just(progress);
    }

    /**
     * 强制重新生成摘要（忽略缓存，直接生成新摘要）
     * @param post 文章对象
     * @return 新生成的摘要内容
     */
    @Override
    public Mono<String> regenerateSummary(Post post) {
        String postMetadataName = post.getMetadata().getName();
        log.info("开始强制重新生成摘要，文章: {}", postMetadataName);
        
        // 先删除所有旧的摘要记录，等待所有删除操作完成
        return findSummaryByPostName(postMetadataName)
            .flatMap(summary -> {
                log.info("删除旧摘要记录，文章: {}, 摘要名称: {}", postMetadataName, summary.getMetadata().getName());
                return client.delete(summary);
            })
            .collectList()  // 收集所有删除操作
            .flatMap(deletedSummaries -> {
                log.info("已删除 {} 条旧摘要记录，文章: {}", deletedSummaries.size(), postMetadataName);
                // 等待一小段时间确保删除操作完全完成
                return Mono.delay(java.time.Duration.ofMillis(100))
                    .then(Mono.defer(() -> {
                        // 删除完成后，强制生成新摘要（不检查缓存）
                        return postContentService.getReleaseContent(postMetadataName)
                            .flatMap(contentWrapper -> {
                                String content = contentWrapper.getRaw();
                                String contentHash = ContentHashUtils.generateHash(content);
                                
                                return Mono.zip(
                                    aiConfigService.getAiConfigForFunction("summary"),
                                    aiConfigService.getAiServiceForFunction("summary")
                                )
                                .flatMap(tuple -> generateSummaryWithAiConfig(post, tuple.getT1(), tuple.getT2()))
                                .map(AiServiceUtils::extractContentFromResponse)  // 提取摘要内容
                                .flatMap(summary -> {
                                    // 检查是否是错误信息
                                    if (AiServiceUtils.isErrorMessage(summary)) {
                                        log.error("生成摘要失败，返回错误信息: {}", summary);
                                        return Mono.error(new RuntimeException(summary));
                                    }
                                    
                                    // 保存新生成的摘要（如果保存失败，尝试创建新的）
                                    return saveSummaryToDatabase(summary, post, contentHash)
                                        .onErrorResume(e -> {
                                            // 如果保存失败（可能是版本冲突），尝试创建新的
                                            log.warn("保存摘要失败，尝试创建新摘要，文章: {}, 错误: {}", postMetadataName, e.getMessage());
                                            return createNewSummaryDirectly(summary, post, postMetadataName, contentHash);
                                        })
                                        .thenReturn(summary);
                                });
                            });
                    }));
            })
            .switchIfEmpty(Mono.defer(() -> {
                // 如果没有旧摘要需要删除，直接生成新摘要
                log.info("没有旧摘要需要删除，直接生成新摘要，文章: {}", postMetadataName);
                return postContentService.getReleaseContent(postMetadataName)
                    .flatMap(contentWrapper -> {
                        String content = contentWrapper.getRaw();
                        String contentHash = ContentHashUtils.generateHash(content);
                        
                        return Mono.zip(
                            aiConfigService.getAiConfigForFunction("summary"),
                            aiConfigService.getAiServiceForFunction("summary")
                        )
                        .flatMap(tuple -> generateSummaryWithAiConfig(post, tuple.getT1(), tuple.getT2()))
                        .map(AiServiceUtils::extractContentFromResponse)
                        .flatMap(summary -> {
                            if (AiServiceUtils.isErrorMessage(summary)) {
                                log.error("生成摘要失败，返回错误信息: {}", summary);
                                return Mono.error(new RuntimeException(summary));
                            }
                            return createNewSummaryDirectly(summary, post, postMetadataName, contentHash)
                                .thenReturn(summary);
                        });
                    });
            }))
            .doOnSuccess(summary -> log.info("强制重新生成摘要成功，文章: {}, 摘要长度: {}", postMetadataName, summary != null ? summary.length() : 0))
            .doOnError(e -> log.error("强制重新生成摘要失败，文章: {}, 错误: {}", postMetadataName, e.getMessage(), e));
    }
    
    /**
     * 直接创建新摘要（不检查是否存在）
     */
    private Mono<Void> createNewSummaryDirectly(String summary, Post post, String postMetadataName, String contentHash) {
        // 检查是否启用加密
        return aiConfigService.getAiConfigForFunction("summary")
            .flatMap(aiConfig -> settingConfigGetter.getBasicConfig()
                .map(basicConfig -> {
                    boolean shouldEncrypt = basicConfig.getEnableEncryption() != null 
                        && basicConfig.getEnableEncryption();
                    
                    final String summaryToSave;
                    if (shouldEncrypt) {
                        String encrypted = encryptionUtils.encrypt(summary);
                        if (encrypted == null) {
                            log.error("加密摘要失败，文章: {}，将保存明文", postMetadataName);
                            summaryToSave = summary;
                        } else {
                            summaryToSave = encrypted;
                        }
                    } else {
                        summaryToSave = summary;
                    }
                    
                    return summaryToSave;
                })
            )
            .defaultIfEmpty(summary)
            .flatMap(summaryToSave -> {
                Summary summaryEntity = new Summary();
                summaryEntity.setMetadata(new Metadata());
                summaryEntity.getMetadata().setGenerateName("summary-");
                
                Summary.SummarySpec summarySpec = new Summary.SummarySpec();
                summarySpec.setPostSummary(summaryToSave);
                summarySpec.setPostMetadataName(postMetadataName);
                summarySpec.setPostUrl(post.getStatus().getPermalink());
                summarySpec.setContentHash(contentHash);
                summaryEntity.setSummarySpec(summarySpec);
                
                return client.create(summaryEntity)
                    .doOnSuccess(s -> log.info("新摘要已创建，文章: {}", postMetadataName))
                    .doOnError(e -> log.error("创建新摘要失败，文章: {}, 错误: {}", postMetadataName, e.getMessage(), e))
                    .then();
            });
    }

    /**
     * 使用新的AI配置生成摘要
     */
    private Mono<String> generateSummaryWithAiConfig(Post post, SettingConfigGetter.AiConfigResult aiConfig, 
                                                    com.handsome.summary.service.AiService aiService) {
        return postContentService.getReleaseContent(post.getMetadata().getName())
            .flatMap(contentWrapper -> {
                String aiSystem = aiConfig.getSystemPrompt() != null ? aiConfig.getSystemPrompt() : DEFAULT_AI_SYSTEM_PROMPT;
                String prompt = aiSystem + "\n" + contentWrapper.getRaw();
                
                log.info("开始生成摘要，AI类型: {}, 文章: {}", aiConfig.getAiType(), post.getMetadata().getName());
                
                // 创建兼容的BasicConfig
                var compatibleConfig = aiConfigService.createCompatibleBasicConfig(aiConfig);
                return Mono.fromCallable(() -> aiService.chatCompletionRaw(prompt, compatibleConfig));
            });
    }


    


    /**
     * 保存摘要到数据库（带内容哈希）
     * 
     * @param summary 明文摘要
     * @param post 文章对象
     * @param contentHash 内容哈希值
     */
    private Mono<Void> saveSummaryToDatabase(String summary, Post post, String contentHash) {
        String postMetadataName = post.getMetadata().getName();
        
        // 检查是否启用加密
        return aiConfigService.getAiConfigForFunction("summary")
            .flatMap(aiConfig -> settingConfigGetter.getBasicConfig()
                .map(basicConfig -> {
                    boolean shouldEncrypt = basicConfig.getEnableEncryption() != null 
                        && basicConfig.getEnableEncryption();
                    
                    final String summaryToSave;
                    if (shouldEncrypt) {
                        // 启用加密，加密摘要
                        String encrypted = encryptionUtils.encrypt(summary);
                        if (encrypted == null) {
                            log.error("加密摘要失败，文章: {}，将保存明文", postMetadataName);
                            summaryToSave = summary;
                        } else {
                            summaryToSave = encrypted;
                        }
                    } else {
                        // 未启用加密，直接保存明文
                        summaryToSave = summary;
                    }
                    
                    return summaryToSave;
                })
            )
            .defaultIfEmpty(summary) // 如果获取配置失败，使用明文
            .flatMap(summaryToSave -> {
                var summaryFlux = findSummaryByPostName(postMetadataName);
                return summaryFlux
                    .collectList()
                    .flatMap(list -> {
                        if (!list.isEmpty()) {
                            return updateExistingSummary(list.getFirst(), summaryToSave, contentHash, postMetadataName);
                        } else {
                            return createNewSummary(summaryToSave, post, postMetadataName, contentHash);
                        }
                    });
            });
    }

    /**
     * 更新现有摘要
     */
    private Mono<Void> updateExistingSummary(Summary existing, String encryptedSummary, 
                                             String contentHash, String postMetadataName) {
        existing.getSummarySpec().setPostSummary(encryptedSummary);
        existing.getSummarySpec().setContentHash(contentHash);
        return client.update(existing)
            .doOnSuccess(s -> log.info("摘要已更新到数据库，文章: {}", postMetadataName))
            .doOnError(e -> log.error("更新摘要到数据库失败，文章: {}, 错误: {}", postMetadataName, e.getMessage(), e))
            .then();
    }

    /**
     * 创建新摘要
     */
    private Mono<Void> createNewSummary(String encryptedSummary, Post post, 
                                       String postMetadataName, String contentHash) {
        Summary summaryEntity = new Summary();
        summaryEntity.setMetadata(new Metadata());
        summaryEntity.getMetadata().setGenerateName("summary-");
        
        Summary.SummarySpec summarySpec = new Summary.SummarySpec();
        summarySpec.setPostSummary(encryptedSummary);
        summarySpec.setPostMetadataName(postMetadataName);
        summarySpec.setPostUrl(post.getStatus().getPermalink());
        summarySpec.setContentHash(contentHash);
        summaryEntity.setSummarySpec(summarySpec);
        
        return client.create(summaryEntity)
            .doOnSuccess(s -> log.info("摘要已保存到数据库，文章: {}", postMetadataName))
            .doOnError(e -> log.error("保存摘要到数据库失败，文章: {}, 错误: {}", postMetadataName, e.getMessage(), e))
            .then();
    }

    /**
     * 处理摘要生成错误
     */
    private Mono<String> handleSummaryGenerationError(Throwable e) {
        log.error("摘要生成失败: {}", e.getMessage(), e);
        return Mono.just(DEFAULT_SUMMARY_ERROR_MESSAGE + e.getMessage());
    }

    /**
     * 处理更新请求
     */
    private Mono<Map<String, Object>> processUpdateRequest(String postMetadataName) {
        return findSummaryByPostName(postMetadataName)
            .next()
            .flatMap(summary -> {
                final String storedSummary = summary.getSummarySpec().getPostSummary();
                
                // 检查是否加密：如果格式是 iv:authTag:encryptedText（包含两个冒号），则认为是加密的
                final String summaryContent;
                if (storedSummary != null && storedSummary.split(":").length == 3) {
                    // 可能是加密数据，尝试解密
                    String decryptedContent = encryptionUtils.decrypt(storedSummary);
                    if (decryptedContent != null) {
                        summaryContent = decryptedContent;
                        log.debug("成功解密摘要，文章: {}", postMetadataName);
                    } else {
                        // 解密失败，可能是格式巧合，使用原始值
                        summaryContent = storedSummary;
                        log.debug("解密失败，使用原始值，文章: {}", postMetadataName);
                    }
                } else {
                    // 不是加密格式，直接使用
                    summaryContent = storedSummary;
                }
                
                log.info("找到摘要内容，文章: {}, 长度: {}", postMetadataName, 
                    summaryContent != null ? summaryContent.length() : 0);
                
                return client.fetch(Post.class, postMetadataName)
                    .flatMap(post -> updatePostWithSummary(post, summaryContent, postMetadataName))
                    .onErrorResume(e -> handlePostUpdateError(e, summaryContent));
            });
    }

    /**
     * 处理文章更新错误
     */
    private Mono<Map<String, Object>> handlePostUpdateError(Throwable e, String summaryContent) {
        log.error("更新文章摘要时发生错误: {}", e.getMessage(), e);
        return Mono.just(buildResponse(false, "更新文章摘要时发生错误: " + e.getMessage(), summaryContent, false));
    }

    /**
     * 处理更新操作错误
     */
    private Mono<Map<String, Object>> handleUpdateError(Throwable e, String postMetadataName) {
        log.error("更新操作异常，文章: {}, 错误: {}", postMetadataName, e.getMessage(), e);
        return Mono.just(buildResponse(false, "未找到摘要内容", "未找到摘要内容", false));
    }

    /**
     * 更新文章摘要
     */
    private Mono<Map<String, Object>> updatePostWithSummary(Post post, String summaryContent, String postMetadataName) {
        log.info("开始更新文章摘要，文章: {}, 摘要长度: {}", postMetadataName, 
            summaryContent != null ? summaryContent.length() : 0);
        
        var annotations = nullSafeAnnotations(post);
        boolean blackList = Boolean.parseBoolean(annotations.getOrDefault(ENABLE_BLACK_LIST, "false"));
        
        // 黑名单检查
        if (blackList) {
            log.info("文章在黑名单中，跳过更新，文章: {}", postMetadataName);
            return Mono.just(buildResponse(false, "文章在黑名单中，不进行摘要更新", summaryContent, true));
        }
        
        // 手动更新摘要检查（用户手动设置后不再覆盖）
        boolean manualUpdate = Boolean.parseBoolean(annotations.getOrDefault(UPDATE_SUMMARY, "false"));
        if (manualUpdate) {
            log.info("文章已手动更新摘要，跳过AI更新，文章: {}", postMetadataName);
            return Mono.just(buildResponse(false, "文章已手动更新摘要，跳过AI更新", summaryContent, false));
        }
        
        // 获取当前文章的摘要内容
        String currentSummary = post.getSpec().getExcerpt().getRaw();
        log.info("当前文章摘要: [{}], 新生成摘要: [{}]", 
            currentSummary != null ? currentSummary : "暂无摘要", 
            summaryContent != null ? summaryContent : "暂无摘要");
        
        // 检查摘要内容是否发生变化
        boolean summaryChanged = !Objects.equals(currentSummary, summaryContent);
        
        if (!summaryChanged) {
            log.info("文章摘要内容未发生变化，跳过更新，文章: {}", postMetadataName);
            return Mono.just(buildResponse(false, "摘要内容未发生变化，无需更新", summaryContent, false));
        }
        
        log.info("文章摘要内容发生变化，执行更新，文章: {}", postMetadataName);
        return performPostUpdate(post, summaryContent, postMetadataName, annotations);
    }

    /**
     * 执行文章更新
     */
    private Mono<Map<String, Object>> performPostUpdate(Post post, String summaryContent, 
                                                       String postMetadataName, Map<String, String> annotations) {
        // 更新文章摘要
        post.getSpec().getExcerpt().setRaw(summaryContent);
        post.getSpec().getExcerpt().setAutoGenerate(false);
        post.getStatus().setExcerpt(summaryContent);
        annotations.put(AI_SUMMARY_UPDATED, "true");
        
        return client.update(post)
            .doOnSuccess(p -> log.info("已将摘要写入文章正文，文章: {}", postMetadataName))
            .then(Mono.just(buildResponse(true, "成功", summaryContent, false)));
    }

    /**
     * 构建统一的响应结果
     */
    private Map<String, Object> buildResponse(boolean success, String message, String summaryContent, boolean blackList) {
        log.debug("构建响应 - success: {}, message: {}, summaryContent长度: {}, blackList: {}", 
            success, message, summaryContent != null ? summaryContent.length() : 0, blackList);
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", success);
        response.put("message", message);
        response.put("summaryContent", summaryContent != null ? summaryContent : "");
        response.put("blackList", blackList);
        
        return response;
    }
} 