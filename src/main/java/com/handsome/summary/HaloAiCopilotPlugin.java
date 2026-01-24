package com.handsome.summary;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import run.halo.app.plugin.BasePlugin;
import run.halo.app.plugin.PluginContext;

/**
 * <p>
 * Plugin main class to manage the lifecycle of the plugin.
 * </p>
 * <p>
 * This class must be public and have a public constructor.
 * </p>
 * <p>
 * Only one main class extending {@link BasePlugin} is allowed per plugin.
 * </p>
 *
 * @author guqing
 * @since 1.0.0
 */
@Component
@Slf4j
public class HaloAiCopilotPlugin extends BasePlugin {

    public HaloAiCopilotPlugin(PluginContext pluginContext) {
        super(pluginContext);
    }

    @Override
    public void start() {
        // No schemes to register for Article Completion functionality
    }

    @Override
    public void stop() {
        // No schemes to unregister
    }
}
