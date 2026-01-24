import { Extension } from '@halo-dev/richtext-editor'
import { Plugin, PluginKey, EditorState, Transaction } from '@halo-dev/richtext-editor'
import { Decoration, DecorationSet, EditorView } from '@halo-dev/richtext-editor'
import axios from 'axios'
import './ArticleCompletion.scss'

// Plugin Key
const completionPluginKey = new PluginKey<CompletionState>('articleCompletion')

export interface ArticleCompletionOptions {
    debounce?: number
}

// State interface for the plugin
interface CompletionState {
    suggestion: string | null
    timer: any | null
    loading: boolean
}

export default Extension.create<ArticleCompletionOptions>({
    name: 'articleCompletion',

    addOptions() {
        return {
            debounce: 2000, // 2 seconds idle time
        }
    },

    priority: 10000,

    addProseMirrorPlugins() {
        const { debounce } = this.options
        console.log('[ArticleCompletion] Plugin initialized, debounce:', debounce)

        return [
            new Plugin<CompletionState>({
                key: completionPluginKey,
                state: {
                    init() {
                        return { suggestion: null, timer: null, loading: false }
                    },
                    apply(tr: Transaction, value: CompletionState, oldState: EditorState, newState: EditorState) {
                        const nextValue = { ...value }

                        // If document changed, clear suggestion and reset timer
                        if (tr.docChanged || tr.selectionSet) {
                            nextValue.suggestion = null

                            if (nextValue.timer) {
                                clearTimeout(nextValue.timer)
                            }

                            if (tr.docChanged) {
                                nextValue.timer = setTimeout(() => {
                                }, debounce)
                            }
                        }

                        // Check for metadata action to set suggestion
                        const suggestionMeta = tr.getMeta(completionPluginKey)
                        if (suggestionMeta) {
                            if (suggestionMeta.type === 'SET_SUGGESTION') {
                                nextValue.suggestion = suggestionMeta.text
                                nextValue.loading = false
                            } else if (suggestionMeta.type === 'CLEAR') {
                                nextValue.suggestion = null
                            }
                        }

                        return nextValue
                    },
                },
                view(editorView: EditorView) {
                    let timer: any = null
                    const debounceTime = debounce

                    return {
                        update(view: EditorView, prevState: EditorState) {
                            const { state } = view
                            // Check if doc changed
                            if (prevState.doc.eq(state.doc)) return

                            // Doc changed, reset timer
                            if (timer) clearTimeout(timer)

                            timer = setTimeout(() => {
                                fetchCompletion(view)
                            }, debounceTime)
                        },
                        destroy() {
                            if (timer) clearTimeout(timer)
                        }
                    }
                },
                props: {
                    // Render decorations (Ghost Text)
                    decorations(state: EditorState) {
                        // Use key.getState to access plugin state
                        const pluginState = completionPluginKey.getState(state)
                        if (!pluginState || !pluginState.suggestion) return DecorationSet.empty

                        const { to } = state.selection

                        // Create a widget decoration at the cursor position
                        const decoration = Decoration.widget(to, () => {
                            const span = document.createElement('span')
                            span.classList.add('ghost-text')
                            span.textContent = pluginState.suggestion
                            return span
                        }, { side: 1 }) // side 1 means it appears after cursor

                        return DecorationSet.create(state.doc, [decoration])
                    },

                    // Handle Keydown (Higher priority than keymaps)
                    handleKeyDown(view: EditorView, event: KeyboardEvent) {
                        const pluginState = completionPluginKey.getState(view.state)
                        const suggestion = pluginState?.suggestion

                        if (suggestion && event.key === 'Tab') {
                            console.log('[ArticleCompletion] Tab pressed (handleKeyDown), accepting suggestion')
                            event.preventDefault()
                            // Apply suggestion
                            const { to } = view.state.selection
                            view.dispatch(view.state.tr.insertText(suggestion, to))
                            // Clear suggestion trigger
                            view.dispatch(view.state.tr.setMeta(completionPluginKey, { type: 'CLEAR' }))
                            return true
                        }

                        if (suggestion && (event.key === 'Escape' || event.key === 'ArrowRight' || event.key === 'ArrowLeft')) {
                            // Dismiss suggestion on Esc or Arrow keys
                            view.dispatch(view.state.tr.setMeta(completionPluginKey, { type: 'CLEAR' }))
                            return event.key === 'Escape'
                        }

                        return false
                    },
                },
            }),
        ]
    },

    addKeyboardShortcuts() {
        return {
            'Tab': () => {
                const pluginState = completionPluginKey.getState(this.editor.state)
                const suggestion = pluginState?.suggestion
                if (suggestion) {
                    console.log('[ArticleCompletion] Tab pressed (shortcut), accepting suggestion')
                    const { selection } = this.editor.state
                    this.editor.commands.insertContentAt(selection.to, suggestion)
                    this.editor.view.dispatch(this.editor.state.tr.setMeta(completionPluginKey, { type: 'CLEAR' }))
                    return true
                }
                return false
            },
            'Escape': () => {
                const pluginState = completionPluginKey.getState(this.editor.state)
                if (pluginState?.suggestion) {
                    console.log('[ArticleCompletion] Esc pressed, dismissing suggestion')
                    this.editor.view.dispatch(this.editor.state.tr.setMeta(completionPluginKey, { type: 'CLEAR' }))
                    return true
                }
                return false
            },
            'ArrowRight': () => {
                const pluginState = completionPluginKey.getState(this.editor.state)
                if (pluginState?.suggestion) {
                    this.editor.view.dispatch(this.editor.state.tr.setMeta(completionPluginKey, { type: 'CLEAR' }))
                    return false // Don't prevent navigation
                }
                return false
            },
            'ArrowLeft': () => {
                const pluginState = completionPluginKey.getState(this.editor.state)
                if (pluginState?.suggestion) {
                    this.editor.view.dispatch(this.editor.state.tr.setMeta(completionPluginKey, { type: 'CLEAR' }))
                    return false
                }
                return false
            }
        }
    },
})

// Helper to fetch completion
async function fetchCompletion(view: EditorView) {
    if (!view || view.isDestroyed) return;
    console.log('[ArticleCompletion] Fetching completion...')

    // Get context (last 2000 chars)
    const { from } = view.state.selection
    const start = Math.max(0, from - 2000)
    const context = view.state.doc.textBetween(start, from, '\n')

    if (!context || !context.trim()) return;

    try {
        const response = await axios.post('/apis/api.plugin.ai-copilot/v1alpha1/completion', {
            context,
        })

        const text = response.data
        if (text && view && !view.isDestroyed) {
            // Dispatch transaction to update plugin state with suggestion
            view.dispatch(view.state.tr.setMeta(completionPluginKey, { type: 'SET_SUGGESTION', text }))
        }
    } catch (e) {
        console.error("Failed to fetch completion", e)
    }
}
