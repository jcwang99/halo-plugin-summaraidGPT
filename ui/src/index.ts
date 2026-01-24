import { definePlugin } from "@halo-dev/console-shared";
import ArticleCompletion from '@/extensions/ArticleCompletion'

export default definePlugin({
  extensionPoints: {
    "default:editor:extension:create": () => {
      return [ArticleCompletion];
    },
  },
});
